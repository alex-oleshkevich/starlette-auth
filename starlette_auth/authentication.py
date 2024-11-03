import enum
import hashlib
import hmac
import typing

from starlette.authentication import AuthCredentials, AuthenticationBackend, BaseUser, UnauthenticatedUser
from starlette.datastructures import URL
from starlette.requests import HTTPConnection, Request
from starlette.responses import RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send

SESSION_KEY = "__user_id__"
SESSION_HASH = "__user_hash__"
ByIdUserFinder = typing.Callable[[HTTPConnection, str], typing.Awaitable[BaseUser | None]]


class UserWithScopes(typing.Protocol):  # pragma: no cover
    def get_scopes(self) -> list[str]: ...


def get_scopes(user: BaseUser | UserWithScopes) -> list[str]:
    """Extract scopes from user object."""
    if hasattr(user, "get_scopes"):
        return user.get_scopes()
    return []


class LoginScopes(enum.StrEnum):
    FRESH = "login:fresh"
    REMEMBERED = "login:remembered"


def confirm_login(connection: HTTPConnection) -> None:
    """Convert remembered login to fresh login.
    Fresh login is the one where user provided credentials."""
    credentials: AuthCredentials = connection.auth
    if LoginScopes.REMEMBERED in credentials.scopes:
        credentials.scopes.remove(LoginScopes.REMEMBERED)
        credentials.scopes.append(LoginScopes.FRESH)
        connection.session[SESSION_KEY] = connection.user.identity


def is_confirmed(connection: HTTPConnection) -> bool:
    """Check if login is confirmed."""
    return LoginScopes.FRESH in connection.auth.scopes


class SessionBackend(AuthenticationBackend):
    """Authentication backend that uses session to store user information."""

    def __init__(self, user_loader: ByIdUserFinder, secret_key: str) -> None:
        self.user_loader = user_loader
        self.secret_key = secret_key

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, BaseUser] | None:
        user_id: str = conn.session.get(SESSION_KEY, "")
        if user_id and (user := await self.user_loader(conn, user_id)):
            if isinstance(user, HasSessionAuthHash) and not validate_session_auth_hash(
                conn, user.get_session_auth_hash(self.secret_key)
            ):
                # avoid authentication if session hash is invalid
                # this may happen when user changes password OR
                # session is hijacked
                return None
            return AuthCredentials(scopes=get_scopes(user)), user
        return None


class MultiBackend(AuthenticationBackend):
    """Authenticate user using multiple backends."""

    def __init__(self, backends: list[AuthenticationBackend]) -> None:
        self.backends = backends

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, BaseUser] | None:
        for backend in self.backends:
            if result := await backend.authenticate(conn):
                return result
        return None


class HasSessionAuthHash:  # pragma: no cover
    def get_password_hash(self) -> str:
        raise NotImplementedError

    def get_session_auth_hash(self, secret_key: str) -> str:
        """Compute current user session auth hash."""
        key = hashlib.sha256(("starlette_dispatch." + secret_key).encode()).digest()
        return hmac.new(key, msg=self.get_password_hash().encode(), digestmod=hashlib.sha256).hexdigest()


def update_session_auth_hash(connection: HTTPConnection, user: HasSessionAuthHash, secret_key: str) -> None:
    """Update session auth hash.
    Call this function each time you change user's password.
    Otherwise, the session will be instantly invalidated."""
    connection.session[SESSION_HASH] = user.get_session_auth_hash(secret_key)


def validate_session_auth_hash(connection: HTTPConnection, session_auth_hash: str) -> bool:
    """Validate session auth hash."""
    return hmac.compare_digest(connection.session.get(SESSION_HASH, ""), session_auth_hash)


async def login(connection: HTTPConnection, user: BaseUser, secret_key: str) -> None:
    """Login user."""

    # there is a chance that session may already contain data of another user
    # this may happen if you don't clear session property on logout, or
    # SESSION_KEY is set from the outside. In this case we need to run several
    # security checks to ensure that SESSION_KEY is valid.
    session_auth_hash = ""
    if isinstance(user, HasSessionAuthHash):
        session_auth_hash = user.get_session_auth_hash(secret_key)

    if SESSION_KEY in connection.session:
        if any(
            [
                # if we have other user id in the session and this is not the same user
                # OR user does not implement HasSessionAuthHash interface, then don't trust session and clear it
                connection.session[SESSION_KEY] != user.identity,
                # ok, we have the same user id in the session, let's check the session auth hash
                # or session has previously set hash, and hashes are not equal
                # this may happen when user changes password
                session_auth_hash and not validate_session_auth_hash(connection, session_auth_hash),
            ]
        ):
            connection.session.clear()

    connection.scope["auth"] = AuthCredentials(scopes=get_scopes(user) + [LoginScopes.FRESH])
    connection.scope["user"] = user
    connection.session[SESSION_KEY] = user.identity

    # Regenerate session id to prevent session fixation.
    # Note, in case of standard Starlette session middleware, session id is regenerated automatically
    # because the session is stored in the cookie value and once the session is modified, the cookie is updated.
    # For starsessions, we need to regenerate session id manually.
    # https://owasp.org/www-community/attacks/Session_fixation
    if "session_handler" in connection.scope:
        from starsessions import regenerate_session_id

        regenerate_session_id(connection)

    # Generate and store session auth hash.
    # Session auth has is used to invalidate session when user's password changes.
    connection.session[SESSION_HASH] = session_auth_hash


async def logout(connection: HTTPConnection) -> None:
    connection.session.clear()  # wipe all data
    connection.scope["auth"] = AuthCredentials()
    connection.scope["user"] = UnauthenticatedUser()


def is_authenticated(connection: HTTPConnection) -> bool:
    """Check if user is authenticated."""
    value: bool = connection.auth and connection.user.is_authenticated
    return value


class LoginRequiredMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        redirect_url: str | None = None,
        *,
        path_name: str | None = "login",
        path_params: dict[str, typing.Any] | None = None,
    ) -> None:
        assert redirect_url or path_name
        self.app = app
        self.redirect_url = redirect_url
        self.path_name = path_name
        self.path_params = path_params or {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        user = typing.cast(BaseUser, scope.get("user"))
        if not user.is_authenticated:
            request = Request(scope, receive, send)
            redirect_to = self.redirect_url or request.app.url_path_for(self.path_name, **self.path_params)
            url = URL(redirect_to).include_query_params(next=str(request.url.replace(scheme="", netloc="")))
            response = RedirectResponse(url, 302)
            await response(scope, receive, send)
        else:
            await self.app(scope, receive, send)
