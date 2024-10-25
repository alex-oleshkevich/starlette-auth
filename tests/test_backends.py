from starlette.authentication import AuthCredentials, AuthenticationBackend, BaseUser
from starlette.requests import HTTPConnection

from starlette_auth import MultiBackend, SessionBackend
from starlette_auth.authentication import SESSION_HASH, SESSION_KEY, update_session_auth_hash
from tests.conftest import User, UserWithSessionHash


class _DummyBackend(AuthenticationBackend):
    def __init__(self, user: BaseUser | None) -> None:
        self.user = user

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, BaseUser] | None:
        if self.user:
            return AuthCredentials(), self.user
        return None


async def test_multi_backend() -> None:
    user = User("root")
    backend = MultiBackend(
        [
            _DummyBackend(None),
            _DummyBackend(None),
        ]
    )
    conn = HTTPConnection({"type": "http"})
    assert await backend.authenticate(conn) is None

    backend = MultiBackend(
        [
            _DummyBackend(None),
            _DummyBackend(user),
        ]
    )
    conn = HTTPConnection({"type": "http"})
    result = await backend.authenticate(conn)
    assert result
    _, auth_user = result
    assert auth_user == user


async def test_session_backend() -> None:
    user = User("root")

    async def user_loader(conn: HTTPConnection, user_id: str) -> BaseUser | None:
        return user if user_id == user.identity else None

    backend = SessionBackend(user_loader=user_loader, secret_key="key!")
    conn = HTTPConnection({"type": "http"})
    conn.scope["session"] = {}
    conn.session[SESSION_KEY] = "root"
    result = await backend.authenticate(conn)
    assert result
    _, auth_user = result
    assert auth_user == user

    conn.session[SESSION_KEY] = ""
    assert not await backend.authenticate(conn)


async def test_session_backend_extracts_user_scopes() -> None:
    class UserWithScopes(User):
        def get_scopes(self) -> list[str]:
            return ["admin"]

    async def user_loader(conn: HTTPConnection, user_id: str) -> BaseUser | None:
        return UserWithScopes(username="test")

    backend = SessionBackend(user_loader=user_loader, secret_key="key!")
    conn = HTTPConnection({"type": "http"})
    conn.scope["session"] = {}
    conn.session[SESSION_KEY] = "root"
    result = await backend.authenticate(conn)
    assert result
    assert result[0].scopes == ["admin"]


async def test_session_backend_validates_session_hash() -> None:
    user = UserWithSessionHash(username="root", password="password")

    async def user_loader(conn: HTTPConnection, user_id: str) -> BaseUser | None:
        return user if user_id == user.identity else None

    backend = SessionBackend(user_loader=user_loader, secret_key="key!")
    conn = HTTPConnection({"type": "http"})
    conn.scope["session"] = {
        SESSION_KEY: "root",
        SESSION_HASH: user.get_session_auth_hash("key!"),
    }
    assert await backend.authenticate(conn)


async def test_session_backend_validates_invalid_session_hash() -> None:
    user = UserWithSessionHash(username="root", password="password")

    async def user_loader(conn: HTTPConnection, user_id: str) -> BaseUser | None:
        return user if user_id == user.identity else None

    backend = SessionBackend(user_loader=user_loader, secret_key="key!")
    conn = HTTPConnection({"type": "http"})
    conn.scope["session"] = {
        SESSION_KEY: "root",
        SESSION_HASH: "bad hash",
    }
    assert not await backend.authenticate(conn)


async def test_session_backend_validates_fixed_invalid_session_hash() -> None:
    user = UserWithSessionHash(username="root", password="password")

    async def user_loader(conn: HTTPConnection, user_id: str) -> BaseUser | None:
        return user if user_id == user.identity else None

    backend = SessionBackend(user_loader=user_loader, secret_key="key!")
    conn = HTTPConnection({"type": "http"})
    conn.scope["session"] = {
        SESSION_KEY: "root",
        SESSION_HASH: "bad hash",
    }
    assert not await backend.authenticate(conn)
    update_session_auth_hash(conn, user, "key!")
    assert await backend.authenticate(conn)
