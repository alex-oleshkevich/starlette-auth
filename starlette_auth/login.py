from starlette.authentication import AuthCredentials, BaseUser, UnauthenticatedUser
from starlette.requests import HTTPConnection

from starlette_auth.scopes import get_scopes, LoginScopes
from starlette_auth.settings import SESSION_KEY


def _regenerate_session_id(connection: HTTPConnection) -> None:
    if "session_handler" in connection.scope:  # when starsessions installed
        from starsessions import regenerate_session_id

        regenerate_session_id(connection)


async def login(connection: HTTPConnection, user: BaseUser) -> None:
    """Login user."""

    # Regenerate session id to prevent session fixation.
    # Attack vector:
    # A malicious user can steal session ID from victim's browser and set it into his own.
    # When victim sign in and session is NOT regenerated then two browsers will share same session and data
    _regenerate_session_id(connection)

    connection.scope["auth"] = AuthCredentials(scopes=get_scopes(user) + [LoginScopes.FRESH])
    connection.scope["user"] = user
    connection.session[SESSION_KEY] = user.identity


async def logout(connection: HTTPConnection) -> None:
    connection.session.clear()  # wipe all data
    _regenerate_session_id(connection)
    connection.scope["auth"] = AuthCredentials()
    connection.scope["user"] = UnauthenticatedUser()


def is_authenticated(connection: HTTPConnection) -> bool:
    """Check if user is authenticated."""
    value: bool = connection.auth and connection.user.is_authenticated
    return value
