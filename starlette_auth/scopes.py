import enum
import typing

from starlette.authentication import AuthCredentials, BaseUser
from starlette.requests import HTTPConnection

from starlette_auth.settings import SESSION_KEY


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
