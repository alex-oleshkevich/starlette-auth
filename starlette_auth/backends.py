import typing

from starlette.authentication import AuthCredentials, AuthenticationBackend, BaseUser
from starlette.requests import HTTPConnection

from starlette_auth.login import get_scopes, SESSION_KEY

ByIdUserFinder = typing.Callable[[HTTPConnection, str], typing.Awaitable[BaseUser | None]]


class SessionBackend(AuthenticationBackend):
    """Authentication backend that uses session to store user information."""

    def __init__(self, user_loader: ByIdUserFinder) -> None:
        self.user_loader = user_loader

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, BaseUser] | None:
        user_id: str = conn.session.get(SESSION_KEY, "")
        if user_id and (user := await self.user_loader(conn, user_id)):
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
