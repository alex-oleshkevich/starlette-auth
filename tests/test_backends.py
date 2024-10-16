from starlette.authentication import AuthCredentials, AuthenticationBackend, BaseUser
from starlette.requests import HTTPConnection

from starlette_auth.backends import MultiBackend, SessionBackend
from starlette_auth.login import SESSION_KEY
from tests.conftest import User


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

    backend = SessionBackend(user_loader=user_loader)
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

    backend = SessionBackend(user_loader=user_loader)
    conn = HTTPConnection({"type": "http"})
    conn.scope["session"] = {}
    conn.session[SESSION_KEY] = "root"
    result = await backend.authenticate(conn)
    assert result
    assert result[0].scopes == ["admin"]
