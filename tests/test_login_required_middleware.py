from unittest import mock

import pytest
from starlette.applications import Starlette
from starlette.authentication import AuthCredentials, AuthenticationBackend, BaseUser
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import HTTPConnection, Request
from starlette.routing import Route
from starlette.testclient import TestClient
from starlette.types import Message

from starlette_auth import LoginRequiredMiddleware
from tests.conftest import User


def view(request: Request) -> None: ...


class _DummyLoginBackend(AuthenticationBackend):
    def __init__(self, user: User) -> None:
        self.user = user

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, BaseUser] | None:
        return (AuthCredentials(), self.user) if "login" in conn.query_params else None


def test_login_required_middleware_redirects_to_url(user: User) -> None:
    app = Starlette(
        debug=True,
        routes=[
            Route("/", view),
        ],
        middleware=[
            Middleware(AuthenticationMiddleware, backend=_DummyLoginBackend(user)),
            Middleware(LoginRequiredMiddleware, redirect_url="/login"),
        ],
    )
    client = TestClient(app)

    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/login?next=%2F"


def test_login_required_middleware_redirects_to_path(user: User) -> None:
    app = Starlette(
        debug=True,
        routes=[
            Route("/", view),
            Route("/security/login/{id}", view, name="login"),
        ],
        middleware=[
            Middleware(AuthenticationMiddleware, backend=_DummyLoginBackend(user)),
            Middleware(LoginRequiredMiddleware, path_name="login", path_params={"id": "1"}),
        ],
    )
    client = TestClient(app)
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/security/login/1?next=%2F"


def test_login_required_middleware_redirects_to_default_route_path(user: User) -> None:
    app = Starlette(
        debug=True,
        routes=[
            Route("/", view),
            Route("/security/login", view, name="login"),
        ],
        middleware=[
            Middleware(AuthenticationMiddleware, backend=_DummyLoginBackend(user)),
            Middleware(LoginRequiredMiddleware),
        ],
    )
    client = TestClient(app)
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/security/login?next=%2F"


@pytest.mark.anyio()
async def test_login_required_middleware_bypass_unsupported_request_types(user: User) -> None:
    async def receive() -> Message:  # pragma: nocover
        return {}

    async def send(message: Message) -> None:  # pragma: nocover
        ...

    base_app = mock.AsyncMock()
    app = LoginRequiredMiddleware(base_app)
    await app({"type": "unsupported"}, receive, send)
    base_app.assert_called_once()


@pytest.mark.anyio()
async def test_login_calls_next_app_on_success(user: User) -> None:
    async def receive() -> Message:  # pragma: nocover
        return {}

    async def send(message: Message) -> None:  # pragma: nocover
        ...

    base_app = mock.AsyncMock()
    app = LoginRequiredMiddleware(base_app)
    await app({"type": "http", "user": user}, receive, send)
    base_app.assert_called_once()

    base_app = mock.AsyncMock()
    app = LoginRequiredMiddleware(base_app)
    await app({"type": "websocket", "user": user}, receive, send)
    base_app.assert_called_once()
