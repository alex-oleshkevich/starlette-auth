from unittest import mock

from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.testclient import TestClient
from starlette.types import Receive, Scope, Send
from starsessions import CookieStore, load_session, SessionMiddleware as StarsessionSessionMiddleware

from starlette_auth.login import is_authenticated, login, logout
from tests.conftest import User


def test_login() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive, send)
        user = User(username="root")
        await login(request, user)
        authenticated = is_authenticated(request)
        await Response("yes" if authenticated else "no")(scope, receive, send)

    client = TestClient(SessionMiddleware(app, secret_key="key!"))
    response = client.get("/")
    assert response.text == "yes"
    assert "session" in response.cookies


def test_login_regenerates_session_id() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive, send)
        await load_session(request)
        user = User(username="root")
        await login(request, user)
        authenticated = is_authenticated(request)
        await Response("yes" if authenticated else "no")(scope, receive, send)

    with mock.patch("starsessions.regenerate_session_id") as fn:
        client = TestClient(StarsessionSessionMiddleware(app, store=CookieStore(secret_key="key!")))
        client.get("/")
        fn.assert_called_once()


def test_logout() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive, send)
        user = User(username="root")
        await login(request, user)
        assert is_authenticated(request)

        await logout(request)
        await Response("yes" if request.user.is_authenticated else "no")(scope, receive, send)

    client = TestClient(SessionMiddleware(app, secret_key="key!"))
    response = client.get("/")
    assert response.text == "no"
    assert "session" not in response.cookies
