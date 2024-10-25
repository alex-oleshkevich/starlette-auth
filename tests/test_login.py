from unittest import mock

from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.testclient import TestClient
from starlette.types import Receive, Scope, Send
from starsessions import CookieStore, load_session, SessionMiddleware as StarsessionSessionMiddleware

from starlette_auth import is_authenticated, login, logout
from starlette_auth.authentication import SESSION_HASH, SESSION_KEY
from tests.conftest import User, UserWithSessionHash


def test_login() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive, send)
        user = User(username="root")
        await login(request, user, secret_key="key!")
        authenticated = is_authenticated(request)
        await Response("yes" if authenticated else "no")(scope, receive, send)

    client = TestClient(SessionMiddleware(app, secret_key="key!"))
    response = client.get("/")
    assert response.text == "yes"
    assert "session" in response.cookies


async def test_session_auth_hash() -> None:
    """It should compute and store session auth hash."""
    user = UserWithSessionHash(username="root", password="password")
    request = mock.MagicMock(
        session={"keepme": "ok"},
        scope={},
    )
    await login(request, user, secret_key="key!")
    assert request.session[SESSION_KEY] == user.identity
    assert SESSION_HASH in request.session
    assert request.session["keepme"] == "ok"


async def test_session_auth_hash_with_base_user() -> None:
    """Users who do not implement HasSessionAuthHash should also have session auth hash."""
    user = User(username="root")
    request = mock.MagicMock(
        session={"keepme": "ok"},
        scope={},
    )
    await login(request, user, secret_key="key!")
    assert request.session[SESSION_KEY] == user.identity
    assert SESSION_HASH in request.session
    assert request.session["keepme"] == "ok"


async def test_session_auth_hash_with_base_user_and_existing_user() -> None:
    user = User(username="root")
    request = mock.MagicMock(
        session={"keepme": "ok", SESSION_KEY: "root"},
        scope={},
    )
    await login(request, user, secret_key="key!")
    assert request.session[SESSION_KEY] == user.identity
    assert SESSION_HASH in request.session
    assert request.session["keepme"] == "ok"


async def test_with_existing_another_user() -> None:
    """If user identity is present in the session, then user should be compared with current one.
    If they are different, then session should be cleared."""
    user = UserWithSessionHash(username="root", password="password")
    request = mock.MagicMock(
        session={SESSION_KEY: "another_user", "keepme": "ok"},
        scope={},
    )
    await login(request, user, secret_key="key!")
    assert request.session[SESSION_KEY] == user.identity
    assert SESSION_HASH in request.session
    assert "keepme" not in request.session


async def test_with_existing_current_user_and_valid_hash() -> None:
    """If user identity is present in the session, and it is the same as current user, then check the session auth hash."""
    user = UserWithSessionHash(username="root", password="password")
    request = mock.MagicMock(
        session={SESSION_KEY: user.identity, "keepme": "ok", SESSION_HASH: user.get_session_auth_hash("key!")},
        scope={},
    )
    await login(request, user, secret_key="key!")
    assert request.session[SESSION_KEY] == user.identity
    assert SESSION_HASH in request.session
    assert "keepme" in request.session


async def test_with_existing_current_user_and_invalid_hash() -> None:
    """If user identity is present in the session, and it is the same as current user,
    then check the session auth hash. If it is invalid, then clear the session."""
    user = UserWithSessionHash(username="root", password="password")
    request = mock.MagicMock(
        session={SESSION_KEY: user.identity, "keepme": "ok", SESSION_HASH: "bad hash"},
        scope={},
    )
    await login(request, user, secret_key="key!")
    assert request.session[SESSION_KEY] == user.identity
    assert SESSION_HASH in request.session
    assert "keepme" not in request.session


def test_login_regenerates_session_id() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive, send)
        await load_session(request)
        user = User(username="root")
        await login(request, user, secret_key="key!")
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
        await login(request, user, secret_key="key!")
        assert is_authenticated(request)

        await logout(request)
        await Response("yes" if request.user.is_authenticated else "no")(scope, receive, send)

    client = TestClient(SessionMiddleware(app, secret_key="key!"))
    response = client.get("/")
    assert response.text == "no"
    assert "session" not in response.cookies
