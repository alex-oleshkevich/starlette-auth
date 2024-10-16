import datetime
import http.cookies
import time
from unittest import mock

import itsdangerous
from starlette.authentication import BaseUser
from starlette.requests import HTTPConnection
from starlette.responses import Response

from starlette_auth.remember_me import forget_me, REMEMBER_COOKIE_NAME, remember_me, RememberMeBackend
from tests.conftest import User


def test_remember_me() -> None:
    user = User(username="root")
    response = Response()
    remember_me(response, "key!", user, duration=datetime.timedelta(seconds=10))
    cookies: http.cookies.SimpleCookie = http.cookies.SimpleCookie(response.headers["set-cookie"])
    assert REMEMBER_COOKIE_NAME in cookies
    assert cookies[REMEMBER_COOKIE_NAME]["max-age"] == "10"

    response = Response()
    forget_me(response)
    cookies = http.cookies.SimpleCookie(response.headers["set-cookie"])
    assert REMEMBER_COOKIE_NAME in cookies
    assert cookies[REMEMBER_COOKIE_NAME]["max-age"] == "-1"


async def test_remember_me_backend() -> None:
    user = User("root")

    async def user_loader(conn: HTTPConnection, user_id: str) -> BaseUser | None:
        return user if user_id == user.identity else None

    secret_key = "key!"
    backend = RememberMeBackend(user_loader=user_loader, secret_key=secret_key)
    conn = HTTPConnection({"type": "http", "headers": {}})
    conn.cookies[REMEMBER_COOKIE_NAME] = itsdangerous.TimestampSigner(secret_key=secret_key).sign("root").decode()
    result = await backend.authenticate(conn)
    assert result
    auth_credentials, auth_user = result
    assert auth_user == user
    assert "login:remembered" in auth_credentials.scopes


async def test_remember_me_backend_no_cookie() -> None:
    async def user_loader(conn: HTTPConnection, user_id: str) -> BaseUser | None:  # pragma: no cover
        return None

    secret_key = "key!"
    backend = RememberMeBackend(user_loader=user_loader, secret_key=secret_key)
    conn = HTTPConnection({"type": "http", "headers": {}})
    assert not await backend.authenticate(conn)


async def test_remember_me_backend_not_authenticates() -> None:
    async def user_loader(conn: HTTPConnection, user_id: str) -> BaseUser | None:
        return None

    secret_key = "key!"
    backend = RememberMeBackend(user_loader=user_loader, secret_key=secret_key)
    conn = HTTPConnection({"type": "http", "headers": {}})
    conn.cookies[REMEMBER_COOKIE_NAME] = itsdangerous.TimestampSigner(secret_key=secret_key).sign("root").decode()
    assert not await backend.authenticate(conn)


async def test_remember_me_backend_checks_max_age() -> None:
    user = User("root")

    async def user_loader(conn: HTTPConnection, user_id: str) -> BaseUser | None:
        return user if user_id == user.identity else None

    secret_key = "key!"
    backend = RememberMeBackend(user_loader=user_loader, secret_key=secret_key, duration=datetime.timedelta(seconds=20))
    conn = HTTPConnection({"type": "http", "headers": {}})
    ts = time.time()

    # cookie generated 10 seconds ago
    # remember me lifetime = 20 seconds
    # test must pass
    with mock.patch("itsdangerous.TimestampSigner.get_timestamp", return_value=int(ts - 10)):
        conn.cookies[REMEMBER_COOKIE_NAME] = itsdangerous.TimestampSigner(secret_key=secret_key).sign("root").decode()
        result = await backend.authenticate(conn)
        assert result
        auth_credentials, auth_user = result
        assert auth_user == user

    # cookie generated 30 seconds ago
    # remember me lifetime = 20 seconds
    # test must fail
    with mock.patch("itsdangerous.TimestampSigner.get_timestamp", return_value=int(ts - 30)):
        conn.cookies[REMEMBER_COOKIE_NAME] = itsdangerous.TimestampSigner(secret_key=secret_key).sign("root").decode()
    assert not await backend.authenticate(conn)
