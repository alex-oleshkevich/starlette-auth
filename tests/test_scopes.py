from starlette.authentication import AuthCredentials
from starlette.requests import Request

from starlette_auth.scopes import confirm_login, is_confirmed, LoginScopes
from tests.conftest import User


def test_is_confirmed() -> None:
    assert is_confirmed(
        Request(
            {
                "type": "http",
                "headers": {},
                "session": {},
                "auth": AuthCredentials(scopes=[LoginScopes.FRESH]),
            }
        )
    )
    assert not is_confirmed(
        Request(
            {
                "type": "http",
                "headers": {},
                "session": {},
                "auth": AuthCredentials(scopes=[LoginScopes.REMEMBERED]),
            }
        )
    )
    assert not is_confirmed(
        Request(
            {
                "type": "http",
                "headers": {},
                "session": {},
                "auth": AuthCredentials(scopes=[]),
            }
        )
    )


def test_confirm_login_ok(user: User) -> None:
    request = Request(
        {
            "type": "http",
            "headers": {},
            "session": {},
            "user": user,
            "auth": AuthCredentials(scopes=[LoginScopes.REMEMBERED]),
        }
    )
    confirm_login(request)
    assert is_confirmed(request)


def test_confirm_login_when_already_confirmed(user: User) -> None:
    request = Request(
        {
            "type": "http",
            "headers": {},
            "session": {},
            "user": user,
            "auth": AuthCredentials(scopes=[LoginScopes.FRESH]),
        }
    )
    confirm_login(request)
    assert is_confirmed(request)
