from starlette_auth.backends import MultiBackend, SessionBackend
from starlette_auth.login import is_authenticated, login, logout
from starlette_auth.middleware import LoginRequiredMiddleware
from starlette_auth.remember_me import forget_me, remember_me, RememberMeBackend
from starlette_auth.scopes import confirm_login, is_confirmed, LoginScopes

__all__ = [
    "login",
    "logout",
    "is_authenticated",
    "MultiBackend",
    "SessionBackend",
    "RememberMeBackend",
    "remember_me",
    "forget_me",
    "confirm_login",
    "is_confirmed",
    "LoginScopes",
    "LoginRequiredMiddleware",
]
