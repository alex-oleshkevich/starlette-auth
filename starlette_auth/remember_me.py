import datetime
import typing

import itsdangerous
from starlette.authentication import AuthCredentials, AuthenticationBackend, BaseUser
from starlette.requests import HTTPConnection
from starlette.responses import Response

from starlette_auth.backends import ByIdUserFinder
from starlette_auth.login import get_scopes, LoginScopes

REMEMBER_COOKIE_NAME = "remember_me"


class RememberMeBackend(AuthenticationBackend):
    """Authenticates user using "remember me" cookie.

    It also adds "login:remembered" scope to distinguish between fresh and remembered logins."""

    def __init__(
        self,
        user_loader: ByIdUserFinder,
        secret_key: str,
        duration: datetime.timedelta | None = None,
        *,
        cookie_name: str = REMEMBER_COOKIE_NAME,
    ) -> None:
        self.secret_key = secret_key
        self.user_loader = user_loader
        self.cookie_name = cookie_name
        self.duration = duration

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, BaseUser] | None:
        if cookie_value := conn.cookies.get(self.cookie_name):
            try:
                max_age = int(self.duration.total_seconds()) if self.duration else None
                signer = itsdangerous.TimestampSigner(secret_key=self.secret_key)
                user_id = signer.unsign(cookie_value, max_age=max_age).decode("utf8")
                if user := await self.user_loader(conn, user_id):
                    return AuthCredentials(scopes=get_scopes(user) + [LoginScopes.REMEMBERED]), user
            except itsdangerous.BadSignature:
                return None
        return None


def remember_me(
    response: Response,
    secret_key: str,
    user: BaseUser,
    duration: datetime.timedelta,
    *,
    cookie_name: str = REMEMBER_COOKIE_NAME,
    cookie_path: str = "/",
    cookie_domain: str | None = None,
    cookie_samesite: typing.Literal["lax", "strict", "none"] = "lax",
    cookie_secure: bool = False,
    cookie_http_only: bool = True,
) -> Response:
    """Remember user by setting a cookie."""
    signer = itsdangerous.TimestampSigner(secret_key)
    value = signer.sign(user.identity).decode("utf8")
    response.set_cookie(
        key=cookie_name,
        value=value,
        max_age=int(duration.total_seconds()),
        path=cookie_path,
        domain=cookie_domain,
        secure=cookie_secure,
        httponly=cookie_http_only,
        samesite=cookie_samesite,
    )
    return response


def forget_me(
    response: Response,
    *,
    cookie_name: str = REMEMBER_COOKIE_NAME,
    cookie_path: str = "/",
    cookie_domain: str | None = None,
    cookie_samesite: typing.Literal["lax", "strict", "none"] = "lax",
    cookie_secure: bool = False,
    cookie_http_only: bool = True,
) -> Response:
    """Forget user by removing 'remember me' cookie."""
    response.set_cookie(
        key=cookie_name,
        value="null",
        max_age=-1,
        path=cookie_path,
        domain=cookie_domain,
        secure=cookie_secure,
        httponly=cookie_http_only,
        samesite=cookie_samesite,
    )
    return response
