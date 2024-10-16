import typing

from starlette.authentication import BaseUser
from starlette.datastructures import URL
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send


class LoginRequiredMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        redirect_url: str | None = None,
        *,
        path_name: str | None = "login",
        path_params: dict[str, typing.Any] | None = None,
    ) -> None:
        assert redirect_url or path_name
        self.app = app
        self.redirect_url = redirect_url
        self.path_name = path_name
        self.path_params = path_params or {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        user = typing.cast(BaseUser, scope.get("user"))
        if not user.is_authenticated:
            request = Request(scope, receive, send)
            redirect_to = self.redirect_url or request.app.url_path_for(self.path_name, **self.path_params)
            url = URL(redirect_to).include_query_params(next=str(request.url.replace(scheme="", netloc="")))
            response = RedirectResponse(url, 302)
            await response(scope, receive, send)
        else:
            await self.app(scope, receive, send)
