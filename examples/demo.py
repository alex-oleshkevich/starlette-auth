import dataclasses
import datetime

from starlette.applications import Starlette
from starlette.authentication import BaseUser
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import HTTPConnection, Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from starlette_auth import forget_me, is_confirmed, login, remember_me
from starlette_auth.backends import MultiBackend, SessionBackend
from starlette_auth.login import is_authenticated, logout
from starlette_auth.remember_me import RememberMeBackend


@dataclasses.dataclass
class User(BaseUser):
    name: str

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.name

    @property
    def identity(self) -> str:
        return self.name


users: dict[str, User] = {
    "admin": User(name="admin"),
}


def index_view(request: Request) -> Response:
    if is_authenticated(request):
        return RedirectResponse(url="/profile")

    return HTMLResponse(f'<h1>hi, {request.user}</h1><a href="/login">login</a>')


async def login_view(request: Request) -> Response:
    if is_authenticated(request):
        return RedirectResponse(url="/profile")

    if request.method == "POST":
        form_data = await request.form()
        email = form_data.get("email")
        user = users.get(str(email), None)
        if not user:
            return RedirectResponse("/login?message=Invalid email or password", status_code=301)

        await login(request, user)

        response = RedirectResponse("/profile?message=You are logged in", status_code=301)
        if form_data.get("remember_me"):
            response = remember_me(response, "secret", user, datetime.timedelta(days=7))
        return response

    error = request.query_params.get("message", "")
    return HTMLResponse(f"""
    <p>{error}</p>
    <form method="post" action="/login">
        <label>Email: <input type="text" name="email"></label><br>
        <label>Password: <input type="password" name="password"></label><br>
        <label><input type="checkbox" name="remember_me"> Remember me</label><br>
        <button type="submit">Login</button>
    </form>
    """)


async def logout_view(request: Request) -> Response:
    if not is_authenticated(request):
        return HTMLResponse('You are not logged in <a href="/">login</a>', status_code=401)

    await logout(request)
    response = RedirectResponse(url="/", status_code=301)
    response = forget_me(response)
    return response


def profile_view(request: Request) -> Response:
    if not is_authenticated(request):
        return RedirectResponse(url="/login?message=You are not logged in", status_code=301)
    return HTMLResponse(
        f"hi, {request.user}! confirmed: {is_confirmed(request)} "
        '<form method="post" action="/logout"><button>logout</button></form>'
    )


async def user_loader(request: HTTPConnection, username: str) -> User | None:
    if username == "admin":
        return User(name=username)
    return None


app = Starlette(
    debug=True,
    routes=[
        Route("/", index_view),
        Route("/login", login_view, methods=["get", "post"]),
        Route("/logout", logout_view, methods=["post"]),
        Route("/profile", profile_view),
    ],
    middleware=[
        Middleware(SessionMiddleware, secret_key="secret"),
        Middleware(
            AuthenticationMiddleware,
            backend=MultiBackend(
                [
                    SessionBackend(user_loader),
                    RememberMeBackend(user_loader, secret_key="secret"),
                ]
            ),
        ),
    ],
)
