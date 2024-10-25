import dataclasses

import pytest
from starlette.authentication import BaseUser

from starlette_auth.authentication import HasSessionAuthHash


@dataclasses.dataclass
class User(BaseUser):
    username: str

    @property
    def identity(self) -> str:
        return self.username

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:  # pragma: no cover
        return self.username


@pytest.fixture
def user() -> User:
    return User(username="root")


@dataclasses.dataclass
class UserWithSessionHash(User, HasSessionAuthHash):
    password: str

    def get_password_hash(self) -> str:
        return self.password
