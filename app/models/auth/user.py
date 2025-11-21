from typing import ClassVar

from odmantic import Model
from pydantic import EmailStr


class User(Model):
    email: EmailStr
    password: str

    model_config: ClassVar[dict[str, str]] = {
        "collection": "users"
    }
