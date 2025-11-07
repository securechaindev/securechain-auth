from odmantic import Model
from pydantic import EmailStr


class User(Model):
    email: EmailStr
    password: str
