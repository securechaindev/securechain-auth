from odmantic import Model
from pydantic import EmailStr, field_validator
from app.schemas.validators import validate_password

class User(Model):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_validation(cls, value: str) -> str:
        return validate_password(value)