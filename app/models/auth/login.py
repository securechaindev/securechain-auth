from pydantic import BaseModel, Field, field_validator

from app.models.patterns import EMAIL_PATTERN
from app.models.validators import validate_password


class LoginRequest(BaseModel):
    email: str = Field(
        pattern=EMAIL_PATTERN
    )
    password: str = Field(...)

    @field_validator("password")
    def validate_password(cls, value):
        return validate_password(value)
