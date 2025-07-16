from pydantic import BaseModel, Field, field_validator

from app.schemas.patterns import EMAIL_PATTERN
from app.schemas.validators import validate_password


class LoginRequest(BaseModel):
    email: str = Field(
        ...,
        pattern=EMAIL_PATTERN,
        description="User's email address."
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=20,
        description="User's password."
    )

    @field_validator("password")
    def validate_password(cls, value):
        return validate_password(value)
