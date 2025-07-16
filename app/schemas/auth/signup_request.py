from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schemas.patterns import EMAIL_PATTERN
from app.schemas.validators import validate_password


class SignUpRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        pattern=EMAIL_PATTERN,
        description="User's email address."
    )
    password: str = Field(
        ...,
        description="User's password."
    )

    @field_validator("password")
    def validate_password(cls, value):
        return validate_password(value)
