from pydantic import BaseModel, Field, field_validator, EmailStr

from app.models.patterns import EMAIL_PATTERN
from app.models.validators import validate_password


class User(BaseModel):
    email: EmailStr = Field(
        ...,
        pattern=EMAIL_PATTERN,
        description="User's email address, must match the specified pattern."
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=20,
        description="User's password, must be between 8 and 20 characters long."
    )

    @field_validator("password")
    def validate_password(cls, value):
        return validate_password(value)
