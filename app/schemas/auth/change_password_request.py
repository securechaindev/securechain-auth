from pydantic import BaseModel, Field, field_validator

from app.schemas.patterns import EMAIL_PATTERN
from app.schemas.validators import validate_password


class ChangePasswordRequest(BaseModel):
    email: str = Field(
        ...,
        pattern=EMAIL_PATTERN,
        description="User's email address."
    )
    old_password: str = Field(
        ...,
        min_length=8,
        max_length=20,
        description="User's old password."
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=20,
        description="User's new password."
    )

    @field_validator("new_password", "old_password")
    def validate_password(cls, value):
        return validate_password(value)
