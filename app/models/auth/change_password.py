from pydantic import BaseModel, Field, field_validator

from app.models.patterns import EMAIL_PATTERN
from app.models.validators import validate_password


class ChangePasswordRequest(BaseModel):
    email: str = Field(
        pattern=EMAIL_PATTERN
    )
    old_password: str = Field(...)
    new_password: str = Field(...)

    @field_validator("new_password", "old_password")
    def validate_password(cls, value):
        return validate_password(value)
