from pydantic import BaseModel, EmailStr, Field

from app.schemas.patterns import EMAIL_PATTERN


class AccountExistsRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        pattern=EMAIL_PATTERN,
        description="User's email address."
    )
