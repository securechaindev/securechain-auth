from pydantic import BaseModel, Field

from app.schemas.patterns import EMAIL_PATTERN


class AccountExistsRequest(BaseModel):
    email: str = Field(
        ...,
        pattern=EMAIL_PATTERN,
        description="User's email address."
    )
