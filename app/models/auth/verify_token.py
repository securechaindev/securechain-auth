from pydantic import BaseModel, Field


class VerifyTokenRequest(BaseModel):
    token: str | None = Field(...)
