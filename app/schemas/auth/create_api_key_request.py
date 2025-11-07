from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, Field, computed_field


class CreateApiKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Descriptive name for the API key")
    duration_days: Literal[10, 20, 30] = Field(..., description="Duration in days (10, 20, or 30)")

    @computed_field
    @property
    def expires_at(self) -> datetime:
        return datetime.now(UTC) + timedelta(days=self.duration_days)
