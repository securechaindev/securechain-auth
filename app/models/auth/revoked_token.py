from datetime import datetime
from typing import ClassVar

from odmantic import Model


class RevokedToken(Model):
    token: str
    expires_at: datetime

    model_config: ClassVar[dict[str, str]] = {
        "collection": "revoked_tokens"
    }
