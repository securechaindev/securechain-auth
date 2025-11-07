from datetime import datetime

from odmantic import Field, Model


class ApiKey(Model):
    key_hash: str
    user_id: str
    name: str
    created_at: datetime = Field(default_factory=datetime.now)
    expires_at: datetime
    is_active: bool = True
