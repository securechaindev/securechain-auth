from odmantic import Model
from datetime import datetime


class RevokedToken(Model):
    token: str
    expires_at: datetime
