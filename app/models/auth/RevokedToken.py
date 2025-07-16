from datetime import datetime

from odmantic import Model


class RevokedToken(Model):
    token: str
    expires_at: datetime
