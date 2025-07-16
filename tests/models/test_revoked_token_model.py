from datetime import datetime

from odmantic import Model

from app.models.auth.RevokedToken import RevokedToken


def test_revoked_token_model_fields():
    token = RevokedToken(token="sometoken", expires_at=datetime(2030, 1, 1))
    assert hasattr(token, "token")
    assert hasattr(token, "expires_at")
    assert isinstance(token.token, str)
    assert isinstance(token.expires_at, datetime)


def test_revoked_token_model_inheritance():
    token = RevokedToken(token="othertoken", expires_at=datetime(2030, 1, 1))
    assert isinstance(token, Model)
