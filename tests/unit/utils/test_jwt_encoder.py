from datetime import datetime
from unittest.mock import Mock

import pytest
from fastapi import Response

from app.exceptions import NotAuthenticatedException
from app.utils import JWTBearer


@pytest.fixture
def jwt_bearer():
    return JWTBearer()


def test_jwt_bearer_read_expiration_date_invalid_token(jwt_bearer):
    invalid_token = "invalid.token.here"

    expiration = jwt_bearer.read_expiration_date(invalid_token)

    # Should return current time when token is invalid
    assert isinstance(expiration, datetime)
    assert abs((expiration - datetime.now()).total_seconds()) < 1


def test_jwt_bearer_set_auth_cookies(jwt_bearer):
    response = Response()
    access_token = "access_token_value"
    refresh_token = "refresh_token_value"

    jwt_bearer.set_auth_cookies(response, access_token, refresh_token)

    # Check that cookies were set by looking at raw headers
    raw_headers = response.raw_headers
    cookie_headers = [h for h in raw_headers if h[0] == b'set-cookie']

    assert len(cookie_headers) == 2
    assert b'access_token' in cookie_headers[0][1]
    assert b'refresh_token' in cookie_headers[1][1]


@pytest.mark.asyncio
async def test_jwt_bearer_call_without_token(jwt_bearer):
    from fastapi import Request

    request = Mock(spec=Request)
    request.cookies = {}

    with pytest.raises(NotAuthenticatedException):
        await jwt_bearer(request)
