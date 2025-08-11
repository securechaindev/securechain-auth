from datetime import datetime, timedelta
from typing import Any

from fastapi import HTTPException, Request, status
from jwt import decode, encode
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.config import settings


async def create_access_token(user_id: str) -> str:
    expire = datetime.now() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"user_id": str(user_id), "exp": expire}
    return encode(payload, settings.JWT_ACCESS_SECRET_KEY, algorithm=settings.ALGORITHM)


async def create_refresh_token(user_id: str) -> str:
    expire = datetime.now() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {"user_id": str(user_id), "exp": expire}
    return encode(payload, settings.JWT_REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM)


async def read_expiration_date(request: Request) -> datetime:
    token = request.cookies.get("refresh_token")
    if not token:
        return datetime.now()
    try:
        payload = decode(token, settings.JWT_REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
        return datetime.fromtimestamp(payload["exp"])
    except (ExpiredSignatureError, InvalidTokenError, KeyError, TypeError, ValueError):
        return datetime.now()


async def verify_access_token(request: Request) -> dict[str, Any]:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = decode(token, settings.JWT_ACCESS_SECRET_KEY, algorithms=[settings.ALGORITHM])
    except ExpiredSignatureError as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from err
    except InvalidTokenError as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from err
    return payload


async def verify_refresh_token(request: Request) -> dict[str, Any]:
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = decode(token, settings.JWT_REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
    except ExpiredSignatureError as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from err
    except InvalidTokenError as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from err
    return payload


class JWTBearer:
    def __init__(self, cookie_name: str = "access_token"):
        self.cookie_name = cookie_name

    async def __call__(self, request: Request) -> dict[str, Any]:
        token = request.cookies.get(self.cookie_name)
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        try:
            payload = decode(token, settings.JWT_ACCESS_SECRET_KEY, algorithms=[settings.ALGORITHM])
        except ExpiredSignatureError as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from err
        except InvalidTokenError as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from err
        return payload
