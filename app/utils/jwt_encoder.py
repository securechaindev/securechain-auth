from datetime import datetime, timedelta
from typing import Any

from fastapi import HTTPException, Request, Response, status
from jwt import decode, encode
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.config import settings


async def set_auth_cookies(resp: Response, access_token: str, refresh_token: str) -> None:
    common = {
        "httponly": True,
        "secure": settings.SECURE_COOKIES,
        "samesite": "none" if settings.SECURE_COOKIES else "lax",
        "path": "/",
    }
    resp.set_cookie("access_token",  access_token, max_age=60 * settings.ACCESS_TOKEN_EXPIRE_MINUTES, **common)
    resp.set_cookie("refresh_token", refresh_token, max_age=60 * 60 * 24 * settings.REFRESH_TOKEN_EXPIRE_DAYS, **common)


async def create_access_token(user_id: str) -> str:
    expire = datetime.now() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"user_id": user_id, "exp": expire}
    return encode(payload, settings.JWT_ACCESS_SECRET_KEY, algorithm=settings.ALGORITHM)


async def create_refresh_token(user_id: str) -> str:
    expire = datetime.now() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {"user_id": user_id, "exp": expire}
    return encode(payload, settings.JWT_REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM)


async def read_expiration_date(refresh_token: str) -> datetime:
    try:
        payload = decode(refresh_token, settings.JWT_REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
        expires_at = datetime.fromtimestamp(payload["exp"])
    except Exception:
        expires_at = datetime.now()
    return expires_at


async def verify_access_token(token: str) -> dict[str, Any]:
    payload = decode(token, settings.JWT_ACCESS_SECRET_KEY, algorithms=[settings.ALGORITHM])
    return payload


async def verify_refresh_token(token: str) -> dict[str, Any]:
    payload = decode(token, settings.JWT_REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
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
