from datetime import datetime, timedelta
from typing import Any

from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import decode, encode

from app.config import settings


async def create_access_token(user_id: str) -> str:
    expire = datetime.now() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"user_id": str(user_id), "exp": expire}
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


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials | None = await super().__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not await verify_access_token(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")
