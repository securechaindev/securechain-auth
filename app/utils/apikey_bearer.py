import hashlib
import secrets

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPBearer

from app.constants import ResponseCode, ResponseMessage
from app.models.auth import ApiKey


class ApiKeyBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    @staticmethod
    def generate() -> str:
        token = secrets.token_urlsafe(32)
        return f"sk_{token}"

    @staticmethod
    def hash(api_key: str) -> str:
        return hashlib.sha256(api_key.encode()).hexdigest()

    @staticmethod
    def verify(api_key: str, key_hash: str) -> bool:
        return hashlib.sha256(api_key.encode()).hexdigest() == key_hash

    async def __call__(self, request: Request) -> dict[str, str]:
        api_key = request.headers.get("X-API-Key")

        if not api_key:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={
                        "code": ResponseCode.MISSING_API_KEY,
                        "message": ResponseMessage.MISSING_API_KEY
                    },
                )
            return None

        if not api_key.startswith("sk_"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "code": ResponseCode.INVALID_API_KEY,
                    "message": ResponseMessage.INVALID_API_KEY
                },
            )

        key_hash = self.hash(api_key)

        db_manager = request.app.state.db_manager
        engine = db_manager.get_odmantic_engine()

        stored_key = await engine.find_one(ApiKey, ApiKey.key_hash == key_hash)

        if not stored_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "code": ResponseCode.INVALID_API_KEY,
                    "message": ResponseMessage.INVALID_API_KEY
                },
            )

        if not stored_key.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "code": ResponseCode.REVOKED_API_KEY,
                    "message": ResponseMessage.REVOKED_API_KEY
                },
            )

        return {"user_id": stored_key.user_id}
