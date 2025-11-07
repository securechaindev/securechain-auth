from datetime import datetime

from bson import ObjectId

from app.database import DatabaseManager
from app.exceptions import ApiKeyNameExistsException
from app.models.auth import ApiKey
from app.utils.apikey_bearer import ApiKeyBearer


class ApiKeyService:
    def __init__(self, db: DatabaseManager) -> None:
        self.engine = db.get_odmantic_engine()

    async def create_api_key(self, user_id: str, name: str, expires_at: datetime) -> dict:
        existing_key = await self.engine.find_one(
            ApiKey, ApiKey.user_id == user_id, ApiKey.name == name
        )

        if existing_key:
            raise ApiKeyNameExistsException(name)

        api_key = ApiKeyBearer.generate()
        key_hash = ApiKeyBearer.hash(api_key)
        api_key_doc = ApiKey(
            key_hash=key_hash,
            user_id=user_id,
            name=name,
            expires_at=expires_at
        )
        result = await self.engine.save(api_key_doc)

        return {
            "id": str(result.id),
            "api_key": api_key,
            "name": result.name,
            "created_at": result.created_at.isoformat(),
            "expires_at": result.expires_at.isoformat(),
            "is_active": result.is_active
        }

    async def list_user_api_keys(self, user_id: str) -> list[dict]:
        api_keys = await self.engine.find(ApiKey, ApiKey.user_id == user_id)

        return [
            {
                "id": str(key.id),
                "name": key.name,
                "created_at": key.created_at.isoformat(),
                "expires_at": key.expires_at.isoformat(),
                "is_active": key.is_active
            }
            for key in api_keys
        ]

    async def revoke_api_key(self, key_id: str, user_id: str) -> bool:
        try:
            api_key = await self.engine.find_one(
                ApiKey,
                ApiKey.id == ObjectId(key_id),
                ApiKey.user_id == user_id
            )

            if not api_key:
                return False

            api_key.is_active = False
            await self.engine.save(api_key)

            return True
        except Exception:
            return False
