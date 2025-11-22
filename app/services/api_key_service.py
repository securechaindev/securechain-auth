from datetime import datetime

from bson import ObjectId

from app.database import DatabaseManager
from app.exceptions import ApiKeyNameExistsException
from app.utils.apikey_bearer import ApiKeyBearer


class ApiKeyService:
    def __init__(self, db: DatabaseManager) -> None:
        self.api_keys_collection = db.get_api_keys_collection()

    async def create_api_key(self, user_id: str, name: str, expires_at: datetime) -> dict:
        existing_key = await self.api_keys_collection.find_one(
            {"user_id": user_id, "name": name}
        )

        if existing_key:
            raise ApiKeyNameExistsException(name)

        api_key = ApiKeyBearer.generate()
        key_hash = ApiKeyBearer.hash(api_key)

        api_key_doc = {
            "key_hash": key_hash,
            "user_id": user_id,
            "name": name,
            "created_at": datetime.now(),
            "expires_at": expires_at,
            "is_active": True
        }

        result = await self.api_keys_collection.insert_one(api_key_doc)

        return {
            "id": str(result.inserted_id),
            "api_key": api_key,
            "name": api_key_doc["name"],
            "created_at": api_key_doc["created_at"].isoformat(),
            "expires_at": api_key_doc["expires_at"].isoformat(),
            "is_active": api_key_doc["is_active"]
        }

    async def list_user_api_keys(self, user_id: str) -> list[dict]:
        cursor = self.api_keys_collection.find({"user_id": user_id})
        api_keys = await cursor.to_list(length=None)

        return [
            {
                "id": str(key["_id"]),
                "name": key["name"],
                "created_at": key["created_at"].isoformat(),
                "expires_at": key["expires_at"].isoformat(),
                "is_active": key["is_active"]
            }
            for key in api_keys
        ]

    async def revoke_api_key(self, key_id: str, user_id: str) -> bool:
        try:
            result = await self.api_keys_collection.update_one(
                {"_id": ObjectId(key_id), "user_id": user_id},
                {"$set": {"is_active": False}}
            )
            return result.modified_count > 0
        except Exception:
            return False
