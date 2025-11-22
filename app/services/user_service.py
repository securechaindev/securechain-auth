from datetime import datetime

from app.database import DatabaseManager


class UserService:
    def __init__(self, db: DatabaseManager) -> None:
        self.driver = db.get_neo4j_driver()
        self.users_collection = db.get_users_collection()
        self.revoked_tokens_collection = db.get_revoked_tokens_collection()

    async def create_user(self, email: str, password: str) -> None:
        result = await self.users_collection.insert_one({
            "email": email,
            "password": password
        })
        user_id = str(result.inserted_id)

        query = """
        create(u: User{
            _id: $user_id
        })
        """
        async with self.driver.session() as session:
            await session.run(query, user_id=user_id)

    async def create_revoked_token(self, token: str, expires_at: datetime) -> None:
        await self.revoked_tokens_collection.insert_one({
            "token": token,
            "expires_at": expires_at
        })

    async def read_user_by_email(self, email: str) -> dict | None:
        return await self.users_collection.find_one({"email": email})

    async def update_user_password(self, email: str, password: str) -> None:
        await self.users_collection.update_one(
            {"email": email},
            {"$set": {"password": password}}
        )

    async def is_token_revoked(self, token: str) -> bool:
        revoked_token = await self.revoked_tokens_collection.find_one({"token": token})
        return revoked_token is not None
