from datetime import datetime

from app.database import DatabaseManager
from app.models.auth import RevokedToken, User


class UserService:
    def __init__(self, db: DatabaseManager) -> None:
        self.driver = db.get_neo4j_driver()
        self.engine = db.get_odmantic_engine()

    async def create_user(self, user: dict[str, str]) -> None:
        query = """
        create(u: User{
            _id: $user_id
        })
        """
        user: User = User(**user)
        result = await self.engine.save(user)
        user_id = str(result.id)
        async with self.driver.session() as session:
            result = await session.run(query, user_id=user_id)

    async def create_revoked_token(self, token: str, expires_at: datetime) -> None:
        revoked_token = RevokedToken(token=token, expires_at=expires_at)
        await self.engine.save(revoked_token)

    async def read_user_by_email(self, email: str) -> User:
        user = await self.engine.find_one(User, User.email == email)
        return user

    async def update_user_password(self, user: User) -> None:
        user_doc = await self.engine.find_one(User, User.email == user.email)
        if user_doc:
            user_doc.password = user.password
            await self.engine.save(user_doc)

    async def is_token_revoked(self, token: str) -> bool:
        revoked_token = await self.engine.find_one(RevokedToken, RevokedToken.token == token)
        return revoked_token is not None
