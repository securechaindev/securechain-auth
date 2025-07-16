from datetime import datetime

from app.logger import logger
from app.models.auth import RevokedToken, User

from .dbs.databases import get_graph_db_driver, get_odmantic_engine


async def create_user(user: dict[str, str]) -> None:
    engine = get_odmantic_engine()
    query = """
    create(u: User{
        _id: $user_id
    })
    """
    user: User = User(**user)
    result = await engine.save(user)
    user_id = str(result.id)
    async with get_graph_db_driver().session() as session:
        result = await session.run(query, user_id=user_id)


async def create_revoked_token(token: str, expires_at: datetime) -> None:
    engine = get_odmantic_engine()
    revoked_token = RevokedToken(token=token, expires_at=expires_at)
    await engine.save(revoked_token)


async def read_user_by_email(email: str) -> User:
    engine = get_odmantic_engine()
    user = await engine.find_one(User, User.email == email)
    return user


async def update_user_password(user: User) -> None:
    engine = get_odmantic_engine()
    logger.info(user)
    user_doc = await engine.find_one(User, User.email == user.email)
    if user_doc:
        user_doc.password = user.password
        await engine.save(user_doc)


async def is_token_revoked(token: str) -> bool:
    engine = get_odmantic_engine()
    revoked_token = await engine.find_one(RevokedToken, RevokedToken.token == token)
    return revoked_token is not None
