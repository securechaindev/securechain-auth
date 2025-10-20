from motor.motor_asyncio import AsyncIOMotorClient
from neo4j import AsyncDriver, AsyncGraphDatabase
from odmantic import AIOEngine

from app.config import settings
from app.constants import DatabaseConfig
from app.logger import logger


class DatabaseManager:
    _instance: "DatabaseManager | None" = None
    _mongo_client: AsyncIOMotorClient | None = None
    _neo4j_driver: AsyncDriver | None = None
    _odmantic_engine: AIOEngine | None = None

    def __new__(cls) -> "DatabaseManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def initialize(self) -> None:
        if self._mongo_client is None:
            logger.info("Initializing MongoDB connection pool...")
            self._mongo_client = AsyncIOMotorClient(
                settings.VULN_DB_URI,
                minPoolSize=DatabaseConfig.MIN_POOL_SIZE,
                maxPoolSize=DatabaseConfig.MAX_POOL_SIZE,
                maxIdleTimeMS=DatabaseConfig.MAX_IDLE_TIME_MS,
                serverSelectionTimeoutMS=DatabaseConfig.DEFAULT_QUERY_TIMEOUT_MS,
            )
            self._odmantic_engine = AIOEngine(
                client=self._mongo_client,
                database="securechain"
            )
            logger.info("MongoDB connection pool initialized")

        if self._neo4j_driver is None:
            logger.info("Initializing Neo4j driver...")
            self._neo4j_driver = AsyncGraphDatabase.driver(
                uri=settings.GRAPH_DB_URI,
                auth=(settings.GRAPH_DB_USER, settings.GRAPH_DB_PASSWORD),
                max_connection_pool_size=DatabaseConfig.MAX_POOL_SIZE,
            )
            logger.info("Neo4j driver initialized")

    async def close(self) -> None:
        if self._mongo_client:
            logger.info("Closing MongoDB connection...")
            self._mongo_client.close()
            self._mongo_client = None
            self._odmantic_engine = None
            logger.info("MongoDB connection closed")

        if self._neo4j_driver:
            logger.info("Closing Neo4j driver...")
            await self._neo4j_driver.close()
            self._neo4j_driver = None
            logger.info("Neo4j driver closed")

    def get_odmantic_engine(self) -> AIOEngine:
        if self._odmantic_engine is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._odmantic_engine

    def get_neo4j_driver(self) -> AsyncDriver:
        if self._neo4j_driver is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._neo4j_driver


_db_manager: DatabaseManager | None = None


def get_database_manager() -> DatabaseManager:
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager
