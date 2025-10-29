from motor.motor_asyncio import AsyncIOMotorClient
from neo4j import AsyncDriver, AsyncGraphDatabase
from odmantic import AIOEngine

from app.constants import DatabaseConfig
from app.logger import logger
from app.settings import settings


class DatabaseManager:
    instance: "DatabaseManager | None" = None
    mongo_client: AsyncIOMotorClient | None = None
    neo4j_driver: AsyncDriver | None = None
    odmantic_engine: AIOEngine | None = None

    def __new__(cls) -> "DatabaseManager":
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    async def initialize(self) -> None:
        if self.mongo_client is None:
            logger.info("Initializing MongoDB connection pool...")
            self.mongo_client = AsyncIOMotorClient(
                settings.VULN_DB_URI,
                minPoolSize=DatabaseConfig.MIN_POOL_SIZE,
                maxPoolSize=DatabaseConfig.MAX_POOL_SIZE,
                maxIdleTimeMS=DatabaseConfig.MAX_IDLE_TIME_MS,
                serverSelectionTimeoutMS=DatabaseConfig.DEFAULT_QUERY_TIMEOUT_MS,
            )
            self.odmantic_engine = AIOEngine(
                client=self.mongo_client,
                database="securechain"
            )
            logger.info("MongoDB connection pool initialized")

        if self.neo4j_driver is None:
            logger.info("Initializing Neo4j driver...")
            self.neo4j_driver = AsyncGraphDatabase.driver(
                uri=settings.GRAPH_DB_URI,
                auth=(settings.GRAPH_DB_USER, settings.GRAPH_DB_PASSWORD),
                max_connection_pool_size=DatabaseConfig.MAX_POOL_SIZE,
            )
            logger.info("Neo4j driver initialized")

    async def close(self) -> None:
        if self.mongo_client:
            logger.info("Closing MongoDB connection...")
            self.mongo_client.close()
            self.mongo_client = None
            self.odmantic_engine = None
            logger.info("MongoDB connection closed")

        if self.neo4j_driver:
            logger.info("Closing Neo4j driver...")
            await self.neo4j_driver.close()
            self.neo4j_driver = None
            logger.info("Neo4j driver closed")

    def get_odmantic_engine(self) -> AIOEngine:
        if self.odmantic_engine is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self.odmantic_engine

    def get_neo4j_driver(self) -> AsyncDriver:
        if self.neo4j_driver is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self.neo4j_driver


db_manager: DatabaseManager | None = None


def get_database_manager() -> DatabaseManager:
    global db_manager
    if db_manager is None:
        db_manager = DatabaseManager()
    return db_manager
