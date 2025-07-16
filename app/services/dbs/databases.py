from functools import lru_cache

from motor.motor_asyncio import AsyncIOMotorClient
from neo4j import AsyncDriver, AsyncGraphDatabase
from odmantic import AIOEngine

from app.config import settings


@lru_cache
def get_graph_db_driver() -> AsyncDriver:
    return AsyncGraphDatabase.driver(
        uri=settings.GRAPH_DB_URI,
        auth=(settings.GRAPH_DB_USER, settings.GRAPH_DB_PASSWORD),
    )


@lru_cache
def get_odmantic_engine() -> AIOEngine:
    return AIOEngine(
        client=AsyncIOMotorClient(settings.VULN_DB_URI),
        database="securechain"
    )
