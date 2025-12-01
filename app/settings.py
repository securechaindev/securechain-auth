from functools import lru_cache

from pydantic import ConfigDict, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env")

    GRAPH_DB_URI: str = Field("bolt://neo4j:7687", alias="GRAPH_DB_URI")
    GRAPH_DB_USER: str = Field("neo4j", alias="GRAPH_DB_USER")
    GRAPH_DB_PASSWORD: str = Field("neoSecureChain", alias="GRAPH_DB_PASSWORD")
    VULN_DB_URI: str = Field("mongodb://mongoSecureChain:mongoSecureChain@mongo:27017/admin", alias="VULN_DB_URI")
    DOCS_URL: str | None =  Field(None, alias="DOCS_URL")
    SERVICES_ALLOWED_ORIGINS: list[str] =  Field(["*"], alias="SERVICES_ALLOWED_ORIGINS")
    SECURE_COOKIES: bool = Field(True, alias="SECURE_COOKIES")
    ALGORITHM: str = Field("HS256", alias="ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(15, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(7, alias="REFRESH_TOKEN_EXPIRE_DAYS")
    JWT_ACCESS_SECRET_KEY: str = Field("your_access_secret_key", alias="JWT_ACCESS_SECRET_KEY")
    JWT_REFRESH_SECRET_KEY: str = Field("your_refresh_secret_key", alias="JWT_REFRESH_SECRET_KEY")

    # Database Configuration
    DB_MIN_POOL_SIZE: int = 10
    DB_MAX_POOL_SIZE: int = 100
    DB_MAX_IDLE_TIME_MS: int = 60000
    DB_DEFAULT_QUERY_TIMEOUT_MS: int = 30000
    DB_USERS_COLLECTION: str = "users"
    DB_REVOKED_TOKENS_COLLECTION: str = "revoked_tokens"
    DB_API_KEYS_COLLECTION: str = "api_keys"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()
