from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database connections (required)
    GRAPH_DB_URI: str = Field(..., alias="GRAPH_DB_URI")
    GRAPH_DB_USER: str = Field(..., alias="GRAPH_DB_USER")
    GRAPH_DB_PASSWORD: str = Field(..., alias="GRAPH_DB_PASSWORD")
    VULN_DB_URI: str = Field(..., alias="VULN_DB_URI")

    # JWT secrets (required)
    JWT_ACCESS_SECRET_KEY: str = Field(..., alias="JWT_ACCESS_SECRET_KEY")
    JWT_REFRESH_SECRET_KEY: str = Field(..., alias="JWT_REFRESH_SECRET_KEY")

    # Application settings (safe defaults)
    DOCS_URL: str | None = Field(None, alias="DOCS_URL")
    SERVICES_ALLOWED_ORIGINS: list[str] = Field(["*"], alias="SERVICES_ALLOWED_ORIGINS")
    SECURE_COOKIES: bool = Field(True, alias="SECURE_COOKIES")
    ALGORITHM: str = Field("HS256", alias="ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(15, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(7, alias="REFRESH_TOKEN_EXPIRE_DAYS")

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
