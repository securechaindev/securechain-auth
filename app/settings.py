from functools import lru_cache

from pydantic import ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env")

    GRAPH_DB_URI: str = ""
    GRAPH_DB_USER: str = ""
    GRAPH_DB_PASSWORD: str = ""
    VULN_DB_URI: str = ""
    VULN_DB_USER: str = ""
    VULN_DB_PASSWORD: str = ""
    DOCS_URL: str | None = None
    SERVICES_ALLOWED_ORIGINS: list[str] = []
    SECURE_COOKIES: bool = True
    ALGORITHM: str = ""
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 0
    REFRESH_TOKEN_EXPIRE_DAYS: int = 0
    JWT_ACCESS_SECRET_KEY: str = ""
    JWT_REFRESH_SECRET_KEY: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()
