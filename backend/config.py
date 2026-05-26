from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    ENVIRONMENT: str = "development"
    API_V1_PREFIX: str = "/api/v1"

    # Gemini
    GEMINI_API_KEY: str
    GEMINI_STORE_ID: str = ""          # file_search_stores/xxxx — set after first upload
    GEMINI_MODEL: str = "gemini-2.0-flash"

    # Auth
    BACKEND_API_KEY: str               # shared secret: MCP → backend (X-Api-Key header)
    ADMIN_TOKEN: str                   # upload / store management (X-Admin-Token header)


@lru_cache
def get_settings() -> Settings:
    return Settings()
