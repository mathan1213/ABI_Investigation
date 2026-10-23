import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    """Configuration settings for Account Breach Investigation backend."""
    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(__file__), ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "Account Breach Investigation API"
    ENVIRONMENT: str = "development"
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ]

    # Optional third-party threat intelligence keys
    ABUSEIPDB_KEY: Optional[str] = None
    VIRUSTOTAL_KEY: Optional[str] = None

    # Safety limits
    REQUEST_TIMEOUT_SECONDS: float = 5.0
    PORT_CHECK_TIMEOUT_SECONDS: float = 2.0
    RATE_LIMIT_PER_MINUTE: int = 20
    MAX_REDIRECT_HOPS: int = 8
    TOR_EXIT_CACHE_HOURS: int = 6

settings = Settings()
