import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
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
    GITHUB_TOKEN: Optional[str] = None

    # Telegram MTProto API credentials (https://my.telegram.org)
    TELEGRAM_API_ID: Optional[int] = None
    TELEGRAM_API_HASH: Optional[str] = None

    @field_validator("TELEGRAM_API_ID", mode="before")
    @classmethod
    def parse_telegram_api_id(cls, v):
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        return int(v)

    @field_validator("ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "GITHUB_TOKEN", "TELEGRAM_API_HASH", mode="before")
    @classmethod
    def parse_empty_strings(cls, v):
        if isinstance(v, str) and not v.strip():
            return None
        return v

    # Safety limits
    REQUEST_TIMEOUT_SECONDS: float = 5.0
    PORT_CHECK_TIMEOUT_SECONDS: float = 2.0
    RATE_LIMIT_PER_MINUTE: int = 20
    REPO_RATE_LIMIT_PER_MINUTE: int = 5
    REPO_CLONE_TIMEOUT_SECONDS: float = 60.0
    REPO_OVERALL_TIMEOUT_SECONDS: float = 120.0
    REPO_MAX_FILES: int = 3000
    REPO_MAX_FILE_BYTES: int = 1024 * 1024  # 1 MB
    REPO_MAX_SIZE_KB: int = 100 * 1024  # 100 MB
    MAX_REDIRECT_HOPS: int = 8
    TOR_EXIT_CACHE_HOURS: int = 6
    TELEGRAM_SEND_CODE_RATE_LIMIT: int = 3  # per 10 minutes
    TELEGRAM_DEFAULT_RATE_LIMIT: int = 10   # per minute
    TELEGRAM_FLOW_TTL_SECONDS: int = 600   # 10 minutes

settings = Settings()
