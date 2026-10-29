import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, model_validator
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
    APP_ENV: str = "development"
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ]

    # Database
    DATABASE_URL: str = "sqlite:///./app.db"

    # Authentication & JWT
    JWT_SECRET: str = "abi-jwt-production-secret-investigation-2026-secure"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24

    # Initial Admin Seed Credentials
    ADMIN_EMAIL: Optional[str] = "admin@breach-investigation.local"
    ADMIN_PASSWORD: Optional[str] = "AdminSecurePassword2026!"

    # Email / SMTP Configuration (Gmail STARTTLS by default)
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_EMAIL: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_USER: Optional[str] = None
    SMTP_APP_PASSWORD: Optional[str] = None
    SMTP_FROM: Optional[str] = None

    @property
    def smtp_username(self) -> Optional[str]:
        return self.SMTP_EMAIL or self.SMTP_USER

    @property
    def smtp_pass(self) -> Optional[str]:
        return self.SMTP_PASSWORD or self.SMTP_APP_PASSWORD

    # Security & Policy Settings
    AUTH_LOGIN_RATE_LIMIT: int = 10
    MAX_FAILED_LOGINS: int = 10
    LOCKOUT_MINUTES: int = 15
    RATE_LIMIT_PER_MINUTE: int = 30

    # Optional third-party threat intelligence keys
    ABUSEIPDB_KEY: Optional[str] = None
    VIRUSTOTAL_KEY: Optional[str] = None
    GITHUB_TOKEN: Optional[str] = None

    @field_validator("ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "GITHUB_TOKEN", mode="before")
    @classmethod
    def parse_empty_strings(cls, v):
        if isinstance(v, str) and not v.strip():
            return None
        return v

    @model_validator(mode="after")
    def validate_jwt_secret_strength(self):
        secret = self.JWT_SECRET or ""
        weak_secrets = {"change-me", "secret", "your-jwt-secret", "default", "password", "admin", "12345678"}
        if len(secret.strip()) < 16 or secret.strip().lower() in weak_secrets:
            raise ValueError(
                "JWT_SECRET is missing or too weak (must be at least 16 characters and not a trivial default)."
            )
        return self

    # Safety limits
    REQUEST_TIMEOUT_SECONDS: float = 5.0
    PORT_CHECK_TIMEOUT_SECONDS: float = 2.0
    RATE_LIMIT_PER_MINUTE: int = 20
    AUTH_LOGIN_RATE_LIMIT: int = 5  # 5 per minute per IP
    REPO_RATE_LIMIT_PER_MINUTE: int = 5
    REPO_CLONE_TIMEOUT_SECONDS: float = 60.0
    REPO_OVERALL_TIMEOUT_SECONDS: float = 120.0
    REPO_MAX_FILES: int = 3000
    REPO_MAX_FILE_BYTES: int = 1024 * 1024  # 1 MB
    REPO_MAX_SIZE_KB: int = 100 * 1024  # 100 MB
    MAX_REDIRECT_HOPS: int = 8
    TOR_EXIT_CACHE_HOURS: int = 6

settings = Settings()
