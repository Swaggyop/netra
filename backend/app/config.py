"""
NETRA — Application configuration.

All secrets are loaded from environment variables (never hardcoded).
Pydantic Settings validates types at startup and fails fast on missing values.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration — one source of truth for all settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────
    app_name: str = "netra"
    app_env: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"
    secret_key: SecretStr = Field(..., min_length=32)
    allowed_hosts: list[str] = ["localhost", "127.0.0.1"]

    # ── PostgreSQL ───────────────────────────────────────────
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "netra"
    postgres_user: str = "netra"
    postgres_password: SecretStr = Field(..., min_length=8)

    @property
    def database_url(self) -> str:
        """Async database URL for SQLAlchemy."""
        pwd = self.postgres_password.get_secret_value()
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{pwd}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def database_url_sync(self) -> str:
        """Sync database URL for Alembic migrations."""
        pwd = self.postgres_password.get_secret_value()
        return (
            f"postgresql+psycopg://{self.postgres_user}:{pwd}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # ── Neo4j ────────────────────────────────────────────────
    neo4j_uri: str = "bolt://neo4j:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: SecretStr = Field(..., min_length=8)

    # ── Redpanda / Kafka ─────────────────────────────────────
    redpanda_brokers: str = "redpanda:9092"
    event_bus: Literal["redpanda", "redis"] = "redpanda"

    # ── Redis ────────────────────────────────────────────────
    redis_url: str = "redis://redis:6379/0"
    celery_broker_url: str = "redis://redis:6379/1"
    celery_result_backend: str = "redis://redis:6379/2"

    # ── MinIO ────────────────────────────────────────────────
    minio_endpoint: str = "minio:9000"
    minio_access_key: str = "netra"
    minio_secret_key: SecretStr = Field(..., min_length=8)
    minio_bucket: str = "netra-snapshots"
    minio_secure: bool = False

    # ── Tor ──────────────────────────────────────────────────
    tor_socks_proxy: str = "socks5://tor:9050"

    # ── JWT (OWASP A07: Identification and Authentication) ───
    jwt_secret_key: SecretStr = Field(..., min_length=32)
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_minutes: int = 10080  # 7 days

    # ── Security (OWASP) ─────────────────────────────────────
    rate_limit_per_minute: int = 60
    rate_limit_burst: int = 20
    cors_origins: list[str] = ["http://localhost:5173"]
    bcrypt_rounds: int = 12
    max_request_size_mb: int = 10
    csrf_enabled: bool = True

    # ── Optional API keys ────────────────────────────────────
    shodan_api_key: str | None = None
    censys_api_id: str | None = None
    censys_api_secret: str | None = None
    etherscan_api_key: str | None = None
    trongrid_api_key: str | None = None
    otx_api_key: str | None = None

    # ── Live adapter API keys (Phase 1) ──────────────────────
    ransomware_live_api_key: str | None = None    # Free key from ransomware.live/my
    abuse_ch_auth_key: str | None = None           # Free key from auth.abuse.ch
    greynoise_api_key: str | None = None           # Free community tier
    hibp_api_key: str | None = None                # haveibeenpwned.com API key
    blockchair_api_key: str | None = None          # Free tier: 1440 req/day

    @field_validator("allowed_hosts", "cors_origins", mode="before")
    @classmethod
    def split_comma_list(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            return [h.strip() for h in v.split(",") if h.strip()]
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached singleton — call this everywhere instead of constructing Settings()."""
    return Settings()  # type: ignore[call-arg]
