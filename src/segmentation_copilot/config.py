"""Centralized configuration via Pydantic Settings.

Loads from environment variables and an optional `.env` file. Replaces the
scattered sidebar inputs and ad-hoc `os.environ` reads so every service
(api, worker, daemon, mcp-server, streamlit) consumes the same settings
surface.

Each subsection is a nested model so callers can pass `settings.db` /
`settings.redis` / `settings.anthropic` to the components that need them.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Async SQLAlchemy connection.

    Defaults to a local SQLite file so `pytest` and dev workflows work
    out of the box; production overrides via `SCOPILOT_DB__URL`.
    """

    url: str = "sqlite+aiosqlite:///data/segmentation.db"
    sync_url: str | None = None
    """Optional sync URL used by Alembic. Derived from `url` if unset."""
    echo: bool = False
    pool_size: int = 5
    max_overflow: int = 10

    model_config = SettingsConfigDict(env_prefix="SCOPILOT_DB__", extra="ignore")


class RedisSettings(BaseSettings):
    url: str = "redis://localhost:6379/0"
    stream_max_len: int = 10_000

    model_config = SettingsConfigDict(env_prefix="SCOPILOT_REDIS__", extra="ignore")


class AnthropicSettings(BaseSettings):
    api_key: str | None = None
    model: str = "claude-opus-4-7"
    max_tokens: int = 4096
    timeout_seconds: float = 60.0

    model_config = SettingsConfigDict(env_prefix="SCOPILOT_ANTHROPIC__", extra="ignore")


class ThreatIntelSettings(BaseSettings):
    abuseipdb_api_key: str | None = None
    otx_api_key: str | None = None
    virustotal_api_key: str | None = None
    talos_enabled: bool = False
    malicious_score_threshold: int = 50
    cache_ttl_clean_seconds: int = 6 * 3600
    cache_ttl_malicious_seconds: int = 24 * 3600
    cache_ttl_negative_seconds: int = 3600

    model_config = SettingsConfigDict(env_prefix="SCOPILOT_THREAT__", extra="ignore")


class SchedulerSettings(BaseSettings):
    scan_interval_minutes: int = 15
    classification_cache_days: int = 7
    flow_batch_size: int = 50
    daily_anthropic_spend_usd_cap: float = 50.0
    leader_lock_ttl_seconds: int = 30
    leader_refresh_seconds: int = 10

    model_config = SettingsConfigDict(env_prefix="SCOPILOT_SCHED__", extra="ignore")


class WebExSettings(BaseSettings):
    bot_access_token: str | None = None
    webhook_secret: str | None = None
    operators_room_id: str | None = None
    proposal_expiry_hours: int = 24

    model_config = SettingsConfigDict(env_prefix="SCOPILOT_WEBEX__", extra="ignore")


class ApiSettings(BaseSettings):
    """FastAPI service configuration.

    Auth is intentionally simple in Phase 2: a static set of bearer tokens
    read from `api_keys`. OIDC verification lands in Phase 6 hardening —
    when it does, the `require_auth` toggle stays, but tokens are validated
    against a JWKS instead of a static list.
    """

    host: str = "0.0.0.0"
    port: int = 8000
    base_url: str = "http://localhost:8000"
    require_auth: bool = True
    api_keys: list[str] = Field(default_factory=list)
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    model_config = SettingsConfigDict(env_prefix="SCOPILOT_API__", extra="ignore")


class Settings(BaseSettings):
    """Root settings object. Use `get_settings()` to obtain a cached instance."""

    environment: Literal["dev", "staging", "prod"] = "dev"
    log_level: str = "INFO"
    log_format: Literal["text", "json"] = "text"
    default_tenant_id: str = "default"

    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    anthropic: AnthropicSettings = Field(default_factory=AnthropicSettings)
    threat: ThreatIntelSettings = Field(default_factory=ThreatIntelSettings)
    scheduler: SchedulerSettings = Field(default_factory=SchedulerSettings)
    webex: WebExSettings = Field(default_factory=WebExSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)

    model_config = SettingsConfigDict(
        env_prefix="SCOPILOT_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def sync_database_url(self) -> str:
        """Sync URL used by Alembic migrations (which run sync engines)."""
        if self.db.sync_url:
            return self.db.sync_url
        url = self.db.url
        return (
            url.replace("+aiosqlite", "")
            .replace("+asyncpg", "+psycopg2")
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor. Tests can clear via `get_settings.cache_clear()`."""
    return Settings()
