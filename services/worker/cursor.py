"""Per-tenant scan cursor.

Stores "what's the latest ingestion_ts I've already enqueued for analysis"
so the scheduler doesn't re-process the same flows on every tick. The
cursor lives in Redis with a long TTL (28d); if Redis loses it, the
worst outcome is re-classifying the last few days of flows — which is
absorbed by the 7d classification cache anyway.

In-memory fallback for tests and single-process dev.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

CURSOR_TTL_SECONDS = 28 * 24 * 3600
_KEY = "scopilot:scan:cursor:{tenant_id}"


class CursorStore(Protocol):
    async def get(self, tenant_id: str) -> datetime | None: ...

    async def set(self, tenant_id: str, value: datetime) -> None: ...


class MemoryCursorStore:
    def __init__(self) -> None:
        self._values: dict[str, datetime] = {}

    async def get(self, tenant_id: str) -> datetime | None:
        return self._values.get(tenant_id)

    async def set(self, tenant_id: str, value: datetime) -> None:
        self._values[tenant_id] = value


class RedisCursorStore:
    def __init__(self, redis_client) -> None:
        self._client = redis_client

    async def get(self, tenant_id: str) -> datetime | None:
        raw = await self._client.get(_KEY.format(tenant_id=tenant_id))
        if raw is None:
            return None
        return datetime.fromisoformat(raw)

    async def set(self, tenant_id: str, value: datetime) -> None:
        await self._client.set(
            _KEY.format(tenant_id=tenant_id),
            value.isoformat(),
            ex=CURSOR_TTL_SECONDS,
        )


def build_cursor_store(*, settings) -> CursorStore:
    url = settings.redis.url
    if not url or url.startswith("memory://"):
        return MemoryCursorStore()
    import redis.asyncio as redis  # noqa: PLC0415

    return RedisCursorStore(redis.from_url(url, decode_responses=True))
