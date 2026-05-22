"""Threat-intel caching + persistence.

Two layers:

  * **Redis** — hot path. One key per (target, provider) holding the
    serialised verdict; TTL depends on the outcome (clean lives longer
    than 404, malicious lives longest).
  * **Postgres** (`threat_lookups`) — record-of-truth. Every verdict
    written, never expired. Used for audit + post-hoc analysis.

The cache also has an in-memory fallback so single-process tests / dev
don't need Redis.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from ...config import Settings, get_settings
from ..models.orm import ThreatLookup
from .base import ThreatVerdict

_CLEAN_VERDICT_SENTINEL = "<<clean>>"


class ThreatVerdictCache(Protocol):
    async def get(self, *, target: str, provider: str) -> ThreatVerdict | None | str: ...

    async def set(
        self,
        *,
        target: str,
        provider: str,
        verdict: ThreatVerdict | None,
        ttl_seconds: int,
    ) -> None: ...


class MemoryThreatCache:
    """Single-process cache for tests + dev.

    Stores `(value, expires_at)`; expired entries are treated as misses
    but not actively reaped — fine at test scale.
    """

    def __init__(self) -> None:
        self._values: dict[tuple[str, str], tuple[ThreatVerdict | None, datetime]] = {}

    async def get(self, *, target: str, provider: str) -> ThreatVerdict | None | str:
        entry = self._values.get((target, provider))
        if entry is None:
            return _MISS
        value, expires_at = entry
        if expires_at <= datetime.utcnow():
            return _MISS
        return value

    async def set(
        self,
        *,
        target: str,
        provider: str,
        verdict: ThreatVerdict | None,
        ttl_seconds: int,
    ) -> None:
        self._values[(target, provider)] = (
            verdict,
            datetime.utcnow() + timedelta(seconds=ttl_seconds),
        )


class RedisThreatCache:
    def __init__(self, client) -> None:
        self._client = client

    async def get(self, *, target: str, provider: str) -> ThreatVerdict | None | str:
        raw = await self._client.get(_key(target, provider))
        if raw is None:
            return _MISS
        if raw == _CLEAN_VERDICT_SENTINEL:
            return None
        payload = json.loads(raw)
        return ThreatVerdict(
            provider=payload["provider"],
            target=payload["target"],
            score=payload["score"],
            categories=payload["categories"],
            raw=payload.get("raw"),
            fetched_at=datetime.fromisoformat(payload["fetched_at"]),
        )

    async def set(
        self,
        *,
        target: str,
        provider: str,
        verdict: ThreatVerdict | None,
        ttl_seconds: int,
    ) -> None:
        key = _key(target, provider)
        if verdict is None:
            await self._client.set(key, _CLEAN_VERDICT_SENTINEL, ex=ttl_seconds)
            return
        payload = {
            "provider": verdict.provider,
            "target": verdict.target,
            "score": verdict.score,
            "categories": verdict.categories,
            "raw": verdict.raw,
            "fetched_at": verdict.fetched_at.isoformat(),
        }
        await self._client.set(key, json.dumps(payload), ex=ttl_seconds)


# Sentinel returned for cache miss (None already means "no opinion", we
# need a third state to distinguish "never looked up" from "looked up
# and provider returned no record").
class _MissType:
    __slots__ = ()


_MISS = _MissType()


def is_miss(value: object) -> bool:
    return isinstance(value, _MissType)


def _key(target: str, provider: str) -> str:
    return f"scopilot:threat:{provider}:{target}"


def build_cache(settings: Settings | None = None) -> ThreatVerdictCache:
    settings = settings or get_settings()
    url = settings.redis.url
    if not url or url.startswith("memory://"):
        return MemoryThreatCache()
    import redis.asyncio as redis  # noqa: PLC0415

    return RedisThreatCache(redis.from_url(url, decode_responses=True))


class ThreatLookupRepository:
    """Append-only record of every verdict we've seen.

    The aggregator writes here for audit; the API surfaces it via a future
    `/v1/threat-lookups` endpoint (Phase 6). Never deletes — retention
    policy lives in operations.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record(self, *, tenant_id: str, verdict: ThreatVerdict) -> None:
        self.session.add(
            ThreatLookup(
                tenant_id=tenant_id,
                target=verdict.target,
                provider=verdict.provider,
                score=verdict.score,
                categories=list(verdict.categories),
                raw=verdict.raw,
                fetched_at=verdict.fetched_at,
            )
        )
        await self.session.flush()
