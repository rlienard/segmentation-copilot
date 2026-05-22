"""Redis Streams implementation of the EventBus protocol.

Idempotency dedup is a `SET key NX EX` on `scopilot:idem:<key>` —
publishes that lose the race return None without touching the stream.

Streams are capped with `MAXLEN ~` so a runaway producer can't blow up
Redis memory; tail consumers may miss events under sustained overload,
which is the same tradeoff Phase 4 makes everywhere for now.
"""

from __future__ import annotations

import json
from typing import Any

import redis.asyncio as redis

from .bus import EventEnvelope
from .streams import EVENT_TTL_SECONDS


class RedisStreamsBus:
    name = "redis"

    def __init__(self, client: redis.Redis, *, stream_max_len: int = 10_000) -> None:
        self._client = client
        self._max_len = stream_max_len

    @classmethod
    def from_url(cls, url: str, *, stream_max_len: int = 10_000) -> RedisStreamsBus:
        return cls(redis.from_url(url, decode_responses=True), stream_max_len=stream_max_len)

    # ------------------------------------------------------------------
    # Group bootstrap
    # ------------------------------------------------------------------

    async def ensure_group(self, *, stream: str, group: str) -> None:
        try:
            await self._client.xgroup_create(stream, group, id="$", mkstream=True)
        except redis.ResponseError as exc:
            # BUSYGROUP — already exists. Anything else is a real error.
            if "BUSYGROUP" not in str(exc):
                raise

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    async def publish(
        self,
        *,
        stream: str,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> str | None:
        if idempotency_key is not None:
            claimed = await self._client.set(
                f"scopilot:idem:{idempotency_key}", "1", nx=True, ex=EVENT_TTL_SECONDS
            )
            if not claimed:
                return None
        body = json.dumps(payload, default=str)
        return await self._client.xadd(
            stream,
            {"payload": body, "idem": idempotency_key or ""},
            maxlen=self._max_len,
            approximate=True,
        )

    # ------------------------------------------------------------------
    # Consume + ack
    # ------------------------------------------------------------------

    async def consume(
        self,
        *,
        stream: str,
        group: str,
        consumer: str,
        count: int = 10,
        block_ms: int = 1000,
    ) -> list[EventEnvelope]:
        response = await self._client.xreadgroup(
            groupname=group,
            consumername=consumer,
            streams={stream: ">"},
            count=count,
            block=block_ms,
        )
        if not response:
            return []
        out: list[EventEnvelope] = []
        for _stream_name, messages in response:
            for event_id, fields in messages:
                idem = fields.get("idem") or ""
                payload = json.loads(fields.get("payload") or "{}")
                out.append(
                    EventEnvelope(
                        stream=stream,
                        event_id=event_id,
                        idempotency_key=idem,
                        payload=payload,
                    )
                )
        return out

    async def ack(self, *, stream: str, group: str, event_ids: list[str]) -> None:
        if not event_ids:
            return
        await self._client.xack(stream, group, *event_ids)

    async def aclose(self) -> None:
        await self._client.aclose()
