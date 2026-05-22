"""EventBus protocol + InMemoryBus + factory.

The Protocol covers Redis Streams semantics: consumer groups,
at-least-once delivery, explicit acks. The in-memory implementation is
contract-equivalent so tests don't need a real Redis. Production wires
the Redis implementation via `build_bus()`.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ...config import Settings, get_settings


@dataclass(frozen=True)
class EventEnvelope:
    """One delivered event."""

    stream: str
    event_id: str
    """Stream-assigned id. Pass back to `ack()` after the consumer has
    durably handled the event."""
    idempotency_key: str
    payload: dict[str, Any]


@runtime_checkable
class EventBus(Protocol):
    async def ensure_group(self, *, stream: str, group: str) -> None: ...

    async def publish(
        self,
        *,
        stream: str,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> str | None:
        """Append an event. Returns the event id, or None if the
        idempotency_key was already seen (dedup hit)."""

    async def consume(
        self,
        *,
        stream: str,
        group: str,
        consumer: str,
        count: int = 10,
        block_ms: int = 1000,
    ) -> list[EventEnvelope]: ...

    async def ack(self, *, stream: str, group: str, event_ids: list[str]) -> None: ...

    async def aclose(self) -> None: ...


# ---------------------------------------------------------------------------
# In-memory implementation — for tests + single-process dev runs
# ---------------------------------------------------------------------------


@dataclass
class _MemoryEvent:
    event_id: str
    idempotency_key: str
    payload: dict[str, Any]


@dataclass
class _MemoryGroupState:
    next_index: int = 0
    pending: set[str] = field(default_factory=set)


class InMemoryBus:
    """Single-process bus with the same contract as Redis Streams.

    Streams are append-only deques; each group keeps its own read cursor
    and a pending-ack set. Idempotency dedup is a process-wide set with
    no TTL — fine for tests.
    """

    name = "memory"

    def __init__(self) -> None:
        self._streams: dict[str, list[_MemoryEvent]] = defaultdict(list)
        self._groups: dict[tuple[str, str], _MemoryGroupState] = {}
        self._idempotency: set[str] = set()
        self._lock = asyncio.Lock()
        self._counter = 0

    async def ensure_group(self, *, stream: str, group: str) -> None:
        async with self._lock:
            self._streams.setdefault(stream, [])
            self._groups.setdefault((stream, group), _MemoryGroupState())

    async def publish(
        self,
        *,
        stream: str,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> str | None:
        key = idempotency_key or str(uuid.uuid4())
        async with self._lock:
            if key in self._idempotency:
                return None
            self._idempotency.add(key)
            self._counter += 1
            event_id = f"{int(time.time() * 1000)}-{self._counter}"
            self._streams[stream].append(
                _MemoryEvent(event_id=event_id, idempotency_key=key, payload=payload)
            )
            return event_id

    async def consume(
        self,
        *,
        stream: str,
        group: str,
        consumer: str,
        count: int = 10,
        block_ms: int = 1000,
    ) -> list[EventEnvelope]:
        # `consumer` is accepted for parity with Redis but isn't tracked
        # separately — one in-memory bus serves one process by design.
        del consumer
        deadline = time.monotonic() + (block_ms / 1000.0)
        while True:
            async with self._lock:
                events = self._streams.get(stream, [])
                state = self._groups.setdefault((stream, group), _MemoryGroupState())
                ready = events[state.next_index : state.next_index + count]
                if ready:
                    state.next_index += len(ready)
                    out = [
                        EventEnvelope(
                            stream=stream,
                            event_id=e.event_id,
                            idempotency_key=e.idempotency_key,
                            payload=e.payload,
                        )
                        for e in ready
                    ]
                    for e in out:
                        state.pending.add(e.event_id)
                    return out
            if time.monotonic() >= deadline:
                return []
            await asyncio.sleep(0.01)

    async def ack(self, *, stream: str, group: str, event_ids: list[str]) -> None:
        async with self._lock:
            state = self._groups.get((stream, group))
            if state is None:
                return
            for event_id in event_ids:
                state.pending.discard(event_id)

    async def aclose(self) -> None:
        return None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_bus(settings: Settings | None = None) -> EventBus:
    settings = settings or get_settings()
    url = settings.redis.url
    if not url or url.startswith("memory://"):
        return InMemoryBus()
    # Lazy import so the worker extra isn't required by every service.
    from .redis_bus import RedisStreamsBus  # noqa: PLC0415

    return RedisStreamsBus.from_url(url, stream_max_len=settings.redis.stream_max_len)
