"""Redis-backed leader election.

Multiple scheduler replicas race to `SET key val NX EX ttl`. The winner
holds the lease for `ttl` seconds and renews every `refresh_seconds` by
re-running the same SET with the same value — only the current leader
extends the lease. Followers idle until the leader dies and the key
expires; one of them then wins the next round.

Falls back gracefully when no Redis URL is configured: the in-process
`MemoryLeader` is always the leader (single-process dev / tests).
"""

from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator, Protocol


class LeaderElector(Protocol):
    @property
    def is_leader(self) -> bool: ...

    async def start(self) -> None: ...
    async def stop(self) -> None: ...


class MemoryLeader:
    """Single-process leader — always wins."""

    name = "memory"

    @property
    def is_leader(self) -> bool:
        return True

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None


class RedisLeader:
    def __init__(
        self,
        *,
        redis_client,
        lock_key: str,
        ttl_seconds: int = 30,
        refresh_seconds: int = 10,
    ) -> None:
        self._client = redis_client
        self._key = lock_key
        self._ttl = ttl_seconds
        self._refresh = refresh_seconds
        self._token = str(uuid.uuid4())
        self._task: asyncio.Task | None = None
        self._is_leader = False
        self._stop = asyncio.Event()

    @property
    def is_leader(self) -> bool:
        return self._is_leader

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await asyncio.wait_for(self._task, timeout=5.0)
        # Release the lease if we hold it.
        try:
            current = await self._client.get(self._key)
            if current == self._token:
                await self._client.delete(self._key)
        except Exception:
            pass

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                claimed = await self._client.set(
                    self._key, self._token, nx=True, ex=self._ttl
                )
                if claimed:
                    self._is_leader = True
                else:
                    # If we already hold it, refresh; otherwise we're a follower.
                    current = await self._client.get(self._key)
                    if current == self._token:
                        await self._client.expire(self._key, self._ttl)
                        self._is_leader = True
                    else:
                        self._is_leader = False
            except Exception:
                self._is_leader = False
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._refresh)
            except asyncio.TimeoutError:
                pass


def build_leader(*, settings, lock_key: str = "scopilot:scheduler:leader") -> LeaderElector:
    url = settings.redis.url
    if not url or url.startswith("memory://"):
        return MemoryLeader()
    import redis.asyncio as redis  # noqa: PLC0415

    client = redis.from_url(url, decode_responses=True)
    return RedisLeader(
        redis_client=client,
        lock_key=lock_key,
        ttl_seconds=settings.scheduler.leader_lock_ttl_seconds,
        refresh_seconds=settings.scheduler.leader_refresh_seconds,
    )


@asynccontextmanager
async def leader_lifecycle(leader: LeaderElector) -> AsyncIterator[LeaderElector]:
    await leader.start()
    try:
        yield leader
    finally:
        await leader.stop()
