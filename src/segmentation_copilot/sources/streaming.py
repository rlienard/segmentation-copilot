"""Streaming log sources — continuous tail for the threat daemon.

The Phase-1 `LogSource` is fetch-by-window — fine for the scheduler's
backlog scan but useless for real-time detection. `StreamingLogSource`
exposes `tail()` as an async iterator that yields raw lines as they
arrive, abstracting reconnects + log rotation from the daemon.

Two implementations:

  * `InMemoryStreamingSource` — for tests and for the local-file
    development workflow (pipe a file in via stdin or a queue).
  * `StreamingSSHSource` (`streaming_ssh.py`) — `asyncssh` based,
    `tail -F` with reconnect / backoff / cursor.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Protocol


class StreamingLogSource(Protocol):
    async def tail(self) -> AsyncIterator[str]: ...

    async def aclose(self) -> None: ...


class InMemoryStreamingSource:
    """Yields lines from an in-process queue.

    Lifecycle:
        src = InMemoryStreamingSource()
        await src.feed("line 1")
        await src.feed("line 2")
        await src.close()   # closes the iterator after draining

    `tail()` blocks until a line arrives or the source is closed; the
    iterator terminates on close.
    """

    _SENTINEL: object = object()

    def __init__(self) -> None:
        self._queue: asyncio.Queue[str | object] = asyncio.Queue()
        self._closed = False

    async def feed(self, line: str) -> None:
        if self._closed:
            return
        await self._queue.put(line)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._queue.put(self._SENTINEL)

    async def tail(self) -> AsyncIterator[str]:
        while True:
            item = await self._queue.get()
            if item is self._SENTINEL:
                return
            assert isinstance(item, str)
            yield item

    async def aclose(self) -> None:
        await self.close()
