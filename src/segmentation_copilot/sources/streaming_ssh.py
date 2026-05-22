"""`asyncssh`-based streaming tail with reconnect + backoff.

Runs `tail -F -n 0 <log_path> | grep --line-buffered SGACLHIT` on the
remote syslog host, yielding matching lines as they arrive. `-F`
(capital) re-opens on inode change so log rotation is transparent.

On disconnect the source reconnects with exponential backoff + jitter
up to a configurable ceiling. A heartbeat marker is yielded every
`heartbeat_seconds` so the daemon can prove liveness on quiet links.

Cursor durability is the daemon's responsibility — this source reports
nothing across reconnects beyond "I reopened the tail at EOF".
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import AsyncIterator

log = logging.getLogger(__name__)


HEARTBEAT_PREFIX = "__scopilot_heartbeat__"


class StreamingSSHSource:
    name = "ssh-tail"

    def __init__(
        self,
        *,
        host: str,
        port: int = 22,
        username: str,
        password: str | None = None,
        key_filename: str | None = None,
        log_path: str = "/var/log/network/syslog",
        grep_pattern: str = "SGACLHIT",
        backoff_initial: float = 1.0,
        backoff_max: float = 60.0,
        heartbeat_seconds: float = 30.0,
        connect_timeout: float = 10.0,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._key_filename = key_filename
        self._log_path = log_path
        self._grep_pattern = grep_pattern
        self._backoff_initial = backoff_initial
        self._backoff_max = backoff_max
        self._heartbeat_seconds = heartbeat_seconds
        self._connect_timeout = connect_timeout
        self._stop = asyncio.Event()

    async def close(self) -> None:
        self._stop.set()

    async def aclose(self) -> None:
        await self.close()

    async def tail(self) -> AsyncIterator[str]:
        import asyncssh  # noqa: PLC0415

        backoff = self._backoff_initial
        while not self._stop.is_set():
            try:
                async with asyncssh.connect(
                    host=self._host,
                    port=self._port,
                    username=self._username,
                    password=self._password,
                    client_keys=[self._key_filename] if self._key_filename else None,
                    known_hosts=None,
                    connect_timeout=self._connect_timeout,
                ) as conn:
                    backoff = self._backoff_initial  # reset on successful connect
                    cmd = (
                        f"tail -F -n 0 {self._log_path} | "
                        f"grep --line-buffered {self._grep_pattern}"
                    )
                    async with conn.create_process(cmd, encoding="utf-8") as proc:
                        async for line in self._read_with_heartbeat(proc):
                            yield line
                            if self._stop.is_set():
                                return
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("ssh tail dropped — reconnecting in %.1fs", backoff)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=backoff)
                    return
                except TimeoutError:
                    pass
                jitter = random.uniform(0, backoff * 0.25)
                backoff = min(self._backoff_max, backoff * 2 + jitter)

    async def _read_with_heartbeat(self, proc) -> AsyncIterator[str]:
        """Yield each line, plus a heartbeat marker if the link is quiet."""
        while not self._stop.is_set():
            try:
                line = await asyncio.wait_for(
                    proc.stdout.readline(), timeout=self._heartbeat_seconds
                )
            except TimeoutError:
                yield f"{HEARTBEAT_PREFIX} {self._host}"
                continue
            if not line:
                # EOF — tail exited or the remote killed the pipe.
                return
            yield line.rstrip("\n")
