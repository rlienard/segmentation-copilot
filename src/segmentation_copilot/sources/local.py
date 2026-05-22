"""Local file or directory log source."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from ..parser import _parse_ts  # type: ignore[attr-defined]
from .base import LogSource, LogSourceConfig


class LocalFileSource(LogSource):
    def __init__(self, paths: list[Path]):
        self.paths = paths

    @classmethod
    def from_config(cls, config: LogSourceConfig) -> LocalFileSource:
        raw = config.options.get("path")
        if not raw:
            raise ValueError("LocalFileSource requires 'path' in options")
        root = Path(raw)
        if root.is_dir():
            paths = sorted(p for p in root.rglob("*") if p.is_file())
        else:
            paths = [root]
        return cls(paths)

    def fetch(self, start: datetime, end: datetime) -> Iterator[str]:
        for path in self.paths:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    ts = _parse_ts(line)
                    if ts is None:
                        # No timestamp on this line — yield it so the parser can decide.
                        yield line
                        continue
                    # Compare naive timestamps; syslog timestamps lack a year/tz so we
                    # normalise by replacing with start's year if missing.
                    if ts.year == 1900:
                        ts = ts.replace(year=start.year)
                    if start <= ts <= end:
                        yield line
