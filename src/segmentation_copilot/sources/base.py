"""Abstract base class for log sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class LogSourceConfig:
    kind: str
    options: dict[str, Any]


class LogSource(ABC):
    """Fetch raw syslog lines for a given time window."""

    @abstractmethod
    def fetch(self, start: datetime, end: datetime) -> Iterator[str]:
        """Yield raw syslog lines whose timestamps fall within [start, end]."""

    @classmethod
    @abstractmethod
    def from_config(cls, config: LogSourceConfig) -> LogSource:
        ...
