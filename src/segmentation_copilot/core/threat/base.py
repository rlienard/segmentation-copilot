"""Threat-intel client protocol + verdict shape.

Providers normalise their native scoring into 0..100 so the aggregator
can apply a single threshold across heterogeneous sources. `categories`
is a free-form list of provider labels (e.g. `"c2"`, `"scanner"`,
`"malware"`); the aggregator's "two providers agree it's bad" rule
checks for set overlap, not exact string equality.

Returning `None` from `lookup_ip` means "no opinion" (404 / not in DB) —
NOT an error. Errors propagate as exceptions and the aggregator catches
them per-provider.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class ThreatVerdict:
    provider: str
    target: str
    """The IP / domain that was looked up."""
    score: int
    """Normalised 0–100. 0 = clean, 100 = confirmed malicious."""
    categories: list[str] = field(default_factory=list)
    raw: dict[str, Any] | None = None
    """Provider-native response for audit. Stored verbatim in
    `threat_lookups`."""
    fetched_at: datetime = field(default_factory=datetime.utcnow)


@runtime_checkable
class ThreatIntelClient(Protocol):
    name: str

    async def lookup_ip(self, ip: str) -> ThreatVerdict | None:
        """Return a verdict or None if the provider has no record.

        Implementations should raise on transport / auth / quota errors —
        the aggregator catches these and continues with whichever providers
        succeeded.
        """

    async def aclose(self) -> None: ...
