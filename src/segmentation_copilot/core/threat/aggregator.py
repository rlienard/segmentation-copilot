"""Multi-provider verdict aggregation + decision policy.

`ThreatAggregator.lookup_ip()` is the only thing the daemon calls; it
hides all the cache + parallel-lookup + decision-policy complexity.

Decision policy (`is_malicious`):

  * Any provider with `score >= malicious_threshold` → malicious.
  * Or any two providers agreeing on a malicious category → malicious.
  * Otherwise clean.

Per-provider failures (exceptions, timeouts) are absorbed silently and
attributed to that provider only — a single broken API key can't take
down the whole signal.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from ...config import Settings, get_settings
from .base import ThreatIntelClient, ThreatVerdict
from .cache import ThreatLookupRepository, ThreatVerdictCache, build_cache, is_miss


log = logging.getLogger(__name__)


_MALICIOUS_CATEGORIES: frozenset[str] = frozenset(
    {
        "c2",
        "command_and_control",
        "malware",
        "phishing",
        "scanner",
        "brute_force",
        "ddos",
        "exploit",
        "exploited_host",
        "hacking",
        "web_app_attack",
        "port_scan",
        "ssh",
        "talos_untrusted",
    }
)


@dataclass(frozen=True)
class ThreatDecision:
    target: str
    is_malicious: bool
    max_score: int
    triggering_providers: list[str]
    verdicts: list[ThreatVerdict]


class ThreatAggregator:
    def __init__(
        self,
        *,
        clients: Iterable[ThreatIntelClient],
        cache: ThreatVerdictCache | None = None,
        repository_factory=None,
        settings: Settings | None = None,
        per_call_timeout: float = 2.0,
    ) -> None:
        self._clients = list(clients)
        self._settings = settings or get_settings()
        self._cache = cache or build_cache(self._settings)
        # Lazy session-scoped repo factory; lets the aggregator be reused
        # across requests without holding an open session.
        self._repository_factory = repository_factory
        self._per_call_timeout = per_call_timeout

    @property
    def providers(self) -> list[str]:
        return [c.name for c in self._clients]

    async def lookup_ip(self, *, tenant_id: str, ip: str) -> ThreatDecision:
        verdicts: list[ThreatVerdict] = []
        to_fetch: list[ThreatIntelClient] = []

        for client in self._clients:
            cached = await self._cache.get(target=ip, provider=client.name)
            if not is_miss(cached):
                if cached is not None:
                    verdicts.append(cached)  # type: ignore[arg-type]
                continue
            to_fetch.append(client)

        if to_fetch:
            fresh = await asyncio.gather(
                *(self._fetch_one(client, ip) for client in to_fetch),
                return_exceptions=False,
            )
            for verdict in fresh:
                if verdict is not None:
                    verdicts.append(verdict)

        # Audit-persist every fresh verdict.
        if verdicts and self._repository_factory is not None:
            for verdict in verdicts:
                try:
                    async with self._repository_factory() as session:
                        await ThreatLookupRepository(session).record(
                            tenant_id=tenant_id, verdict=verdict
                        )
                except Exception:
                    log.exception("threat_lookup persist failed provider=%s target=%s",
                                  verdict.provider, ip)

        return self._decide(ip, verdicts)

    async def aclose(self) -> None:
        for client in self._clients:
            try:
                await client.aclose()
            except Exception:
                log.exception("aclose failed provider=%s", client.name)

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    async def _fetch_one(
        self, client: ThreatIntelClient, ip: str
    ) -> ThreatVerdict | None:
        try:
            verdict = await asyncio.wait_for(
                client.lookup_ip(ip), timeout=self._per_call_timeout
            )
        except asyncio.TimeoutError:
            log.warning("threat lookup timed out provider=%s ip=%s", client.name, ip)
            return None
        except Exception:
            log.exception("threat lookup raised provider=%s ip=%s", client.name, ip)
            return None

        ttl = self._ttl_for(verdict)
        try:
            await self._cache.set(
                target=ip, provider=client.name, verdict=verdict, ttl_seconds=ttl
            )
        except Exception:
            log.exception("threat cache set failed provider=%s ip=%s", client.name, ip)
        return verdict

    def _ttl_for(self, verdict: ThreatVerdict | None) -> int:
        threat_cfg = self._settings.threat
        if verdict is None:
            return threat_cfg.cache_ttl_negative_seconds
        if verdict.score >= threat_cfg.malicious_score_threshold:
            return threat_cfg.cache_ttl_malicious_seconds
        return threat_cfg.cache_ttl_clean_seconds

    def _decide(self, target: str, verdicts: list[ThreatVerdict]) -> ThreatDecision:
        threshold = self._settings.threat.malicious_score_threshold
        triggering: list[str] = []
        max_score = 0
        for v in verdicts:
            max_score = max(max_score, v.score)
            if v.score >= threshold:
                triggering.append(v.provider)

        if not triggering:
            # Category-consensus fallback: two providers naming the same
            # malicious category.
            category_to_providers: dict[str, list[str]] = {}
            for v in verdicts:
                for cat in v.categories:
                    if cat in _MALICIOUS_CATEGORIES:
                        category_to_providers.setdefault(cat, []).append(v.provider)
            for providers in category_to_providers.values():
                if len(set(providers)) >= 2:
                    triggering = sorted(set(providers))
                    break

        return ThreatDecision(
            target=target,
            is_malicious=bool(triggering),
            max_score=max_score,
            triggering_providers=triggering,
            verdicts=verdicts,
        )


def build_default_aggregator(
    settings: Settings | None = None,
    *,
    repository_factory=None,
) -> ThreatAggregator | None:
    """Build a ThreatAggregator from settings, or None if no provider is configured."""
    settings = settings or get_settings()
    clients: list[ThreatIntelClient] = []

    if settings.threat.abuseipdb_api_key:
        from .abuseipdb import AbuseIPDBClient  # noqa: PLC0415

        clients.append(AbuseIPDBClient(api_key=settings.threat.abuseipdb_api_key))
    if settings.threat.otx_api_key:
        from .otx import OTXClient  # noqa: PLC0415

        clients.append(OTXClient(api_key=settings.threat.otx_api_key))
    if settings.threat.virustotal_api_key:
        from .virustotal import VirusTotalClient  # noqa: PLC0415

        clients.append(VirusTotalClient(api_key=settings.threat.virustotal_api_key))
    if settings.threat.talos_enabled:
        from .talos import TalosBestEffortClient  # noqa: PLC0415

        clients.append(TalosBestEffortClient())

    if not clients:
        return None
    return ThreatAggregator(
        clients=clients,
        settings=settings,
        repository_factory=repository_factory,
    )
