"""Cisco Talos — opt-in, best-effort.

Talos has **no free public API** for IP-reputation lookups. Their public
web page (`talosintelligence.com/sb_api/query_lookup`) is undocumented,
unstable, and likely violates their ToS for programmatic use.

This client is therefore:
  - **opt-in** via `SCOPILOT_THREAT__TALOS_ENABLED=true`
  - **best-effort**: the aggregator treats Talos failures as "no opinion",
    not as an error.
  - **not the primary signal**: keep AbuseIPDB / OTX / VirusTotal wired
    too. Talos is a corroborating vote at best.

Production deployments with a Cisco SecureX / Threat Response license
should replace this implementation with a real SecureX-API client.
"""

from __future__ import annotations

import httpx

from .base import ThreatVerdict

_URL = "https://talosintelligence.com/sb_api/query_lookup"


class TalosBestEffortClient:
    """Public-page reputation lookup. Brittle by design."""

    name = "talos"

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 4.0,
    ) -> None:
        self._timeout = timeout
        self._client = client
        self._owns_client = client is None

    def _ensure(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                headers={"User-Agent": "segmentation-copilot/0.2"},
            )
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def lookup_ip(self, ip: str) -> ThreatVerdict | None:
        params = {
            "query": ip,
            "query_entry": ip,
            "offset": "0",
            "order": "ip",
        }
        try:
            resp = await self._ensure().get(_URL, params=params)
        except httpx.RequestError:
            return None
        if resp.status_code != 200:
            return None
        try:
            body = resp.json()
        except ValueError:
            return None
        # The public endpoint returns a `reputation` label like
        # "Untrusted" / "Trusted" / "Neutral". Map to a coarse score.
        rep = (body.get("rep_score") or body.get("reputation") or "").lower()
        score = {
            "untrusted": 80,
            "poor": 80,
            "neutral": 30,
            "questionable": 50,
            "favorable": 5,
            "trusted": 0,
        }.get(rep, 0)
        categories: list[str] = []
        if score >= 50:
            categories.append("talos_untrusted")
        return ThreatVerdict(
            provider=self.name,
            target=ip,
            score=score,
            categories=categories,
            raw=body,
        )
