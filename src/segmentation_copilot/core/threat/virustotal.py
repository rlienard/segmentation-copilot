"""VirusTotal — IP address report.

Free tier is **4 requests / minute**. The aggregator's per-call timeout
+ Redis caching keep production within the limit for sane flow rates;
if you blow through it, this client is the right one to disable first
(it's the slowest of the four).

API v3 returns `last_analysis_stats` with `malicious` / `suspicious` /
`harmless` / `undetected` counts. We score as
`(malicious + 0.5 * suspicious) * 100 / total_engines` so a single
detection on a 70-engine scan is ~1.4, while broad consensus is 100.

API key: https://www.virustotal.com/
"""

from __future__ import annotations

import httpx

from .base import ThreatVerdict

_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    name = "virustotal"

    def __init__(
        self,
        *,
        api_key: str,
        client: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._client = client
        self._owns_client = client is None

    def _ensure(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=_BASE_URL,
                headers={"x-apikey": self._api_key, "Accept": "application/json"},
                timeout=self._timeout,
            )
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def lookup_ip(self, ip: str) -> ThreatVerdict | None:
        resp = await self._ensure().get(f"/ip_addresses/{ip}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        body = resp.json()
        attrs = (body.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        total = sum(int(v or 0) for v in stats.values()) or 1
        score = min(100, int(((malicious + 0.5 * suspicious) * 100) / total))
        categories: set[str] = set()
        for result in (attrs.get("last_analysis_results") or {}).values():
            cat = result.get("category")
            if cat in ("malicious", "suspicious"):
                categories.add(cat)
        return ThreatVerdict(
            provider=self.name,
            target=ip,
            score=score,
            categories=sorted(categories),
            raw=body,
        )
