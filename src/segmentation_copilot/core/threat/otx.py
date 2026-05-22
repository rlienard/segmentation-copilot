"""AlienVault OTX — IP-reputation via pulse membership.

OTX returns "pulses" an IP appears in plus a passive-DNS history. We
score by pulse count (cap at 10 → 100/10 = 10× → clip to 100); 0 pulses
is a clean verdict, not a None. The category labels come from each
pulse's `tags` field (free-form), so we don't try to normalise — the
aggregator's threshold-vote handles the score signal, and downstream
display surfaces the raw categories.

API key: free at https://otx.alienvault.com/api
"""

from __future__ import annotations

import httpx

from .base import ThreatVerdict


_BASE_URL = "https://otx.alienvault.com/api/v1"


class OTXClient:
    name = "otx"

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
                headers={"X-OTX-API-KEY": self._api_key, "Accept": "application/json"},
                timeout=self._timeout,
            )
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def lookup_ip(self, ip: str) -> ThreatVerdict | None:
        resp = await self._ensure().get(f"/indicators/IPv4/{ip}/general")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        body = resp.json()
        pulse_info = body.get("pulse_info") or {}
        pulse_count = int(pulse_info.get("count") or 0)
        score = min(100, pulse_count * 10)
        categories: set[str] = set()
        for p in pulse_info.get("pulses") or []:
            for tag in p.get("tags") or []:
                categories.add(str(tag).lower())
        return ThreatVerdict(
            provider=self.name,
            target=ip,
            score=score,
            categories=sorted(categories)[:20],
            raw=body,
        )
