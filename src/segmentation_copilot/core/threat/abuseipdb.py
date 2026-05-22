"""AbuseIPDB — primary IP-reputation provider.

Free tier: 1000 lookups/day, 1 req/s. The aggregator's caching layer
absorbs both limits in practice. API docs:
https://docs.abuseipdb.com/#check-endpoint

AbuseIPDB's `abuseConfidenceScore` is already 0..100, so the
normalisation is identity. Categories come from their `reports[].categories`
codes — we translate the most common ones into human labels because the
aggregator's "two providers agree" rule benefits from shared vocabulary.
"""

from __future__ import annotations

from typing import Any

import httpx

from .base import ThreatVerdict


_BASE_URL = "https://api.abuseipdb.com/api/v2"

# Category code → label mapping (top-level signals only; full list at
# https://www.abuseipdb.com/categories).
_CATEGORY_CODES: dict[int, str] = {
    3: "fraud_orders",
    4: "ddos",
    9: "open_proxy",
    10: "web_spam",
    11: "email_spam",
    14: "port_scan",
    15: "hacking",
    18: "brute_force",
    19: "bad_web_bot",
    20: "exploited_host",
    21: "web_app_attack",
    22: "ssh",
    23: "iot_targeted",
    14: "scanner",
}


def _categories_from_reports(reports: list[dict[str, Any]] | None) -> list[str]:
    if not reports:
        return []
    seen: set[str] = set()
    for r in reports:
        for code in r.get("categories") or []:
            label = _CATEGORY_CODES.get(int(code))
            if label:
                seen.add(label)
    return sorted(seen)


class AbuseIPDBClient:
    name = "abuseipdb"

    def __init__(
        self,
        *,
        api_key: str,
        client: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
        max_age_days: int = 90,
    ) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._max_age_days = max_age_days
        self._client = client
        self._owns_client = client is None

    def _ensure(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=_BASE_URL,
                headers={"Key": self._api_key, "Accept": "application/json"},
                timeout=self._timeout,
            )
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def lookup_ip(self, ip: str) -> ThreatVerdict | None:
        resp = await self._ensure().get(
            "/check",
            params={"ipAddress": ip, "maxAgeInDays": self._max_age_days, "verbose": ""},
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        body = resp.json()
        data = body.get("data") or {}
        score = int(data.get("abuseConfidenceScore") or 0)
        categories = _categories_from_reports(data.get("reports"))
        return ThreatVerdict(
            provider=self.name,
            target=ip,
            score=score,
            categories=categories,
            raw=body,
        )
