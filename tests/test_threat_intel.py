"""Threat-intel layer tests.

Pin the four invariants Phase 5 relies on:
  1. Per-provider failures don't poison the aggregate decision.
  2. Score threshold OR two-provider category consensus → malicious.
  3. Cache short-circuits provider calls.
  4. AbuseIPDB / OTX / VirusTotal clients translate their native shape
     into a `ThreatVerdict` correctly (mocked HTTP).
"""

from __future__ import annotations

import asyncio
from datetime import datetime

import httpx
import pytest

from segmentation_copilot.config import get_settings
from segmentation_copilot.core.threat.abuseipdb import AbuseIPDBClient
from segmentation_copilot.core.threat.aggregator import ThreatAggregator
from segmentation_copilot.core.threat.base import ThreatVerdict
from segmentation_copilot.core.threat.cache import MemoryThreatCache
from segmentation_copilot.core.threat.otx import OTXClient
from segmentation_copilot.core.threat.virustotal import VirusTotalClient

# ---------------------------------------------------------------------------
# Fake providers
# ---------------------------------------------------------------------------


class _FakeProvider:
    def __init__(self, name: str, verdict: ThreatVerdict | None | Exception = None,
                 delay: float = 0.0) -> None:
        self.name = name
        self._verdict = verdict
        self._delay = delay
        self.calls = 0

    async def lookup_ip(self, ip: str) -> ThreatVerdict | None:
        self.calls += 1
        if self._delay:
            await asyncio.sleep(self._delay)
        if isinstance(self._verdict, Exception):
            raise self._verdict
        return self._verdict

    async def aclose(self) -> None: ...


def _verdict(provider: str, ip: str, *, score: int, categories: list[str] | None = None
             ) -> ThreatVerdict:
    return ThreatVerdict(
        provider=provider, target=ip, score=score,
        categories=categories or [], raw=None, fetched_at=datetime.utcnow(),
    )


# ---------------------------------------------------------------------------
# Aggregator policy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aggregator_marks_malicious_above_threshold():
    ip = "1.2.3.4"
    agg = ThreatAggregator(
        clients=[
            _FakeProvider("abuse", _verdict("abuse", ip, score=85, categories=["scanner"])),
            _FakeProvider("otx", _verdict("otx", ip, score=10)),
        ],
        cache=MemoryThreatCache(),
        settings=get_settings(),
    )
    decision = await agg.lookup_ip(tenant_id="t", ip=ip)
    assert decision.is_malicious is True
    assert decision.max_score == 85
    assert "abuse" in decision.triggering_providers


@pytest.mark.asyncio
async def test_aggregator_two_provider_category_consensus_is_malicious():
    ip = "5.6.7.8"
    agg = ThreatAggregator(
        clients=[
            _FakeProvider("abuse", _verdict("abuse", ip, score=20, categories=["scanner"])),
            _FakeProvider("otx", _verdict("otx", ip, score=20, categories=["scanner"])),
        ],
        cache=MemoryThreatCache(),
        settings=get_settings(),
    )
    decision = await agg.lookup_ip(tenant_id="t", ip=ip)
    assert decision.is_malicious is True
    assert set(decision.triggering_providers) == {"abuse", "otx"}


@pytest.mark.asyncio
async def test_aggregator_swallows_per_provider_failures():
    ip = "9.9.9.9"
    healthy = _FakeProvider("ok", _verdict("ok", ip, score=90))
    sick = _FakeProvider("broken", RuntimeError("auth"))
    agg = ThreatAggregator(
        clients=[healthy, sick],
        cache=MemoryThreatCache(),
        settings=get_settings(),
    )
    decision = await agg.lookup_ip(tenant_id="t", ip=ip)
    assert decision.is_malicious is True
    assert healthy.calls == 1
    assert sick.calls == 1


@pytest.mark.asyncio
async def test_aggregator_clean_when_no_provider_triggers():
    ip = "8.8.8.8"
    agg = ThreatAggregator(
        clients=[
            _FakeProvider("abuse", _verdict("abuse", ip, score=5)),
            _FakeProvider("otx", _verdict("otx", ip, score=0)),
        ],
        cache=MemoryThreatCache(),
        settings=get_settings(),
    )
    decision = await agg.lookup_ip(tenant_id="t", ip=ip)
    assert decision.is_malicious is False
    assert decision.triggering_providers == []


@pytest.mark.asyncio
async def test_aggregator_uses_cache_on_repeat_lookup():
    ip = "1.1.1.1"
    provider = _FakeProvider("abuse", _verdict("abuse", ip, score=90))
    cache = MemoryThreatCache()
    agg = ThreatAggregator(
        clients=[provider], cache=cache, settings=get_settings(),
    )
    await agg.lookup_ip(tenant_id="t", ip=ip)
    await agg.lookup_ip(tenant_id="t", ip=ip)
    assert provider.calls == 1  # second hit served from cache


@pytest.mark.asyncio
async def test_aggregator_per_call_timeout_does_not_fail_whole_lookup():
    ip = "2.2.2.2"
    slow = _FakeProvider("slow", _verdict("slow", ip, score=99), delay=0.5)
    fast = _FakeProvider("fast", _verdict("fast", ip, score=90))
    agg = ThreatAggregator(
        clients=[slow, fast], cache=MemoryThreatCache(),
        settings=get_settings(), per_call_timeout=0.05,
    )
    decision = await agg.lookup_ip(tenant_id="t", ip=ip)
    assert decision.is_malicious is True
    # The fast provider's verdict survives even though `slow` timed out.
    assert "fast" in decision.triggering_providers


# ---------------------------------------------------------------------------
# Provider client translation (mocked HTTP)
# ---------------------------------------------------------------------------


def _mock_client(handler, base_url: str):
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport, base_url=base_url)


@pytest.mark.asyncio
async def test_abuseipdb_client_translates_response():
    def handler(request: httpx.Request) -> httpx.Response:
        assert "/check" in str(request.url)
        return httpx.Response(
            200,
            json={
                "data": {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 85,
                    "reports": [{"categories": [14, 18]}],
                }
            },
        )

    async with _mock_client(handler, "https://api.abuseipdb.com/api/v2") as http:
        client = AbuseIPDBClient(api_key="x", client=http)
        verdict = await client.lookup_ip("1.2.3.4")
    assert verdict is not None
    assert verdict.score == 85
    assert "scanner" in verdict.categories
    assert "brute_force" in verdict.categories


@pytest.mark.asyncio
async def test_abuseipdb_returns_none_on_404():
    async with _mock_client(
        lambda r: httpx.Response(404), "https://api.abuseipdb.com/api/v2",
    ) as http:
        client = AbuseIPDBClient(api_key="x", client=http)
        verdict = await client.lookup_ip("1.2.3.4")
    assert verdict is None


@pytest.mark.asyncio
async def test_otx_scores_by_pulse_count():
    def handler(_request):
        return httpx.Response(
            200,
            json={"pulse_info": {"count": 4, "pulses": [{"tags": ["c2"]}]}},
        )

    async with _mock_client(handler, "https://otx.alienvault.com/api/v1") as http:
        client = OTXClient(api_key="x", client=http)
        verdict = await client.lookup_ip("1.2.3.4")
    assert verdict is not None
    assert verdict.score == 40
    assert "c2" in verdict.categories


@pytest.mark.asyncio
async def test_virustotal_normalises_engine_stats():
    def handler(_request):
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 5,
                            "suspicious": 2,
                            "harmless": 30,
                            "undetected": 13,
                            "timeout": 0,
                        },
                        "last_analysis_results": {
                            "engineA": {"category": "malicious"},
                            "engineB": {"category": "harmless"},
                        },
                    }
                }
            },
        )

    async with _mock_client(handler, "https://www.virustotal.com/api/v3") as http:
        client = VirusTotalClient(api_key="x", client=http)
        verdict = await client.lookup_ip("1.2.3.4")
    assert verdict is not None
    # 5 malicious + 0.5 * 2 suspicious = 6 / 50 = 12%
    assert verdict.score == 12
    assert "malicious" in verdict.categories
