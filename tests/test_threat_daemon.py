"""Threat daemon end-to-end tests.

Drive the runner with an `InMemoryStreamingSource`, a fake aggregator
that returns canned verdicts, and the in-memory bus from Phase 4.
Confirms:

  1. Malicious destinations enqueue `events.flow.unknown` with
     `trigger="threat"` and the threat_context attached.
  2. Clean destinations don't enqueue anything.
  3. Heartbeat markers are surfaced via the progress hook but don't
     reach the parser.
  4. Duplicate hits to the same (5-tuple, dst_ip) are deduped by the
     bus's idempotency key.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest

from segmentation_copilot.core.events import (
    STREAM_FLOW_UNKNOWN,
    InMemoryBus,
)
from segmentation_copilot.core.threat.aggregator import ThreatDecision
from segmentation_copilot.core.threat.base import ThreatVerdict
from segmentation_copilot.sources.streaming import InMemoryStreamingSource
from segmentation_copilot.sources.streaming_ssh import HEARTBEAT_PREFIX
from services.threat_daemon.runner import run_daemon

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _malicious_line(dst_ip: str, dst_port: str = "4444") -> str:
    return (
        f"Jun 18 10:00:00: %RBM-6-SGACLHIT: ingress_interface='Gi1/0/1' "
        f"sgacl_name='unknown' action='Permit' protocol='tcp' "
        f"src-vrf='default' src-ip='10.0.0.10' src-port='44521' "
        f"dest-vrf='default' dest-ip='{dst_ip}' dest-port='{dst_port}' "
        f"sgt='100' dgt='999' logging_interval_hits='5'"
    )


class _FakeAggregator:
    """Returns malicious for any IP in `bad`, clean otherwise."""

    def __init__(self, bad: set[str]) -> None:
        self._bad = bad
        self.calls: list[str] = []

    async def lookup_ip(self, *, tenant_id: str, ip: str) -> ThreatDecision:
        self.calls.append(ip)
        is_bad = ip in self._bad
        return ThreatDecision(
            target=ip,
            is_malicious=is_bad,
            max_score=90 if is_bad else 5,
            triggering_providers=["fake"] if is_bad else [],
            verdicts=[
                ThreatVerdict(
                    provider="fake",
                    target=ip,
                    score=90 if is_bad else 5,
                    categories=["c2"] if is_bad else [],
                    raw=None,
                    fetched_at=datetime.utcnow(),
                ),
            ],
        )

    async def aclose(self) -> None: ...


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_daemon_enqueues_for_malicious_dst_ip():
    source = InMemoryStreamingSource()
    await source.feed(_malicious_line("185.243.115.84"))
    await source.feed(_malicious_line("8.8.8.8"))  # clean
    await source.close()

    aggregator = _FakeAggregator({"185.243.115.84"})
    bus = InMemoryBus()
    enqueued = await run_daemon(
        source=source, aggregator=aggregator, bus=bus, tenant_id="t",
    )
    assert enqueued == 1
    assert len(bus._streams[STREAM_FLOW_UNKNOWN]) == 1
    payload = bus._streams[STREAM_FLOW_UNKNOWN][0].payload
    assert payload["trigger"] == "threat"
    assert payload["trigger_ref"] == "185.243.115.84"
    assert payload["threat_context"]["decision"]["is_malicious"] is True
    assert "fake" in payload["threat_context"]["decision"]["triggering_providers"]


@pytest.mark.asyncio
async def test_daemon_clean_destinations_produce_nothing():
    source = InMemoryStreamingSource()
    await source.feed(_malicious_line("8.8.8.8"))
    await source.feed(_malicious_line("1.1.1.1"))
    await source.close()

    aggregator = _FakeAggregator(set())
    bus = InMemoryBus()
    enqueued = await run_daemon(
        source=source, aggregator=aggregator, bus=bus, tenant_id="t",
    )
    assert enqueued == 0
    assert STREAM_FLOW_UNKNOWN not in bus._streams or bus._streams[STREAM_FLOW_UNKNOWN] == []


@pytest.mark.asyncio
async def test_daemon_dedupes_repeat_hits_via_idempotency_key():
    source = InMemoryStreamingSource()
    bad = "185.243.115.84"
    await source.feed(_malicious_line(bad))
    await source.feed(_malicious_line(bad))  # same 5-tuple → dedup
    await source.feed(_malicious_line(bad))
    await source.close()

    aggregator = _FakeAggregator({bad})
    bus = InMemoryBus()
    enqueued = await run_daemon(
        source=source, aggregator=aggregator, bus=bus, tenant_id="t",
    )
    assert enqueued == 1
    assert len(bus._streams[STREAM_FLOW_UNKNOWN]) == 1


@pytest.mark.asyncio
async def test_daemon_passes_heartbeat_to_progress_hook():
    source = InMemoryStreamingSource()
    await source.feed(f"{HEARTBEAT_PREFIX} syslog.example.com")
    await source.feed("this line is not an sgaclhit and should be skipped")
    await source.close()

    seen: list[tuple[str, Any]] = []

    async def hook(event, ctx):
        seen.append((event, ctx))

    aggregator = _FakeAggregator(set())
    bus = InMemoryBus()
    await run_daemon(
        source=source, aggregator=aggregator, bus=bus, tenant_id="t",
        progress_hook=hook,
    )
    kinds = [k for k, _ in seen]
    assert "heartbeat" in kinds
    assert aggregator.calls == []  # heartbeat never reached the aggregator
