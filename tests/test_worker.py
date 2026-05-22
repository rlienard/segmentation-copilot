"""Worker + scheduler integration tests.

Drive the full proactive-autonomy path with an in-memory bus and a
patched Claude classifier:

  1. Ingest a fixture log under a tenant (no baseline yet).
  2. Run a scan tick → uncovered flows fan out onto `events.flow.unknown`.
  3. Run the worker for one iteration → each event becomes a proposal.
  4. Approve one proposal → matrix_version appears → subsequent scan
     no longer treats that flow as uncovered.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from segmentation_copilot.config import get_settings
from segmentation_copilot.core import db as core_db
from segmentation_copilot.core.events import (
    STREAM_FLOW_UNKNOWN,
    InMemoryBus,
)
from segmentation_copilot.core.models.domain import ProposalStatus
from segmentation_copilot.core.repositories.proposals import ProposalRepository
from segmentation_copilot.core.repositories.sgt import SGTRepository
from segmentation_copilot.core.services.ingestion import IngestionService
from segmentation_copilot.core.services.proposal import ProposalService

from services.worker.cursor import MemoryCursorStore
from services.worker.scan import scan_tenant
from services.worker.worker import CONSUMER_GROUP_FLOW_UNKNOWN, run_worker


FIXTURE = Path(__file__).parent / "fixtures" / "sample.log"
TENANT = "test-tenant"


def _fake_classify(flows, sgt_dict, client=None, model=None):
    """Pretend everything but port 6881 (BitTorrent in the fixture) is fine."""
    out = []
    for f in flows:
        if f.key.dst_port == "6881":
            out.append((f, "business_irrelevant", "bittorrent"))
        elif f.key.dst_port == "4444":
            out.append((f, "harmful", "common C2 port"))
        else:
            out.append((f, "business_relevant", "ok"))
    return out


async def _seed_logs() -> None:
    """Ingest the bundled fixture under TENANT + load its SGT dictionary."""
    async with core_db.session_scope() as session:
        sgt = SGTRepository(session)
        for sid, name in [(100, "Employees"), (200, "Web"), (300, "Guests"),
                          (400, "DNS"), (999, "External")]:
            await sgt.upsert(tenant_id=TENANT, sgt_id=sid, name=name)
        ingestion = IngestionService(session)
        await ingestion.ingest_lines(
            tenant_id=TENANT, lines=FIXTURE.read_text().splitlines()
        )


@pytest.mark.asyncio
async def test_scan_enqueues_uncovered_flows():
    await core_db.create_all()
    await _seed_logs()

    bus = InMemoryBus()
    cursor = MemoryCursorStore()
    result = await scan_tenant(tenant_id=TENANT, bus=bus, cursor=cursor)

    assert result.scanned_events > 0
    assert result.aggregated_flows > 0
    # No baseline → every aggregated flow is uncovered.
    assert result.enqueued == result.aggregated_flows
    assert result.new_cursor is not None


@pytest.mark.asyncio
async def test_scan_is_idempotent_via_bus_dedup():
    await core_db.create_all()
    await _seed_logs()

    bus = InMemoryBus()
    cursor = MemoryCursorStore()
    first = await scan_tenant(tenant_id=TENANT, bus=bus, cursor=cursor)
    # Reset cursor so the second scan sees the same window.
    cursor._values.clear()
    second = await scan_tenant(tenant_id=TENANT, bus=bus, cursor=cursor)
    assert first.enqueued > 0
    assert second.enqueued == 0  # all idempotency keys collide


@pytest.mark.asyncio
async def test_worker_creates_proposals_for_each_uncovered_flow():
    await core_db.create_all()
    await _seed_logs()

    bus = InMemoryBus()
    cursor = MemoryCursorStore()
    scan_result = await scan_tenant(tenant_id=TENANT, bus=bus, cursor=cursor)
    assert scan_result.enqueued > 0

    settings = get_settings()
    with patch("services.worker.worker.classify_mod.classify_batch", side_effect=_fake_classify):
        await run_worker(
            bus=bus, settings=settings, consumer_name="test", max_iterations=1
        )

    async with core_db.session_scope() as session:
        proposals = await ProposalRepository(session).list_for_tenant(tenant_id=TENANT)
    # One proposal per unique (src, dst) pair — storm-collapse merges
    # multiple ACEs from the fixture's diverse port set into one card.
    pairs = {(p.src_sgt, p.dst_sgt) for p in proposals}
    assert len(proposals) == len(pairs)
    # The harmful + business_irrelevant ones must end up as deny.
    actions = {(p.src_sgt, p.dst_sgt): {a.action for a in p.proposed_aces} for p in proposals}
    assert "deny" in actions.get((300, 999), set())  # bittorrent flow
    assert "deny" in actions.get((100, 999), set())  # C2 port


@pytest.mark.asyncio
async def test_approved_proposal_changes_baseline_for_next_scan():
    await core_db.create_all()
    await _seed_logs()

    bus = InMemoryBus()
    cursor = MemoryCursorStore()
    await scan_tenant(tenant_id=TENANT, bus=bus, cursor=cursor)

    settings = get_settings()
    with patch("services.worker.worker.classify_mod.classify_batch", side_effect=_fake_classify):
        await run_worker(
            bus=bus, settings=settings, consumer_name="test", max_iterations=1
        )

    # Approve the proposal for the 100→200 HTTPS flow.
    async with core_db.session_scope() as session:
        proposals = await ProposalRepository(session).list_for_tenant(tenant_id=TENANT)
        web_pair = next(p for p in proposals if (p.src_sgt, p.dst_sgt) == (100, 200))
        await ProposalService(session).decide(
            proposal_id=web_pair.id,
            decision=ProposalStatus.APPROVED,
            actor="alice",
            channel="api",
        )

    # Re-scan with a fresh cursor — the 100→200 permit is now baseline, so
    # those flow tuples no longer fan out as "unknown".
    fresh_bus = InMemoryBus()
    fresh_cursor = MemoryCursorStore()
    result = await scan_tenant(tenant_id=TENANT, bus=fresh_bus, cursor=fresh_cursor)

    # Inspect the enqueued events directly via the in-memory bus internals.
    enqueued = fresh_bus._streams[STREAM_FLOW_UNKNOWN]
    enqueued_pairs = {(e.payload["src_sgt"], e.payload["dst_sgt"]) for e in enqueued}
    assert (100, 200) not in enqueued_pairs
    assert result.enqueued >= 1
