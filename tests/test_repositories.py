"""Repository-level tests against an in-memory SQLite.

These tests prove the async SQLAlchemy stack works end-to-end: schema
creation, tenant scoping, idempotent upserts, the proposal optimistic
lock, and the SGT dictionary cache.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from segmentation_copilot.aggregator import AggregatedFlow, FlowKey
from segmentation_copilot.core.models.domain import ACE, ProposalStatus, ProposalTrigger
from segmentation_copilot.core.repositories import (
    ClassificationRepository,
    ContractRepository,
    FlowEventRepository,
    MatrixVersionRepository,
    ProposalRepository,
    RunRepository,
    SGTRepository,
)
from segmentation_copilot.core.repositories.proposals import ProposalConflictError
from segmentation_copilot.parser import FlowEvent as ParsedFlowEvent

TENANT = "test-tenant"


def _make_event(sgt: int = 100, dgt: int = 200, port: str = "443") -> ParsedFlowEvent:
    return ParsedFlowEvent(
        ts=datetime(2026, 5, 1, 12, 0, 0),
        ingress_interface="GigabitEthernet1/0/1",
        sgacl_name="ACL_FROM_100",
        observed_action="permit",
        protocol="tcp",
        src_vrf="default",
        src_ip="10.0.0.10",
        src_port="55555",
        dst_vrf="default",
        dst_ip="10.0.1.10",
        dst_port=port,
        sgt=sgt,
        dgt=dgt,
        hits=5,
        raw="raw",
    )


def _make_flow(sgt: int = 100, dgt: int = 200, port: str = "443") -> AggregatedFlow:
    return AggregatedFlow(
        key=FlowKey(sgt=sgt, dgt=dgt, protocol="tcp", src_port="any", dst_port=port),
        total_hits=5,
    )


@pytest.mark.asyncio
async def test_run_create_get_list(session):
    runs = RunRepository(session)
    run = await runs.create(tenant_id=TENANT, source_type="local")
    assert run.id is not None
    assert run.tenant_id == TENANT
    assert run.status == "in_progress"

    fetched = await runs.get(run.id)
    assert fetched is not None and fetched.id == run.id

    listed = await runs.list_for_tenant(TENANT)
    assert len(listed) == 1


@pytest.mark.asyncio
async def test_flow_events_persist_and_distinct_sgts(session):
    runs = RunRepository(session)
    events = FlowEventRepository(session)
    run = await runs.create(tenant_id=TENANT, source_type="local")

    inserted = await events.bulk_insert(
        run_id=run.id,
        tenant_id=TENANT,
        events=[_make_event(100, 200), _make_event(100, 300), _make_event(400, 200)],
    )
    assert inserted == 3

    distinct = await events.distinct_sgt_dgt_for_run(run.id)
    assert distinct == [100, 200, 300, 400]


@pytest.mark.asyncio
async def test_classification_upsert_idempotent(session):
    runs = RunRepository(session)
    classifications = ClassificationRepository(session)
    run = await runs.create(tenant_id=TENANT, source_type="local")

    flow = _make_flow()
    first = await classifications.upsert_batch(
        run_id=run.id,
        tenant_id=TENANT,
        classified=[(flow, "business_relevant", "HTTPS to web tier")],
    )
    assert first == 1

    # Re-running the same classification is a no-op (the unique key absorbs it).
    second = await classifications.upsert_batch(
        run_id=run.id,
        tenant_id=TENANT,
        classified=[(flow, "default", "different rationale")],
    )
    assert second == 1
    counts = await classifications.counts_for_run(run.id)
    assert counts["business_relevant"] == 1
    assert counts["default"] == 0


@pytest.mark.asyncio
async def test_classification_recent_cache(session):
    runs = RunRepository(session)
    classifications = ClassificationRepository(session)
    run = await runs.create(tenant_id=TENANT, source_type="local")
    flow = _make_flow()
    await classifications.upsert_batch(
        run_id=run.id, tenant_id=TENANT,
        classified=[(flow, "business_relevant", "HTTPS")],
    )

    hit = await classifications.recent_for_flow(
        tenant_id=TENANT,
        sgt=100, dgt=200, protocol="tcp", src_port="any", dst_port="443",
        within=timedelta(days=7),
    )
    assert hit is not None and hit.category.value == "business_relevant"

    miss = await classifications.recent_for_flow(
        tenant_id="other-tenant",
        sgt=100, dgt=200, protocol="tcp", src_port="any", dst_port="443",
        within=timedelta(days=7),
    )
    assert miss is None


@pytest.mark.asyncio
async def test_sgt_repository_upsert_and_dictionary(session):
    sgt = SGTRepository(session)
    await sgt.upsert(tenant_id=TENANT, sgt_id=100, name="Employees")
    await sgt.upsert(tenant_id=TENANT, sgt_id=100, name="Employees_Renamed")
    await sgt.upsert(tenant_id=TENANT, sgt_id=200, name="Web")

    entries = await sgt.list_for_tenant(TENANT)
    assert len(entries) == 2
    assert {e.sgt_id: e.name for e in entries} == {100: "Employees_Renamed", 200: "Web"}

    d = await sgt.as_dictionary(TENANT)
    assert d.get_or_default(100) == "Employees_Renamed"

    missing = await sgt.missing_ids(tenant_id=TENANT, ids=[100, 200, 300])
    assert missing == [300]


@pytest.mark.asyncio
async def test_contracts_replace_for_run_is_idempotent(session):
    runs = RunRepository(session)
    contracts = ContractRepository(session)
    run = await runs.create(tenant_id=TENANT, source_type="local")
    payload = [
        {
            "src_sgt": 100, "dst_sgt": 200,
            "src_sgt_name": "Employees", "dst_sgt_name": "Web",
            "name": "Employees_to_Web",
            "aces": [
                {"protocol": "tcp", "src_port": "any", "dst_port": "443",
                 "action": "permit", "source_category": "business_relevant"},
            ],
        }
    ]
    await contracts.replace_for_run(run_id=run.id, tenant_id=TENANT, contracts=payload)
    await contracts.replace_for_run(run_id=run.id, tenant_id=TENANT, contracts=payload)
    records = await contracts.list_for_run(run.id)
    assert len(records) == 1
    assert records[0].name == "Employees_to_Web"
    assert records[0].aces[0].action == "permit"


@pytest.mark.asyncio
async def test_proposal_idempotency_and_optimistic_lock(session):
    proposals = ProposalRepository(session)
    aces = [ACE(protocol="tcp", src_port="any", dst_port="443", action="deny",
                source_category="harmful")]

    created = await proposals.create(
        tenant_id=TENANT,
        trigger=ProposalTrigger.THREAT,
        src_sgt=100, dst_sgt=200,
        proposed_aces=aces,
        rationale="dst IP flagged as C2",
        idempotency_key="abc123",
        expires_in=timedelta(hours=24),
    )
    assert created.status is ProposalStatus.PENDING

    existing = await proposals.get_by_idempotency(tenant_id=TENANT, idempotency_key="abc123")
    assert existing is not None and existing.id == created.id

    decided = await proposals.decide(
        proposal_id=created.id,
        decision=ProposalStatus.APPROVED,
        actor="alice@example.com",
        channel="webex",
    )
    assert decided.status is ProposalStatus.APPROVED

    with pytest.raises(ProposalConflictError):
        await proposals.decide(
            proposal_id=created.id,
            decision=ProposalStatus.REJECTED,
            actor="bob@example.com",
            channel="webex",
        )


@pytest.mark.asyncio
async def test_matrix_version_latest(session):
    matrix = MatrixVersionRepository(session)
    v1 = await matrix.create(tenant_id=TENANT, contracts={"contracts": []}, note="empty")
    v2 = await matrix.create(
        tenant_id=TENANT, contracts={"contracts": [{"src_sgt": 100, "dst_sgt": 200, "aces": []}]},
        parent_id=v1.id, note="first real version",
    )
    latest = await matrix.latest_for_tenant(TENANT)
    assert latest is not None and latest.id == v2.id
