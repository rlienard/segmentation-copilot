"""Proposal state-machine tests.

Cover the four invariants that Phase 3 relies on:

  1. **Idempotency** — submitting the same shape twice doesn't duplicate.
  2. **Storm collapse** — a different proposal for the same (src, dst)
     pair merges into the existing one instead of stacking.
  3. **Approve → matrix_version** — an approval creates a new immutable
     matrix version, parent-linked to the previous, and the proposal
     ends in APPLIED.
  4. **Expiry** — past-due pending/notified proposals bulk-transition to
     EXPIRED with audit rows.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from segmentation_copilot.core.models.domain import (
    ACE,
    ProposalStatus,
    ProposalTrigger,
)
from segmentation_copilot.core.repositories.matrix import MatrixVersionRepository
from segmentation_copilot.core.services.proposal import (
    ProposalService,
    idempotency_key,
)


TENANT = "test-tenant"


def _ace(port: str, action: str = "deny") -> ACE:
    return ACE(protocol="tcp", src_port="any", dst_port=port,
               action=action, source_category="harmful")


@pytest.mark.asyncio
async def test_propose_then_decide_creates_matrix_version(session):
    service = ProposalService(session)
    proposal, created = await service.propose(
        tenant_id=TENANT,
        trigger=ProposalTrigger.THREAT,
        src_sgt=100, dst_sgt=200,
        proposed_aces=[_ace("445", "deny")],
        rationale="SMB exposed",
    )
    assert created is True
    assert proposal.status is ProposalStatus.PENDING

    decided = await service.decide(
        proposal_id=proposal.id,
        decision=ProposalStatus.APPROVED,
        actor="alice@example.com",
        channel="api",
    )
    assert decided.status is ProposalStatus.APPLIED

    latest = await MatrixVersionRepository(session).latest_for_tenant(TENANT)
    assert latest is not None
    contracts = latest.contracts["contracts"]
    assert len(contracts) == 1
    assert contracts[0]["src_sgt"] == 100 and contracts[0]["dst_sgt"] == 200
    assert any(a["dst_port"] == "445" and a["action"] == "deny" for a in contracts[0]["aces"])


@pytest.mark.asyncio
async def test_idempotent_propose_returns_existing(session):
    service = ProposalService(session)
    aces = [_ace("445")]
    first, created_a = await service.propose(
        tenant_id=TENANT, trigger=ProposalTrigger.MANUAL,
        src_sgt=100, dst_sgt=200, proposed_aces=aces, rationale="r1",
    )
    second, created_b = await service.propose(
        tenant_id=TENANT, trigger=ProposalTrigger.MANUAL,
        src_sgt=100, dst_sgt=200, proposed_aces=aces, rationale="r2",
    )
    assert created_a is True
    assert created_b is False
    assert first.id == second.id


@pytest.mark.asyncio
async def test_storm_collapse_merges_aces(session):
    service = ProposalService(session)
    first, created_a = await service.propose(
        tenant_id=TENANT, trigger=ProposalTrigger.THREAT,
        src_sgt=100, dst_sgt=200,
        proposed_aces=[_ace("445", "deny")],
        rationale="SMB exposed",
    )
    second, created_b = await service.propose(
        tenant_id=TENANT, trigger=ProposalTrigger.THREAT,
        src_sgt=100, dst_sgt=200,
        proposed_aces=[_ace("3389", "deny")],
        rationale="RDP exposed",
    )
    assert created_a is True
    assert created_b is False
    assert first.id == second.id

    ports = sorted(a.dst_port for a in second.proposed_aces)
    assert ports == ["3389", "445"]
    assert "RDP exposed" in second.rationale


@pytest.mark.asyncio
async def test_collapse_conflicting_actions_resolve_to_deny(session):
    service = ProposalService(session)
    await service.propose(
        tenant_id=TENANT, trigger=ProposalTrigger.MANUAL,
        src_sgt=100, dst_sgt=200,
        proposed_aces=[_ace("443", "permit")],
        rationale="HTTPS",
    )
    merged, _ = await service.propose(
        tenant_id=TENANT, trigger=ProposalTrigger.THREAT,
        src_sgt=100, dst_sgt=200,
        proposed_aces=[_ace("443", "deny")],
        rationale="actually malicious",
    )
    matching = [a for a in merged.proposed_aces if a.dst_port == "443"]
    assert len(matching) == 1
    assert matching[0].action == "deny"


@pytest.mark.asyncio
async def test_rejection_does_not_touch_matrix(session):
    service = ProposalService(session)
    proposal, _ = await service.propose(
        tenant_id=TENANT, trigger=ProposalTrigger.MANUAL,
        src_sgt=100, dst_sgt=200,
        proposed_aces=[_ace("445")],
        rationale="r",
    )
    decided = await service.decide(
        proposal_id=proposal.id,
        decision=ProposalStatus.REJECTED,
        actor="bob",
        channel="api",
    )
    assert decided.status is ProposalStatus.REJECTED
    latest = await MatrixVersionRepository(session).latest_for_tenant(TENANT)
    assert latest is None


@pytest.mark.asyncio
async def test_expire_overdue(session):
    service = ProposalService(session)
    proposal, _ = await service.propose(
        tenant_id=TENANT, trigger=ProposalTrigger.MANUAL,
        src_sgt=100, dst_sgt=200,
        proposed_aces=[_ace("445")],
        rationale="r",
        expires_in=timedelta(minutes=1),
    )
    n = await service.expire_overdue(
        tenant_id=TENANT, now=datetime.utcnow() + timedelta(hours=1)
    )
    assert n == 1
    again = await service.proposals.get(proposal.id)
    assert again is not None and again.status is ProposalStatus.EXPIRED


@pytest.mark.asyncio
async def test_approval_chains_matrix_versions(session):
    service = ProposalService(session)
    p1, _ = await service.propose(
        tenant_id=TENANT, trigger=ProposalTrigger.MANUAL,
        src_sgt=100, dst_sgt=200,
        proposed_aces=[_ace("443", "permit")],
        rationale="HTTPS",
    )
    await service.decide(
        proposal_id=p1.id, decision=ProposalStatus.APPROVED,
        actor="alice", channel="api",
    )
    p2, _ = await service.propose(
        tenant_id=TENANT, trigger=ProposalTrigger.MANUAL,
        src_sgt=100, dst_sgt=300,
        proposed_aces=[_ace("53", "permit")],
        rationale="DNS",
    )
    await service.decide(
        proposal_id=p2.id, decision=ProposalStatus.APPROVED,
        actor="alice", channel="api",
    )
    matrix_repo = MatrixVersionRepository(session)
    latest = await matrix_repo.latest_for_tenant(TENANT)
    assert latest is not None
    assert latest.parent_id is not None
    parent = await matrix_repo.get(latest.parent_id)
    assert parent is not None and parent.parent_id is None
    assert len(latest.contracts["contracts"]) == 2


def test_idempotency_key_is_order_independent():
    a = [ACE(protocol="tcp", src_port="any", dst_port="443",
             action="permit", source_category=None),
         ACE(protocol="tcp", src_port="any", dst_port="80",
             action="permit", source_category=None)]
    k1 = idempotency_key(run_id=1, src_sgt=100, dst_sgt=200, aces=a)
    k2 = idempotency_key(run_id=1, src_sgt=100, dst_sgt=200, aces=list(reversed(a)))
    assert k1 == k2
