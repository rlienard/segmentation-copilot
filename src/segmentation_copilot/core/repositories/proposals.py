"""Proposal repository — rule-change proposals and their audit trail.

The full state machine and notification side-effects live in
`core/services/proposal.py` (Phase 3). This module only handles persistence
and the optimistic-lock approve/reject SQL that prevents racing operators
from both winning a decision.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.domain import ACE, ProposalRecord, ProposalStatus, ProposalTrigger
from ..models.orm import Proposal, ProposalAudit


class ProposalConflictError(RuntimeError):
    """Raised when an optimistic-lock decision loses the race."""


class ProposalRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        *,
        tenant_id: str,
        trigger: ProposalTrigger,
        src_sgt: int,
        dst_sgt: int,
        proposed_aces: list[ACE],
        rationale: str,
        idempotency_key: str,
        expires_in: timedelta,
        run_id: int | None = None,
        trigger_ref: str | None = None,
        threat_context: dict[str, Any] | None = None,
    ) -> ProposalRecord:
        proposal = Proposal(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            run_id=run_id,
            trigger=trigger.value,
            trigger_ref=trigger_ref,
            src_sgt=src_sgt,
            dst_sgt=dst_sgt,
            proposed_aces=[ace.model_dump() for ace in proposed_aces],
            rationale=rationale,
            threat_context=threat_context,
            status=ProposalStatus.PENDING.value,
            expires_at=datetime.utcnow() + expires_in,
            idempotency_key=idempotency_key,
        )
        self.session.add(proposal)
        self.session.add(
            ProposalAudit(
                proposal_id=proposal.id,
                event="created",
                actor=None,
                payload={"trigger": trigger.value, "trigger_ref": trigger_ref},
            )
        )
        await self.session.flush()
        await self.session.refresh(proposal)
        return self._to_record(proposal)

    async def get_by_idempotency(
        self, *, tenant_id: str, idempotency_key: str
    ) -> ProposalRecord | None:
        stmt = select(Proposal).where(
            Proposal.tenant_id == tenant_id,
            Proposal.idempotency_key == idempotency_key,
        )
        result = await self.session.execute(stmt)
        row = result.scalars().first()
        return self._to_record(row) if row else None

    async def get(self, proposal_id: str) -> ProposalRecord | None:
        row = await self.session.get(Proposal, proposal_id)
        return self._to_record(row) if row else None

    async def list_pending_for_pair(
        self, *, tenant_id: str, src_sgt: int, dst_sgt: int
    ) -> list[ProposalRecord]:
        stmt = select(Proposal).where(
            Proposal.tenant_id == tenant_id,
            Proposal.src_sgt == src_sgt,
            Proposal.dst_sgt == dst_sgt,
            Proposal.status.in_([ProposalStatus.PENDING.value, ProposalStatus.NOTIFIED.value]),
        )
        result = await self.session.execute(stmt)
        return [self._to_record(p) for p in result.scalars().all()]

    async def list_for_tenant(
        self,
        *,
        tenant_id: str,
        status: ProposalStatus | None = None,
        limit: int = 100,
    ) -> list[ProposalRecord]:
        stmt = select(Proposal).where(Proposal.tenant_id == tenant_id)
        if status is not None:
            stmt = stmt.where(Proposal.status == status.value)
        stmt = stmt.order_by(Proposal.created_at.desc()).limit(limit)
        result = await self.session.execute(stmt)
        return [self._to_record(p) for p in result.scalars().all()]

    async def mark_notified(self, proposal_id: str) -> None:
        await self.session.execute(
            update(Proposal)
            .where(Proposal.id == proposal_id, Proposal.status == ProposalStatus.PENDING.value)
            .values(status=ProposalStatus.NOTIFIED.value, notified_at=datetime.utcnow())
        )
        self.session.add(
            ProposalAudit(proposal_id=proposal_id, event="notified", actor=None, payload=None)
        )

    async def replace_aces(
        self,
        *,
        proposal_id: str,
        new_aces: list[Any],
        appended_rationale: str | None = None,
        actor: str | None = None,
    ) -> ProposalRecord:
        """Update an existing pending proposal's ACEs (storm-collapse path).

        Idempotency key is intentionally NOT recalculated — collapsing must
        not change the natural identity of the proposal that operators are
        already looking at in WebEx.
        """
        proposal = await self.session.get(Proposal, proposal_id)
        if proposal is None:
            raise LookupError(f"proposal {proposal_id} not found")
        if proposal.status not in (ProposalStatus.PENDING.value, ProposalStatus.NOTIFIED.value):
            raise RuntimeError(
                f"can only replace ACEs on pending/notified proposals (got {proposal.status})"
            )
        proposal.proposed_aces = new_aces
        if appended_rationale:
            proposal.rationale = (proposal.rationale + "\n\n" + appended_rationale).strip()
        self.session.add(
            ProposalAudit(
                proposal_id=proposal_id,
                event="collapsed",
                actor=actor,
                payload={"new_ace_count": len(new_aces)},
            )
        )
        await self.session.flush()
        return self._to_record(proposal)

    async def mark_status(
        self,
        *,
        proposal_id: str,
        new_status: ProposalStatus,
        audit_event: str,
        actor: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> ProposalRecord:
        """Unconditional status transition for downstream states (applied/failed/expired).

        Use `decide()` for the optimistic-lock pending→approved/rejected hop.
        """
        proposal = await self.session.get(Proposal, proposal_id)
        if proposal is None:
            raise LookupError(f"proposal {proposal_id} not found")
        proposal.status = new_status.value
        self.session.add(
            ProposalAudit(
                proposal_id=proposal_id,
                event=audit_event,
                actor=actor,
                payload=payload,
            )
        )
        await self.session.flush()
        return self._to_record(proposal)

    async def expire_overdue(self, *, tenant_id: str, now: datetime | None = None) -> int:
        """Bulk transition pending/notified proposals past their expires_at."""
        now = now or datetime.utcnow()
        stmt = select(Proposal).where(
            Proposal.tenant_id == tenant_id,
            Proposal.expires_at < now,
            Proposal.status.in_([ProposalStatus.PENDING.value, ProposalStatus.NOTIFIED.value]),
        )
        rows = (await self.session.execute(stmt)).scalars().all()
        for p in rows:
            p.status = ProposalStatus.EXPIRED.value
            self.session.add(
                ProposalAudit(proposal_id=p.id, event="expired", actor=None, payload=None)
            )
        await self.session.flush()
        return len(rows)

    async def decide(
        self,
        *,
        proposal_id: str,
        decision: ProposalStatus,
        actor: str,
        channel: str,
    ) -> ProposalRecord:
        """Optimistic-lock decision. Raises ProposalConflictError if the
        proposal has already moved out of PENDING/NOTIFIED."""
        if decision not in (ProposalStatus.APPROVED, ProposalStatus.REJECTED):
            raise ValueError(f"invalid decision status: {decision}")

        result = await self.session.execute(
            update(Proposal)
            .where(
                Proposal.id == proposal_id,
                Proposal.status.in_(
                    [ProposalStatus.PENDING.value, ProposalStatus.NOTIFIED.value]
                ),
            )
            .values(
                status=decision.value,
                decided_at=datetime.utcnow(),
                decided_by=actor,
                decision_channel=channel,
            )
        )
        if result.rowcount == 0:
            raise ProposalConflictError(f"proposal {proposal_id} already decided or expired")
        self.session.add(
            ProposalAudit(
                proposal_id=proposal_id,
                event=decision.value,
                actor=actor,
                payload={"channel": channel},
            )
        )
        row = await self.session.get(Proposal, proposal_id)
        assert row is not None
        return self._to_record(row)

    @staticmethod
    def _to_record(p: Proposal) -> ProposalRecord:
        return ProposalRecord(
            id=p.id,
            tenant_id=p.tenant_id,
            run_id=p.run_id,
            trigger=ProposalTrigger(p.trigger),
            trigger_ref=p.trigger_ref,
            src_sgt=p.src_sgt,
            dst_sgt=p.dst_sgt,
            proposed_aces=[ACE(**ace) for ace in p.proposed_aces],
            rationale=p.rationale,
            threat_context=p.threat_context,
            status=ProposalStatus(p.status),
            created_at=p.created_at,
            notified_at=p.notified_at,
            decided_at=p.decided_at,
            decided_by=p.decided_by,
            decision_channel=p.decision_channel,
            expires_at=p.expires_at,
            idempotency_key=p.idempotency_key,
        )
