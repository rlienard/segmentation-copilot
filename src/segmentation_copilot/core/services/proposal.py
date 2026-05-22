"""Proposal state machine.

Owns the full lifecycle:

    pending → notified → (approved | rejected | expired)
    approved → applied | failed

`propose()` is the single creation entry point. It enforces:

  * **Idempotency** — re-submitting the same `(run_id, src_sgt, dst_sgt,
    aces)` shape returns the existing row instead of creating a duplicate.
  * **Storm collapse** — a second proposal for the same `(src_sgt, dst_sgt)`
    with different ACEs merges into the existing pending one, so a
    misconfigured syslog source can't fire thousands of cards at the
    operators.

`decide()` is the single decision entry point and is the only path that
mutates the live matrix: an approval triggers `_apply_to_matrix()` which
folds the proposal's permitted/denied ACEs into a fresh `matrix_version`
(linked to its parent for cheap rollback) and marks the proposal APPLIED.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ...config import get_settings
from ..models.domain import (
    ACE,
    MatrixVersionRecord,
    ProposalRecord,
    ProposalStatus,
    ProposalTrigger,
)
from ..repositories.matrix import MatrixVersionRepository
from ..repositories.proposals import ProposalConflictError, ProposalRepository


class ProposalApplyError(RuntimeError):
    """Apply-to-matrix step failed after an APPROVED decision."""


def idempotency_key(
    *,
    run_id: int | None,
    src_sgt: int,
    dst_sgt: int,
    aces: Iterable[ACE],
) -> str:
    """Stable hash of the proposal's natural identity.

    Two proposals share a key iff they target the same (run, pair) and
    propose the same set of ACEs (order-independent).
    """
    payload = json.dumps(
        {
            "run_id": run_id,
            "src_sgt": src_sgt,
            "dst_sgt": dst_sgt,
            "aces": sorted(
                [a.model_dump() for a in aces],
                key=lambda a: json.dumps(a, sort_keys=True),
            ),
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _ace_key(ace: ACE | dict) -> tuple[str, str, str]:
    if isinstance(ace, ACE):
        return (ace.protocol, ace.src_port, ace.dst_port)
    return (ace["protocol"], ace["src_port"], ace["dst_port"])


def _merge_aces(existing: list[Any], incoming: Iterable[ACE]) -> list[dict]:
    """Merge new ACEs into the existing set; deny wins on conflict.

    Same least-privilege rule as `contracts.build_contracts`.
    """
    merged: dict[tuple[str, str, str], dict] = {}
    for ace in existing:
        merged[_ace_key(ace)] = dict(ace) if not isinstance(ace, dict) else ace
    for ace in incoming:
        key = _ace_key(ace)
        candidate = ace.model_dump()
        prior = merged.get(key)
        if prior and prior.get("action") != candidate.get("action"):
            candidate["action"] = "deny"
        merged[key] = candidate
    return list(merged.values())


class ProposalService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.proposals = ProposalRepository(session)
        self.matrix = MatrixVersionRepository(session)

    # ------------------------------------------------------------------
    # Create / collapse
    # ------------------------------------------------------------------

    async def propose(
        self,
        *,
        tenant_id: str,
        trigger: ProposalTrigger,
        src_sgt: int,
        dst_sgt: int,
        proposed_aces: list[ACE],
        rationale: str,
        run_id: int | None = None,
        trigger_ref: str | None = None,
        threat_context: dict[str, Any] | None = None,
        expires_in: timedelta | None = None,
        collapse: bool = True,
    ) -> tuple[ProposalRecord, bool]:
        """Create (or return / collapse into) a proposal.

        Returns `(proposal, created)` where `created` is True only when a
        brand-new row was inserted.
        """
        expires_in = expires_in or timedelta(
            hours=get_settings().webex.proposal_expiry_hours
        )
        idem = idempotency_key(
            run_id=run_id, src_sgt=src_sgt, dst_sgt=dst_sgt, aces=proposed_aces
        )

        # Exact-match idempotency: same shape → return existing.
        existing = await self.proposals.get_by_idempotency(
            tenant_id=tenant_id, idempotency_key=idem
        )
        if existing is not None:
            return existing, False

        # Storm collapse: any *other* pending/notified proposal for the same
        # (src, dst) pair gets the new ACEs merged in.
        if collapse:
            pending = await self.proposals.list_pending_for_pair(
                tenant_id=tenant_id, src_sgt=src_sgt, dst_sgt=dst_sgt
            )
            if pending:
                target = pending[0]
                merged = _merge_aces(
                    [a.model_dump() for a in target.proposed_aces], proposed_aces
                )
                updated = await self.proposals.replace_aces(
                    proposal_id=target.id,
                    new_aces=merged,
                    appended_rationale=f"[collapsed]: {rationale}",
                    actor=trigger_ref,
                )
                return updated, False

        proposal = await self.proposals.create(
            tenant_id=tenant_id,
            trigger=trigger,
            src_sgt=src_sgt,
            dst_sgt=dst_sgt,
            proposed_aces=proposed_aces,
            rationale=rationale,
            idempotency_key=idem,
            expires_in=expires_in,
            run_id=run_id,
            trigger_ref=trigger_ref,
            threat_context=threat_context,
        )
        return proposal, True

    # ------------------------------------------------------------------
    # Notify
    # ------------------------------------------------------------------

    async def mark_notified(self, proposal_id: str) -> None:
        await self.proposals.mark_notified(proposal_id)

    # ------------------------------------------------------------------
    # Decide + apply
    # ------------------------------------------------------------------

    async def decide(
        self,
        *,
        proposal_id: str,
        decision: ProposalStatus,
        actor: str,
        channel: str,
    ) -> ProposalRecord:
        """Approve or reject. On approve, fold the proposal into a fresh
        matrix_version and mark APPLIED. On apply failure, mark FAILED but
        re-raise so the caller knows to surface the error."""
        decided = await self.proposals.decide(
            proposal_id=proposal_id,
            decision=decision,
            actor=actor,
            channel=channel,
        )
        if decision is not ProposalStatus.APPROVED:
            return decided

        try:
            version = await self._apply_to_matrix(decided)
        except Exception as exc:
            await self.proposals.mark_status(
                proposal_id=proposal_id,
                new_status=ProposalStatus.FAILED,
                audit_event="apply_failed",
                actor=actor,
                payload={"error": str(exc)},
            )
            raise ProposalApplyError(str(exc)) from exc

        return await self.proposals.mark_status(
            proposal_id=proposal_id,
            new_status=ProposalStatus.APPLIED,
            audit_event="applied",
            actor=actor,
            payload={"matrix_version_id": version.id},
        )

    async def _apply_to_matrix(
        self, proposal: ProposalRecord
    ) -> MatrixVersionRecord:
        """Build a new matrix_version that folds the proposal in.

        Rollback is a pointer flip — the parent_id chain is preserved.
        """
        latest = await self.matrix.latest_for_tenant(proposal.tenant_id)
        parent_contracts: list[dict] = (
            list(latest.contracts.get("contracts", [])) if latest else []
        )

        by_pair: dict[tuple[int, int], dict] = {
            (c["src_sgt"], c["dst_sgt"]): {
                **c,
                "aces": list(c.get("aces", [])),
            }
            for c in parent_contracts
        }
        pair = (proposal.src_sgt, proposal.dst_sgt)
        contract = by_pair.get(pair) or {
            "src_sgt": proposal.src_sgt,
            "dst_sgt": proposal.dst_sgt,
            "aces": [],
        }
        contract["aces"] = _merge_aces(contract["aces"], proposal.proposed_aces)
        by_pair[pair] = contract

        snapshot = {"contracts": list(by_pair.values())}
        return await self.matrix.create(
            tenant_id=proposal.tenant_id,
            contracts=snapshot,
            parent_id=latest.id if latest else None,
            created_by=proposal.decided_by,
            note=f"approved proposal {proposal.id}",
        )

    # ------------------------------------------------------------------
    # Expire
    # ------------------------------------------------------------------

    async def expire_overdue(
        self, *, tenant_id: str, now: datetime | None = None
    ) -> int:
        return await self.proposals.expire_overdue(tenant_id=tenant_id, now=now)


__all__ = [
    "ProposalApplyError",
    "ProposalConflictError",
    "ProposalService",
    "idempotency_key",
]
