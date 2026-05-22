"""Proposals router — list, create (manual), approve, reject.

The full state machine (notify → decide → apply matrix) lands in Phase 3
along with the WebEx bot; this router exposes the persistence surface so
the bot, CLI, and Streamlit can all manage proposals through one HTTP API.
"""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from segmentation_copilot.core.models.domain import ProposalStatus, ProposalTrigger
from segmentation_copilot.core.repositories.proposals import (
    ProposalConflictError,
    ProposalRepository,
)

from ..auth import AuthContext
from ..deps import get_auth_context, get_session
from ..schemas import (
    ProposalCreateRequest,
    ProposalDecideRequest,
    ProposalResponse,
    ProposalsListResponse,
)

router = APIRouter(prefix="/v1/proposals", tags=["proposals"])


def _idempotency_key(*, run_id: int | None, src_sgt: int, dst_sgt: int, aces: list) -> str:
    payload = json.dumps(
        {"run_id": run_id, "src_sgt": src_sgt, "dst_sgt": dst_sgt,
         "aces": sorted([a.model_dump() for a in aces], key=lambda a: json.dumps(a, sort_keys=True))},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@router.get("", response_model=ProposalsListResponse)
async def list_proposals(
    status: ProposalStatus | None = None,
    limit: int = 100,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> ProposalsListResponse:
    proposals = await ProposalRepository(session).list_for_tenant(
        tenant_id=ctx.tenant_id, status=status, limit=limit
    )
    return ProposalsListResponse(proposals=proposals)


@router.post("", response_model=ProposalResponse, status_code=201)
async def create_proposal(
    body: ProposalCreateRequest,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> ProposalResponse:
    repo = ProposalRepository(session)
    idem = _idempotency_key(
        run_id=body.run_id, src_sgt=body.src_sgt, dst_sgt=body.dst_sgt, aces=body.proposed_aces
    )
    existing = await repo.get_by_idempotency(tenant_id=ctx.tenant_id, idempotency_key=idem)
    if existing is not None:
        return ProposalResponse(proposal=existing)
    proposal = await repo.create(
        tenant_id=ctx.tenant_id,
        trigger=ProposalTrigger(body.trigger),
        src_sgt=body.src_sgt,
        dst_sgt=body.dst_sgt,
        proposed_aces=body.proposed_aces,
        rationale=body.rationale,
        idempotency_key=idem,
        expires_in=timedelta(hours=body.expires_in_hours),
        run_id=body.run_id,
        trigger_ref=body.trigger_ref,
    )
    return ProposalResponse(proposal=proposal)


@router.get("/{proposal_id}", response_model=ProposalResponse)
async def get_proposal(
    proposal_id: str,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> ProposalResponse:
    proposal = await ProposalRepository(session).get(proposal_id)
    if proposal is None or proposal.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="proposal not found")
    return ProposalResponse(proposal=proposal)


@router.post("/{proposal_id}/decision", response_model=ProposalResponse)
async def decide_proposal(
    proposal_id: str,
    body: ProposalDecideRequest,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> ProposalResponse:
    if body.decision not in (ProposalStatus.APPROVED, ProposalStatus.REJECTED):
        raise HTTPException(status_code=400, detail="decision must be approved or rejected")
    repo = ProposalRepository(session)
    existing = await repo.get(proposal_id)
    if existing is None or existing.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="proposal not found")
    try:
        decided = await repo.decide(
            proposal_id=proposal_id,
            decision=body.decision,
            actor=ctx.actor,
            channel="api",
        )
    except ProposalConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return ProposalResponse(proposal=decided)
