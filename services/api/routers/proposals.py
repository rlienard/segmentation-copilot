"""Proposals router — list, create, approve, reject.

Delegates the state machine + storm-collapse + apply-to-matrix to
`core.services.ProposalService`. The creation endpoint also schedules a
notification fan-out via FastAPI `BackgroundTasks` so operators see the
proposal in WebEx without blocking the HTTP response. When Phase 4 lands
Redis Streams, the BackgroundTask call swaps for a stream enqueue.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from segmentation_copilot.core.models.domain import (
    ProposalRecord,
    ProposalStatus,
    ProposalTrigger,
)
from segmentation_copilot.core.repositories.proposals import (
    ProposalConflictError,
    ProposalRepository,
)
from segmentation_copilot.core.services.notifier import get_notifier
from segmentation_copilot.core.services.proposal import (
    ProposalApplyError,
    ProposalService,
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


async def _fanout_created(proposal: ProposalRecord) -> None:
    await get_notifier().proposal_created(proposal)


async def _fanout_decided(proposal: ProposalRecord) -> None:
    await get_notifier().proposal_decided(proposal)


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
    background: BackgroundTasks,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> ProposalResponse:
    service = ProposalService(session)
    proposal, created = await service.propose(
        tenant_id=ctx.tenant_id,
        trigger=ProposalTrigger(body.trigger),
        src_sgt=body.src_sgt,
        dst_sgt=body.dst_sgt,
        proposed_aces=body.proposed_aces,
        rationale=body.rationale,
        run_id=body.run_id,
        trigger_ref=body.trigger_ref,
        expires_in=timedelta(hours=body.expires_in_hours),
    )
    if created:
        background.add_task(_fanout_created, proposal)
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
    background: BackgroundTasks,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> ProposalResponse:
    if body.decision not in (ProposalStatus.APPROVED, ProposalStatus.REJECTED):
        raise HTTPException(status_code=400, detail="decision must be approved or rejected")
    service = ProposalService(session)
    existing = await service.proposals.get(proposal_id)
    if existing is None or existing.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="proposal not found")
    try:
        decided = await service.decide(
            proposal_id=proposal_id,
            decision=body.decision,
            actor=ctx.actor,
            channel="api",
        )
    except ProposalConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ProposalApplyError as exc:
        # Apply failed; the proposal is now in FAILED state. Surface the
        # underlying error so the caller can investigate.
        raise HTTPException(status_code=500, detail=f"apply failed: {exc}") from exc
    background.add_task(_fanout_decided, decided)
    return ProposalResponse(proposal=decided)
