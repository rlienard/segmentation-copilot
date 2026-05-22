"""Matrix router — build and read the TrustSec contract matrix per run."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from segmentation_copilot.core.repositories.runs import RunRepository
from segmentation_copilot.core.services import MatrixService

from ..auth import AuthContext
from ..deps import get_auth_context, get_session
from ..schemas import MatrixResponse

router = APIRouter(prefix="/v1/runs", tags=["matrix"])


@router.post("/{run_id}/matrix", response_model=MatrixResponse)
async def build_matrix(
    run_id: int,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> MatrixResponse:
    run = await RunRepository(session).get(run_id)
    if run is None or run.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="run not found")
    svc = MatrixService(session)
    contracts = await svc.build(tenant_id=ctx.tenant_id, run_id=run_id)
    md = await svc.render_markdown(run_id=run_id)
    return MatrixResponse(run_id=run_id, contracts=contracts, markdown=md)


@router.get("/{run_id}/matrix", response_model=MatrixResponse)
async def get_matrix(
    run_id: int,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> MatrixResponse:
    run = await RunRepository(session).get(run_id)
    if run is None or run.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="run not found")
    svc = MatrixService(session)
    contracts = await svc.contracts.list_for_run(run_id)
    md = await svc.render_markdown(run_id=run_id)
    return MatrixResponse(run_id=run_id, contracts=contracts, markdown=md)
