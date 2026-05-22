"""Runs router — create runs, ingest log lines, list runs."""

from __future__ import annotations

from datetime import timedelta

from anthropic import Anthropic
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from segmentation_copilot.config import get_settings
from segmentation_copilot.core.repositories.classifications import ClassificationRepository
from segmentation_copilot.core.repositories.events import FlowEventRepository
from segmentation_copilot.core.repositories.runs import RunRepository
from segmentation_copilot.core.services import (
    ClassificationService,
    IngestionService,
    MatrixService,
)

from ..auth import AuthContext
from ..deps import get_auth_context, get_session
from ..schemas import (
    ClassificationsResponse,
    ClassifyResponse,
    CreateRunRequest,
    IngestLinesRequest,
    IngestSummary,
    MissingSGTsResponse,
    RunResponse,
    RunsListResponse,
)

router = APIRouter(prefix="/v1/runs", tags=["runs"])


@router.post("", response_model=RunResponse, status_code=201)
async def create_run(
    body: CreateRunRequest,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> RunResponse:
    run = await RunRepository(session).create(
        tenant_id=ctx.tenant_id,
        source_type=body.source_type,
        source_config=body.source_config,
        window_start=body.window_start,
        window_end=body.window_end,
        trigger=body.trigger,
    )
    return RunResponse(run=run)


@router.get("", response_model=RunsListResponse)
async def list_runs(
    limit: int = 100,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> RunsListResponse:
    runs = await RunRepository(session).list_for_tenant(ctx.tenant_id, limit=limit)
    return RunsListResponse(runs=runs)


@router.get("/{run_id}", response_model=RunResponse)
async def get_run(
    run_id: int,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> RunResponse:
    run = await RunRepository(session).get(run_id)
    if run is None or run.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="run not found")
    return RunResponse(run=run)


@router.post("/{run_id}/ingest", response_model=IngestSummary)
async def ingest_lines(
    run_id: int,
    body: IngestLinesRequest,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> IngestSummary:
    run = await RunRepository(session).get(run_id)
    if run is None or run.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="run not found")
    result = await IngestionService(session).ingest_lines(
        tenant_id=ctx.tenant_id,
        lines=body.lines,
        run_id=run_id,
        source_type=run.source_type,
    )
    return IngestSummary(**result.summary())


@router.get("/{run_id}/missing-sgts", response_model=MissingSGTsResponse)
async def missing_sgts(
    run_id: int,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> MissingSGTsResponse:
    run = await RunRepository(session).get(run_id)
    if run is None or run.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="run not found")
    ids = await FlowEventRepository(session).distinct_sgt_dgt_for_run(run_id)
    from segmentation_copilot.core.repositories.sgt import SGTRepository

    missing = await SGTRepository(session).missing_ids(tenant_id=ctx.tenant_id, ids=ids)
    return MissingSGTsResponse(missing=missing)


@router.post("/{run_id}/classify", response_model=ClassifyResponse)
async def classify(
    run_id: int,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> ClassifyResponse:
    """Classify all aggregated flows for the run.

    Re-aggregates from persisted `flow_events` so the call is stateless
    across the ingest → classify boundary. Uses the 7-day per-tenant
    classification cache so already-seen flows skip the LLM round-trip.
    """
    run = await RunRepository(session).get(run_id)
    if run is None or run.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="run not found")

    ingestion = IngestionService(session)
    flows = await ingestion.aggregated_for_run(run_id)
    if not flows:
        raise HTTPException(status_code=400, detail="no flows to classify; ingest first")

    settings = get_settings()
    client = Anthropic(api_key=settings.anthropic.api_key) if settings.anthropic.api_key else None
    counts = await ClassificationService(session).classify(
        tenant_id=ctx.tenant_id,
        run_id=run_id,
        flows=flows,
        client=client,
        cache_window=timedelta(days=settings.scheduler.classification_cache_days),
    )
    return ClassifyResponse(run_id=run_id, counts=counts)


@router.get("/{run_id}/classifications", response_model=ClassificationsResponse)
async def list_classifications(
    run_id: int,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> ClassificationsResponse:
    run = await RunRepository(session).get(run_id)
    if run is None or run.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="run not found")
    records = await ClassificationRepository(session).list_for_run(run_id)
    return ClassificationsResponse(classifications=records)
