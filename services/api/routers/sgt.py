"""SGT dictionary router — per-tenant id→name CRUD."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from segmentation_copilot.core.repositories.sgt import SGTRepository

from ..auth import AuthContext
from ..deps import get_auth_context, get_session
from ..schemas import (
    SGTBulkUpsertRequest,
    SGTListResponse,
    SGTUpsertRequest,
)

router = APIRouter(prefix="/v1/sgt", tags=["sgt"])


@router.get("", response_model=SGTListResponse)
async def list_entries(
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> SGTListResponse:
    entries = await SGTRepository(session).list_for_tenant(ctx.tenant_id)
    return SGTListResponse(entries=entries)


@router.post("", status_code=201)
async def upsert_entry(
    body: SGTUpsertRequest,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> dict[str, int | str]:
    record = await SGTRepository(session).upsert(
        tenant_id=ctx.tenant_id, sgt_id=body.sgt_id, name=body.name
    )
    return {"sgt_id": record.sgt_id, "name": record.name}


@router.post("/bulk", status_code=201)
async def bulk_upsert(
    body: SGTBulkUpsertRequest,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> dict[str, int]:
    try:
        entries = [(int(k), v) for k, v in body.entries.items()]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="SGT IDs must be integers") from exc
    count = await SGTRepository(session).upsert_many(
        tenant_id=ctx.tenant_id, entries=entries
    )
    return {"upserted": count}
