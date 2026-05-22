"""Liveness + readiness probes.

`/healthz` is process-alive (always 200 if FastAPI is serving requests).
`/readyz` additionally pings the DB so K8s only routes traffic when the
backend is reachable.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_session

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(session: AsyncSession = Depends(get_session)) -> dict[str, str]:
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover — exercised by chaos tests
        raise HTTPException(status_code=503, detail=f"db unreachable: {exc}") from exc
    return {"status": "ready"}
