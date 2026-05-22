"""Run repository — analysis-pass lifecycle."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.domain import RunRecord
from ..models.orm import Run


class RunRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        *,
        tenant_id: str,
        source_type: str,
        source_config: dict[str, Any] | None = None,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
        trigger: str = "manual",
    ) -> RunRecord:
        run = Run(
            tenant_id=tenant_id,
            source_type=source_type,
            source_config=source_config,
            window_start=window_start,
            window_end=window_end,
            trigger=trigger,
        )
        self.session.add(run)
        await self.session.flush()
        await self.session.refresh(run)
        return RunRecord.model_validate(run)

    async def set_status(self, run_id: int, status: str) -> None:
        run = await self.session.get(Run, run_id)
        if run is None:
            raise LookupError(f"run {run_id} not found")
        run.status = status

    async def get(self, run_id: int) -> RunRecord | None:
        run = await self.session.get(Run, run_id)
        return RunRecord.model_validate(run) if run else None

    async def list_for_tenant(self, tenant_id: str, limit: int = 100) -> list[RunRecord]:
        stmt = (
            select(Run)
            .where(Run.tenant_id == tenant_id)
            .order_by(Run.id.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return [RunRecord.model_validate(r) for r in result.scalars().all()]
