"""Classification repository — per-flow category + rationale, with a
cache lookup keyed by aggregated-flow tuple so the scheduler can skip
flows already classified within the last N days."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ...aggregator import AggregatedFlow
from ..models.domain import ClassificationRecord, FlowCategory
from ..models.orm import FlowClassification


class ClassificationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def upsert_batch(
        self,
        *,
        run_id: int,
        tenant_id: str,
        classified: Iterable[tuple[AggregatedFlow, str, str]],
    ) -> int:
        """Insert classifications, ignoring duplicates on the natural key.

        Uses dialect-specific `INSERT ... ON CONFLICT DO NOTHING` so reruns
        of the same `run_id` are idempotent.
        """
        rows = [
            {
                "run_id": run_id,
                "tenant_id": tenant_id,
                "sgt": flow.key.sgt,
                "dgt": flow.key.dgt,
                "protocol": flow.key.protocol,
                "src_port": flow.key.src_port,
                "dst_port": flow.key.dst_port,
                "category": category,
                "rationale": rationale,
                "total_hits": flow.total_hits,
            }
            for flow, category, rationale in classified
        ]
        if not rows:
            return 0

        dialect = self.session.bind.dialect.name if self.session.bind else "sqlite"
        if dialect == "postgresql":
            stmt = pg_insert(FlowClassification).values(rows)
            stmt = stmt.on_conflict_do_nothing(constraint="uq_classification_run_flow")
        else:
            stmt = sqlite_insert(FlowClassification).values(rows)
            stmt = stmt.on_conflict_do_nothing(
                index_elements=["run_id", "sgt", "dgt", "protocol", "src_port", "dst_port"]
            )
        await self.session.execute(stmt)
        return len(rows)

    async def recent_for_flow(
        self,
        *,
        tenant_id: str,
        sgt: int,
        dgt: int,
        protocol: str,
        src_port: str,
        dst_port: str,
        within: timedelta,
    ) -> ClassificationRecord | None:
        """Return the most recent classification for this flow tuple within
        the window. Used by the scheduler to skip re-classifying flows."""
        cutoff = datetime.utcnow() - within
        stmt = (
            select(FlowClassification)
            .where(
                FlowClassification.tenant_id == tenant_id,
                FlowClassification.sgt == sgt,
                FlowClassification.dgt == dgt,
                FlowClassification.protocol == protocol,
                FlowClassification.src_port == src_port,
                FlowClassification.dst_port == dst_port,
                FlowClassification.classified_at >= cutoff,
            )
            .order_by(FlowClassification.classified_at.desc())
            .limit(1)
        )
        result = await self.session.execute(stmt)
        row = result.scalars().first()
        return ClassificationRecord.model_validate(row) if row else None

    async def list_for_run(self, run_id: int) -> list[ClassificationRecord]:
        stmt = (
            select(FlowClassification)
            .where(FlowClassification.run_id == run_id)
            .order_by(FlowClassification.id)
        )
        result = await self.session.execute(stmt)
        return [ClassificationRecord.model_validate(c) for c in result.scalars().all()]

    async def counts_for_run(self, run_id: int) -> dict[str, int]:
        records = await self.list_for_run(run_id)
        counts: dict[str, int] = {c.value: 0 for c in FlowCategory}
        for r in records:
            counts[r.category.value] = counts.get(r.category.value, 0) + 1
        return counts
