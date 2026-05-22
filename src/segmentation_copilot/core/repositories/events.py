"""Flow-event repository — raw parsed SGACLHIT entries."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...parser import FlowEvent as ParsedFlowEvent
from ..models.domain import FlowEventRecord
from ..models.orm import FlowEvent


class FlowEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def bulk_insert(
        self,
        *,
        run_id: int,
        tenant_id: str,
        events: Iterable[ParsedFlowEvent],
        ingestion_ts: datetime | None = None,
    ) -> int:
        rows = [
            FlowEvent(
                run_id=run_id,
                tenant_id=tenant_id,
                ts=e.ts,
                ingestion_ts=ingestion_ts or datetime.utcnow(),
                sgt=e.sgt,
                dgt=e.dgt,
                protocol=e.protocol,
                src_port=e.src_port,
                dst_port=e.dst_port,
                src_ip=e.src_ip or None,
                dst_ip=e.dst_ip or None,
                hits=e.hits,
                sgacl_name=e.sgacl_name or None,
                observed_action=e.observed_action or None,
            )
            for e in events
        ]
        if not rows:
            return 0
        self.session.add_all(rows)
        await self.session.flush()
        return len(rows)

    async def list_for_run(self, run_id: int) -> list[FlowEventRecord]:
        stmt = select(FlowEvent).where(FlowEvent.run_id == run_id).order_by(FlowEvent.id)
        result = await self.session.execute(stmt)
        return [FlowEventRecord.model_validate(e) for e in result.scalars().all()]

    async def distinct_sgt_dgt_for_run(self, run_id: int) -> list[int]:
        stmt = select(FlowEvent.sgt, FlowEvent.dgt).where(FlowEvent.run_id == run_id).distinct()
        result = await self.session.execute(stmt)
        ids: set[int] = set()
        for sgt, dgt in result.all():
            ids.add(sgt)
            ids.add(dgt)
        return sorted(ids)

    async def list_since(
        self, *, tenant_id: str, since: datetime | None
    ) -> list[FlowEventRecord]:
        """Events ingested for this tenant on or after `since`.

        Uses `ingestion_ts` (wall-clock), not the syslog `ts`, so the
        scheduler is robust against year/TZ heuristics breaking at
        rollover (the 24/7 case the parser warns about).
        """
        stmt = (
            select(FlowEvent)
            .where(FlowEvent.tenant_id == tenant_id)
            .order_by(FlowEvent.ingestion_ts)
        )
        if since is not None:
            stmt = stmt.where(FlowEvent.ingestion_ts >= since)
        result = await self.session.execute(stmt)
        return [FlowEventRecord.model_validate(e) for e in result.scalars().all()]
