"""SGT dictionary repository — per-tenant id→name mapping.

Replaces the in-memory `SGTDictionary` for persistent / multi-tenant use.
The in-memory `SGTDictionary` class still exists for the pure-function
classify/aggregate pipeline; this repo is how it gets persisted.
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ...sgt import SGTDictionary
from ..models.domain import SGTEntryRecord
from ..models.orm import SGTEntry


class SGTRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def upsert(self, *, tenant_id: str, sgt_id: int, name: str) -> SGTEntryRecord:
        dialect = self.session.bind.dialect.name if self.session.bind else "sqlite"
        values = {"tenant_id": tenant_id, "sgt_id": sgt_id, "name": name}
        if dialect == "postgresql":
            stmt = pg_insert(SGTEntry).values(values)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_sgt_tenant_id",
                set_={"name": stmt.excluded.name},
            )
        else:
            stmt = sqlite_insert(SGTEntry).values(values)
            stmt = stmt.on_conflict_do_update(
                index_elements=["tenant_id", "sgt_id"],
                set_={"name": stmt.excluded.name},
            )
        await self.session.execute(stmt)
        result = await self.session.execute(
            select(SGTEntry).where(
                SGTEntry.tenant_id == tenant_id, SGTEntry.sgt_id == sgt_id
            )
        )
        return SGTEntryRecord.model_validate(result.scalars().one())

    async def upsert_many(
        self, *, tenant_id: str, entries: Iterable[tuple[int, str]]
    ) -> int:
        count = 0
        for sgt_id, name in entries:
            await self.upsert(tenant_id=tenant_id, sgt_id=sgt_id, name=name)
            count += 1
        return count

    async def list_for_tenant(self, tenant_id: str) -> list[SGTEntryRecord]:
        stmt = select(SGTEntry).where(SGTEntry.tenant_id == tenant_id).order_by(SGTEntry.sgt_id)
        result = await self.session.execute(stmt)
        return [SGTEntryRecord.model_validate(e) for e in result.scalars().all()]

    async def as_dictionary(self, tenant_id: str) -> SGTDictionary:
        entries = await self.list_for_tenant(tenant_id)
        return SGTDictionary(names={e.sgt_id: e.name for e in entries})

    async def missing_ids(self, *, tenant_id: str, ids: Iterable[int]) -> list[int]:
        existing = await self.list_for_tenant(tenant_id)
        known = {e.sgt_id for e in existing}
        return sorted({i for i in ids if i not in known})
