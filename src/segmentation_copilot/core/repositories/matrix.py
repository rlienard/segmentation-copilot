"""Matrix-version repository — immutable approved baselines.

Each approval creates a new `MatrixVersion` row pointing at its parent;
rollback is a pointer flip (the latest applied row IS the current baseline).
The `baseline` service uses `latest_for_tenant` to answer "what is
currently permitted?" when the scheduler scans for unknown flows.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.domain import MatrixVersionRecord
from ..models.orm import MatrixVersion


class MatrixVersionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        *,
        tenant_id: str,
        contracts: dict[str, Any],
        parent_id: int | None = None,
        created_by: str | None = None,
        note: str | None = None,
    ) -> MatrixVersionRecord:
        version = MatrixVersion(
            tenant_id=tenant_id,
            parent_id=parent_id,
            contracts=contracts,
            created_by=created_by,
            note=note,
        )
        self.session.add(version)
        await self.session.flush()
        await self.session.refresh(version)
        return MatrixVersionRecord.model_validate(version)

    async def latest_for_tenant(self, tenant_id: str) -> MatrixVersionRecord | None:
        stmt = (
            select(MatrixVersion)
            .where(MatrixVersion.tenant_id == tenant_id)
            .order_by(MatrixVersion.id.desc())
            .limit(1)
        )
        result = await self.session.execute(stmt)
        row = result.scalars().first()
        return MatrixVersionRecord.model_validate(row) if row else None

    async def get(self, version_id: int) -> MatrixVersionRecord | None:
        row = await self.session.get(MatrixVersion, version_id)
        return MatrixVersionRecord.model_validate(row) if row else None
