"""Contract repository — TrustSec matrix output for a run."""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models.domain import ACE, ContractRecord
from ..models.orm import Contract, ContractACE


class ContractRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def replace_for_run(
        self,
        *,
        run_id: int,
        tenant_id: str,
        contracts: Iterable[dict],
    ) -> int:
        """Replace any existing contracts for this run with the supplied set.

        Idempotent: re-running build_matrix on the same run cleanly overwrites.
        """
        # Delete-then-insert keeps the operation idempotent even across
        # schema variants that don't support a clean upsert on composite FKs.
        existing_stmt = select(Contract).where(Contract.run_id == run_id)
        existing = (await self.session.execute(existing_stmt)).scalars().all()
        for c in existing:
            await self.session.delete(c)
        await self.session.flush()

        count = 0
        for contract in contracts:
            c = Contract(
                run_id=run_id,
                tenant_id=tenant_id,
                src_sgt=contract["src_sgt"],
                dst_sgt=contract["dst_sgt"],
                src_sgt_name=contract["src_sgt_name"],
                dst_sgt_name=contract["dst_sgt_name"],
                name=contract["name"],
            )
            self.session.add(c)
            await self.session.flush()
            for ace in contract["aces"]:
                self.session.add(
                    ContractACE(
                        contract_id=c.id,
                        protocol=ace["protocol"],
                        src_port=ace["src_port"],
                        dst_port=ace["dst_port"],
                        action=ace["action"],
                        source_category=ace.get("source_category"),
                    )
                )
            count += 1
        await self.session.flush()
        return count

    async def list_for_run(self, run_id: int) -> list[ContractRecord]:
        stmt = (
            select(Contract)
            .where(Contract.run_id == run_id)
            .options(selectinload(Contract.aces))
            .order_by(Contract.src_sgt, Contract.dst_sgt)
        )
        result = await self.session.execute(stmt)
        records: list[ContractRecord] = []
        for c in result.scalars().all():
            records.append(
                ContractRecord(
                    id=c.id,
                    run_id=c.run_id,
                    tenant_id=c.tenant_id,
                    src_sgt=c.src_sgt,
                    dst_sgt=c.dst_sgt,
                    src_sgt_name=c.src_sgt_name,
                    dst_sgt_name=c.dst_sgt_name,
                    name=c.name,
                    aces=[
                        ACE(
                            protocol=a.protocol,
                            src_port=a.src_port,
                            dst_port=a.dst_port,
                            action=a.action,
                            source_category=a.source_category,
                        )
                        for a in c.aces
                    ],
                )
            )
        return records
