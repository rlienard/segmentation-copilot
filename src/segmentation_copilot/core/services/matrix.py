"""Matrix service — build contracts from classifications and render output."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from ... import contracts as contracts_lib
from ...aggregator import AggregatedFlow, FlowKey
from ..models.domain import ContractRecord
from ..repositories.classifications import ClassificationRepository
from ..repositories.contracts import ContractRepository
from ..repositories.runs import RunRepository
from ..repositories.sgt import SGTRepository


class MatrixService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.classifications = ClassificationRepository(session)
        self.contracts = ContractRepository(session)
        self.sgt = SGTRepository(session)
        self.runs = RunRepository(session)

    async def build(self, *, tenant_id: str, run_id: int) -> list[ContractRecord]:
        """Build (or rebuild) the contract list for a run from its
        classifications. Idempotent."""
        sgt_dict = await self.sgt.as_dictionary(tenant_id)
        classifications = await self.classifications.list_for_run(run_id)

        as_pairs: list[tuple[AggregatedFlow, str, str]] = []
        for c in classifications:
            flow = AggregatedFlow(
                key=FlowKey(
                    sgt=c.sgt,
                    dgt=c.dgt,
                    protocol=c.protocol,
                    src_port=c.src_port,
                    dst_port=c.dst_port,
                ),
                total_hits=c.total_hits,
            )
            as_pairs.append((flow, c.category.value, c.rationale or ""))

        contract_dicts = contracts_lib.build_contracts(as_pairs, sgt_dict)
        await self.contracts.replace_for_run(
            run_id=run_id, tenant_id=tenant_id, contracts=contract_dicts
        )
        await self.runs.set_status(run_id, "complete")
        return await self.contracts.list_for_run(run_id)

    async def render_markdown(self, *, run_id: int) -> str:
        records = await self.contracts.list_for_run(run_id)
        return contracts_lib.render_markdown(
            [
                {
                    "src_sgt": c.src_sgt,
                    "dst_sgt": c.dst_sgt,
                    "src_sgt_name": c.src_sgt_name,
                    "dst_sgt_name": c.dst_sgt_name,
                    "name": c.name,
                    "aces": [ace.model_dump() for ace in c.aces],
                }
                for c in records
            ]
        )
