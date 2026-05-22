"""Baseline service — the canonical answer to "what's currently permitted?"

Used by the scheduler (Phase 4) to detect flows not covered by the
latest approved matrix version. Without this, the proactive scan has
no notion of "unknown flow" and is meaningless.

The baseline is the latest `MatrixVersion` for the tenant. Each version
stores a JSON snapshot of the entire matrix; this service exposes a
quick `is_covered()` predicate and a diff against a set of aggregated
flows.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from ...aggregator import AggregatedFlow
from ..repositories.matrix import MatrixVersionRepository


@dataclass(frozen=True)
class _BaselineKey:
    src_sgt: int
    dst_sgt: int
    protocol: str
    src_port: str
    dst_port: str


@dataclass
class BaselineDiff:
    covered: list[AggregatedFlow]
    uncovered: list[AggregatedFlow]


class BaselineService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.matrix = MatrixVersionRepository(session)

    async def load_keys(self, tenant_id: str) -> set[_BaselineKey]:
        """Load the (sgt, dgt, protocol, src_port, dst_port) keys from the
        latest matrix version, restricted to ACEs whose action is `permit`
        (deny ACEs don't constitute coverage of legitimate flows)."""
        version = await self.matrix.latest_for_tenant(tenant_id)
        if version is None:
            return set()
        keys: set[_BaselineKey] = set()
        for contract in version.contracts.get("contracts", []):
            for ace in contract.get("aces", []):
                if ace.get("action") != "permit":
                    continue
                keys.add(
                    _BaselineKey(
                        src_sgt=contract["src_sgt"],
                        dst_sgt=contract["dst_sgt"],
                        protocol=ace["protocol"],
                        src_port=ace["src_port"],
                        dst_port=ace["dst_port"],
                    )
                )
        return keys

    async def diff(
        self, *, tenant_id: str, flows: Iterable[AggregatedFlow]
    ) -> BaselineDiff:
        """Partition flows by whether the current matrix permits them."""
        keys = await self.load_keys(tenant_id)
        covered: list[AggregatedFlow] = []
        uncovered: list[AggregatedFlow] = []
        for flow in flows:
            k = _BaselineKey(
                src_sgt=flow.key.sgt,
                dst_sgt=flow.key.dgt,
                protocol=flow.key.protocol,
                src_port=flow.key.src_port,
                dst_port=flow.key.dst_port,
            )
            (covered if k in keys else uncovered).append(flow)
        return BaselineDiff(covered=covered, uncovered=uncovered)
