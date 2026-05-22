"""Ingestion service — fetch logs, parse, aggregate, persist.

Wraps the existing pure-function pipeline (`parser`, `aggregator`,
`sources`) and persists the result via `FlowEventRepository`. Returns
both a summary and the aggregated flows (in-memory) so the caller can
pass them straight to the classification service without a round-trip.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ... import aggregator, parser
from ...sources import LocalFileSource, LogSourceConfig, SSHSource
from ..models.domain import RunRecord
from ..repositories.events import FlowEventRepository
from ..repositories.runs import RunRepository


class IngestionResult:
    def __init__(
        self,
        *,
        run: RunRecord,
        raw_lines: int,
        parsed_events: int,
        aggregated_flows: list[aggregator.AggregatedFlow],
        unique_sgts: list[int],
    ) -> None:
        self.run = run
        self.raw_lines = raw_lines
        self.parsed_events = parsed_events
        self.aggregated_flows = aggregated_flows
        self.unique_sgts = unique_sgts

    def summary(self) -> dict[str, Any]:
        return {
            "run_id": self.run.id,
            "raw_lines": self.raw_lines,
            "parsed_events": self.parsed_events,
            "unique_flows": len(self.aggregated_flows),
            "unique_sgts": self.unique_sgts,
        }


class IngestionService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.runs = RunRepository(session)
        self.events = FlowEventRepository(session)

    async def ingest_window(
        self,
        *,
        tenant_id: str,
        source_config: LogSourceConfig,
        window_start: datetime,
        window_end: datetime,
        trigger: str = "manual",
        run_id: int | None = None,
    ) -> IngestionResult:
        """Fetch logs in the given window and persist them under a new (or
        existing) run.

        Note: log fetching itself is synchronous in the legacy sources; for
        Phase 1 we run it inline. Phase 5 introduces an async streaming
        source for the daemon.
        """
        run = (
            await self.runs.get(run_id)
            if run_id is not None
            else await self.runs.create(
                tenant_id=tenant_id,
                source_type=source_config.kind,
                source_config=source_config.options,
                window_start=window_start,
                window_end=window_end,
                trigger=trigger,
            )
        )
        if run is None:
            raise LookupError(f"run {run_id} not found")

        source = _build_source(source_config)
        raw_lines = list(source.fetch(window_start, window_end))
        events = list(parser.parse_lines(raw_lines))
        aggregated = aggregator.aggregate(events)

        await self.events.bulk_insert(run_id=run.id, tenant_id=tenant_id, events=events)

        unique_sgts = sorted({e.sgt for e in events} | {e.dgt for e in events})
        return IngestionResult(
            run=run,
            raw_lines=len(raw_lines),
            parsed_events=len(events),
            aggregated_flows=aggregated,
            unique_sgts=unique_sgts,
        )

    async def ingest_lines(
        self,
        *,
        tenant_id: str,
        lines: Iterable[str],
        trigger: str = "manual",
        run_id: int | None = None,
        source_type: str = "inline",
    ) -> IngestionResult:
        """Ingest pre-fetched syslog lines (used by tests, the threat
        daemon, and the streaming path)."""
        run = (
            await self.runs.get(run_id)
            if run_id is not None
            else await self.runs.create(
                tenant_id=tenant_id,
                source_type=source_type,
                trigger=trigger,
            )
        )
        if run is None:
            raise LookupError(f"run {run_id} not found")

        line_list = list(lines)
        events = list(parser.parse_lines(line_list))
        aggregated = aggregator.aggregate(events)
        await self.events.bulk_insert(run_id=run.id, tenant_id=tenant_id, events=events)

        unique_sgts = sorted({e.sgt for e in events} | {e.dgt for e in events})
        return IngestionResult(
            run=run,
            raw_lines=len(line_list),
            parsed_events=len(events),
            aggregated_flows=aggregated,
            unique_sgts=unique_sgts,
        )


def _build_source(cfg: LogSourceConfig):
    if cfg.kind == "local":
        return LocalFileSource.from_config(cfg)
    if cfg.kind == "ssh":
        return SSHSource.from_config(cfg)
    raise ValueError(f"unknown source kind: {cfg.kind}")
