"""Baseline scan — the central piece of proactive autonomy.

Run by the scheduler at every tick:

  1. Load all flow_events ingested since the last cursor.
  2. Re-aggregate them.
  3. Diff against the latest approved `matrix_version` (the "current
     baseline" — what's permitted right now).
  4. For each uncovered flow, publish `events.flow.unknown` so a
     worker can classify it and turn it into a proposal.
  5. Advance the cursor to the newest event we just observed.

Idempotency: each event's key is a hash of the flow tuple + the cursor
window. Re-running the same tick (e.g. on retry) re-publishes the same
keys and the bus dedupes them — no duplicate proposals.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from segmentation_copilot import aggregator, parser
from segmentation_copilot.core import db as core_db
from segmentation_copilot.core.events import (
    STREAM_FLOW_UNKNOWN,
    EventBus,
    FlowUnknownPayload,
)
from segmentation_copilot.core.observability import flow_unknown_published_counter
from segmentation_copilot.core.repositories.events import FlowEventRepository
from segmentation_copilot.core.services.baseline import BaselineService

from .cursor import CursorStore


@dataclass
class ScanResult:
    tenant_id: str
    scanned_events: int
    aggregated_flows: int
    enqueued: int
    new_cursor: datetime | None


def _aggregate_records(records) -> list[aggregator.AggregatedFlow]:
    """Convert FlowEventRecord rows back into the in-memory aggregation
    shape — same helper as `IngestionService.aggregated_for_run` but
    works against a slice (not a whole run)."""
    events = [
        parser.FlowEvent(
            ts=r.ts,
            ingress_interface="",
            sgacl_name=r.sgacl_name or "",
            observed_action=r.observed_action or "",
            protocol=r.protocol,
            src_vrf="",
            src_ip=r.src_ip or "",
            src_port=r.src_port,
            dst_vrf="",
            dst_ip=r.dst_ip or "",
            dst_port=r.dst_port,
            sgt=r.sgt,
            dgt=r.dgt,
            hits=r.hits,
            raw="",
        )
        for r in records
    ]
    return aggregator.aggregate(events)


def _idempotency_key(*, tenant_id: str, flow: aggregator.AggregatedFlow, window_start: datetime | None) -> str:
    parts = [
        tenant_id,
        str(flow.key.sgt),
        str(flow.key.dgt),
        flow.key.protocol,
        flow.key.src_port,
        flow.key.dst_port,
        window_start.isoformat() if window_start else "",
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


async def scan_tenant(
    *,
    tenant_id: str,
    bus: EventBus,
    cursor: CursorStore,
    now: datetime | None = None,
) -> ScanResult:
    """Run a single baseline scan for one tenant."""
    now = now or datetime.utcnow()
    since = await cursor.get(tenant_id)

    async with core_db.session_scope() as session:
        records = await FlowEventRepository(session).list_since(
            tenant_id=tenant_id, since=since
        )
        flows = _aggregate_records(records)
        diff = await BaselineService(session).diff(tenant_id=tenant_id, flows=flows)

    enqueued = 0
    for flow in diff.uncovered:
        payload = FlowUnknownPayload(
            tenant_id=tenant_id,
            src_sgt=flow.key.sgt,
            dst_sgt=flow.key.dgt,
            protocol=flow.key.protocol,
            src_port=flow.key.src_port,
            dst_port=flow.key.dst_port,
            total_hits=flow.total_hits,
            sample_src_ips=sorted(flow.sample_src_ips)[:5],
            sample_dst_ips=sorted(flow.sample_dst_ips)[:5],
            trigger="scheduled",
            detected_at=now,
        )
        idem = _idempotency_key(tenant_id=tenant_id, flow=flow, window_start=since)
        event_id = await bus.publish(
            stream=STREAM_FLOW_UNKNOWN,
            payload=payload.model_dump(mode="json"),
            idempotency_key=idem,
        )
        if event_id is not None:
            enqueued += 1
            flow_unknown_published_counter.labels(
                tenant_id=tenant_id, trigger="scheduled"
            ).inc()

    # Advance cursor to the newest event we just observed (NOT `now` —
    # the cursor must track ingestion progress, not wall-clock, so a
    # tick that runs against an empty backlog doesn't skip future events.)
    new_cursor = records[-1].ingestion_ts if records else since
    if new_cursor is not None and (since is None or new_cursor > since):
        await cursor.set(tenant_id, new_cursor)

    return ScanResult(
        tenant_id=tenant_id,
        scanned_events=len(records),
        aggregated_flows=len(flows),
        enqueued=enqueued,
        new_cursor=new_cursor,
    )
