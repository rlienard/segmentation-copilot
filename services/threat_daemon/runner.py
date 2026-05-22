"""Daemon control loop, separated from the entrypoint for testability.

`run_daemon()` takes already-constructed dependencies (source,
aggregator, bus). The CLI in `main.py` wires production defaults; tests
inject an `InMemoryStreamingSource` and a fake aggregator.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Awaitable, Callable

from segmentation_copilot import parser
from segmentation_copilot.core.events import (
    STREAM_FLOW_UNKNOWN,
    EventBus,
    FlowUnknownPayload,
)
from segmentation_copilot.core.threat import ThreatAggregator
from segmentation_copilot.sources.streaming import StreamingLogSource
from segmentation_copilot.sources.streaming_ssh import HEARTBEAT_PREFIX


log = logging.getLogger(__name__)


DaemonProgressHook = Callable[[str, dict], Awaitable[None]]


async def run_daemon(
    *,
    source: StreamingLogSource,
    aggregator: ThreatAggregator,
    bus: EventBus,
    tenant_id: str,
    progress_hook: DaemonProgressHook | None = None,
    max_events: int | None = None,
) -> int:
    """Stream lines from `source`, classify destination IPs, enqueue threats.

    Returns the number of `events.flow.unknown` enqueued. `max_events`
    is an upper bound on processed lines (tests use it to terminate).
    """
    enqueued = 0
    processed = 0

    async for line in source.tail():
        if line.startswith(HEARTBEAT_PREFIX):
            # Liveness marker — surface for observability and skip parsing.
            if progress_hook is not None:
                await progress_hook("heartbeat", {"line": line})
            continue

        event = parser.parse_line(line)
        processed += 1
        if event is None:
            if progress_hook is not None:
                await progress_hook("skip_unparseable", {"line": line})
            if max_events is not None and processed >= max_events:
                return enqueued
            continue
        if not event.dst_ip:
            if progress_hook is not None:
                await progress_hook("skip_no_dst_ip", {"event": event.raw})
            if max_events is not None and processed >= max_events:
                return enqueued
            continue

        decision = await aggregator.lookup_ip(tenant_id=tenant_id, ip=event.dst_ip)
        if progress_hook is not None:
            await progress_hook(
                "lookup",
                {"ip": event.dst_ip, "is_malicious": decision.is_malicious,
                 "max_score": decision.max_score},
            )
        if not decision.is_malicious:
            if max_events is not None and processed >= max_events:
                return enqueued
            continue

        payload = FlowUnknownPayload(
            tenant_id=tenant_id,
            src_sgt=event.sgt,
            dst_sgt=event.dgt,
            protocol=event.protocol,
            src_port=event.src_port,
            dst_port=event.dst_port,
            total_hits=event.hits,
            sample_src_ips=[event.src_ip] if event.src_ip else [],
            sample_dst_ips=[event.dst_ip] if event.dst_ip else [],
            trigger="threat",
            trigger_ref=event.dst_ip,
            threat_context={
                "decision": {
                    "is_malicious": decision.is_malicious,
                    "max_score": decision.max_score,
                    "triggering_providers": decision.triggering_providers,
                },
                "verdicts": [
                    {
                        "provider": v.provider,
                        "score": v.score,
                        "categories": v.categories,
                    }
                    for v in decision.verdicts
                ],
            },
            detected_at=datetime.utcnow(),
        )
        # Idempotency = "this destination + this 5-tuple, once per cache
        # TTL window" — repeat hits to the same C2 don't fire a card a
        # second.
        idem = (
            f"threat:{tenant_id}:{event.sgt}:{event.dgt}:{event.protocol}:"
            f"{event.src_port}:{event.dst_port}:{event.dst_ip}"
        )
        event_id = await bus.publish(
            stream=STREAM_FLOW_UNKNOWN,
            payload=payload.model_dump(mode="json"),
            idempotency_key=idem,
        )
        if event_id is not None:
            enqueued += 1
            if progress_hook is not None:
                await progress_hook("enqueued", {"ip": event.dst_ip})

        if max_events is not None and processed >= max_events:
            return enqueued

    return enqueued
