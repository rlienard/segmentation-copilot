"""Scheduler loop — fires baseline scans on a fixed interval.

The loop runs continuously; only the elected leader actually scans.
Followers spin idly, ready to pick up if the leader dies. With the
in-memory leader (dev / tests), the single process always scans.

Interval and tenant list come from settings; multi-tenant fan-out is
sequential — Phase 6 can parallelise per-tenant if needed.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable

from segmentation_copilot.config import Settings
from segmentation_copilot.core.events import EventBus

from .cursor import CursorStore
from .leader import LeaderElector
from .scan import ScanResult, scan_tenant

log = logging.getLogger(__name__)


async def run_scheduler(
    *,
    bus: EventBus,
    cursor_store: CursorStore,
    leader: LeaderElector,
    settings: Settings,
    tenants: Iterable[str] | None = None,
    stop_event: asyncio.Event | None = None,
    tick_hook=None,
) -> None:
    """Run the scheduler forever.

    `tick_hook(results)` is invoked at the end of each completed tick —
    tests use it to observe outcomes without waiting on real time.
    """
    interval = settings.scheduler.scan_interval_minutes * 60
    stop_event = stop_event or asyncio.Event()
    tenant_list = list(tenants or [settings.default_tenant_id])

    while not stop_event.is_set():
        results: list[ScanResult] = []
        if leader.is_leader:
            for tenant_id in tenant_list:
                try:
                    result = await scan_tenant(
                        tenant_id=tenant_id, bus=bus, cursor=cursor_store
                    )
                    results.append(result)
                    log.info(
                        "scan tenant=%s scanned=%d enqueued=%d",
                        tenant_id, result.scanned_events, result.enqueued,
                    )
                except Exception:
                    # Phase 6: structured logging + circuit breaker on
                    # repeated failures. For now keep the loop alive.
                    log.exception("scan failed tenant=%s", tenant_id)

        if tick_hook is not None:
            await tick_hook(results)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except TimeoutError:
            pass
