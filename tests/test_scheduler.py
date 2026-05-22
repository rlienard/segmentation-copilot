"""Scheduler loop smoke tests.

Drive `run_scheduler` for a couple of ticks via the `tick_hook` so we
don't have to wait on real time, and prove that:

  * the leader runs the scan,
  * a non-leader does not.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from segmentation_copilot.config import get_settings
from segmentation_copilot.core import db as core_db
from segmentation_copilot.core.events import InMemoryBus
from segmentation_copilot.core.repositories.sgt import SGTRepository
from segmentation_copilot.core.services.ingestion import IngestionService

from services.worker.cursor import MemoryCursorStore
from services.worker.leader import MemoryLeader
from services.worker.scheduler import run_scheduler


FIXTURE = Path(__file__).parent / "fixtures" / "sample.log"
TENANT = "test-tenant"


class _AlwaysFollower:
    name = "follower"

    @property
    def is_leader(self) -> bool:
        return False

    async def start(self) -> None: ...
    async def stop(self) -> None: ...


async def _seed_logs() -> None:
    await core_db.create_all()
    async with core_db.session_scope() as session:
        sgt = SGTRepository(session)
        for sid, name in [(100, "Employees"), (200, "Web"), (300, "Guests"),
                          (400, "DNS"), (999, "External")]:
            await sgt.upsert(tenant_id=TENANT, sgt_id=sid, name=name)
        await IngestionService(session).ingest_lines(
            tenant_id=TENANT, lines=FIXTURE.read_text().splitlines()
        )


@pytest.mark.asyncio
async def test_leader_runs_scan(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SCOPILOT_SCHED__SCAN_INTERVAL_MINUTES", "1")
    get_settings.cache_clear()
    await _seed_logs()

    bus = InMemoryBus()
    cursor = MemoryCursorStore()
    leader = MemoryLeader()
    stop = asyncio.Event()
    results: list[list] = []

    async def hook(ticks):
        results.append(ticks)
        stop.set()  # stop after the first tick

    await run_scheduler(
        bus=bus, cursor_store=cursor, leader=leader,
        settings=get_settings(), tenants=[TENANT],
        stop_event=stop, tick_hook=hook,
    )
    assert results and results[0]
    assert results[0][0].tenant_id == TENANT
    assert results[0][0].enqueued > 0


@pytest.mark.asyncio
async def test_follower_does_not_scan(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SCOPILOT_SCHED__SCAN_INTERVAL_MINUTES", "1")
    get_settings.cache_clear()
    await _seed_logs()

    bus = InMemoryBus()
    cursor = MemoryCursorStore()
    leader = _AlwaysFollower()
    stop = asyncio.Event()
    seen: list[list] = []

    async def hook(ticks):
        seen.append(ticks)
        stop.set()

    await run_scheduler(
        bus=bus, cursor_store=cursor, leader=leader,
        settings=get_settings(), tenants=[TENANT],
        stop_event=stop, tick_hook=hook,
    )
    assert seen == [[]]
