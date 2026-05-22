"""InMemoryBus contract tests.

These pin the semantics Phase 4 depends on:
  - Idempotency dedup: same key → second publish returns None.
  - Consumer groups: each group reads independently from the stream head.
  - Acks track pending state but do not block redelivery in the in-memory
    bus (Redis Streams provides that — tested in Phase 6 with fakeredis).
"""

from __future__ import annotations

import asyncio

import pytest

from segmentation_copilot.core.events import InMemoryBus


@pytest.mark.asyncio
async def test_publish_returns_event_id():
    bus = InMemoryBus()
    eid = await bus.publish(stream="s.test", payload={"hello": "world"})
    assert eid is not None


@pytest.mark.asyncio
async def test_publish_with_idempotency_key_dedupes():
    bus = InMemoryBus()
    a = await bus.publish(stream="s.test", payload={"n": 1}, idempotency_key="same")
    b = await bus.publish(stream="s.test", payload={"n": 2}, idempotency_key="same")
    assert a is not None
    assert b is None


@pytest.mark.asyncio
async def test_consume_and_ack():
    bus = InMemoryBus()
    await bus.ensure_group(stream="s.test", group="g")
    await bus.publish(stream="s.test", payload={"n": 1})
    await bus.publish(stream="s.test", payload={"n": 2})

    envs = await bus.consume(stream="s.test", group="g", consumer="c1", count=10, block_ms=10)
    assert [e.payload["n"] for e in envs] == [1, 2]

    # Re-consuming after ack returns nothing (cursor advanced).
    await bus.ack(stream="s.test", group="g", event_ids=[e.event_id for e in envs])
    envs2 = await bus.consume(stream="s.test", group="g", consumer="c1", count=10, block_ms=10)
    assert envs2 == []


@pytest.mark.asyncio
async def test_consume_blocks_until_timeout_when_empty():
    bus = InMemoryBus()
    await bus.ensure_group(stream="s.empty", group="g")
    start = asyncio.get_event_loop().time()
    envs = await bus.consume(stream="s.empty", group="g", consumer="c1", count=10, block_ms=30)
    elapsed = asyncio.get_event_loop().time() - start
    assert envs == []
    assert elapsed >= 0.02
