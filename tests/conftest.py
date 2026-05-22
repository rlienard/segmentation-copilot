"""Shared pytest fixtures.

Each test gets an isolated in-memory SQLite database with the full ORM
schema applied (via `Base.metadata.create_all`, not Alembic — much faster
for tests). The fixture also clears the cached `Settings` so per-test
env overrides are picked up.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio


@pytest.fixture(autouse=True)
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force each test onto an in-memory SQLite + cleared settings cache."""
    monkeypatch.setenv("SCOPILOT_DB__URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("SCOPILOT_ANTHROPIC__API_KEY", "test-key")
    monkeypatch.setenv("SCOPILOT_DEFAULT_TENANT_ID", "test-tenant")
    from segmentation_copilot import config
    from segmentation_copilot.core.services import notifier as notifier_mod

    config.get_settings.cache_clear()
    notifier_mod.reset_notifier()


@pytest_asyncio.fixture
async def session() -> AsyncIterator:
    """Yield a fresh async SQLAlchemy session backed by an in-memory DB.

    Tables are created once per test from the ORM metadata.
    """
    from segmentation_copilot.core import db as core_db

    await core_db.create_all()
    maker = core_db.get_sessionmaker()
    async with maker() as s:
        yield s
        await s.rollback()
    await core_db.dispose_engine()
