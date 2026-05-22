"""Async SQLAlchemy 2.0 engine and session factory.

Drives both Postgres (`asyncpg`) in production and SQLite (`aiosqlite`)
in dev/tests via the URL in `Settings.db.url`. Replaces the old
synchronous `db.py` SQLite module — that file is kept as a temporary
compat shim until the Streamlit UI is refactored to call the API.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ..config import DatabaseSettings, get_settings
from .models.orm import Base


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _build_engine(cfg: DatabaseSettings) -> AsyncEngine:
    kwargs: dict[str, object] = {"echo": cfg.echo, "future": True}
    # SQLite + aiosqlite does not accept pool sizing args.
    if not cfg.url.startswith("sqlite"):
        kwargs["pool_size"] = cfg.pool_size
        kwargs["max_overflow"] = cfg.max_overflow
    return create_async_engine(cfg.url, **kwargs)


def get_engine() -> AsyncEngine:
    global _engine, _sessionmaker
    if _engine is None:
        cfg = get_settings().db
        _engine = _build_engine(cfg)
        _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    get_engine()
    assert _sessionmaker is not None
    return _sessionmaker


async def dispose_engine() -> None:
    """Release pool connections — call at process shutdown / test teardown."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _sessionmaker = None


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Yield a session inside a transaction; commit on success, rollback on error."""
    maker = get_sessionmaker()
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def create_all() -> None:
    """Create tables from the ORM metadata.

    Convenience for tests and the dev SQLite path; production uses Alembic.
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_all() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
