"""FastAPI dependencies: async DB session + auth context.

The session dep yields a session inside a transaction, committing on
success or rolling back on exception — same pattern as `core.db.session_scope`.
Tests override `get_session` to inject an in-memory session bound to a
shared transaction so writes are visible across the request boundary.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from segmentation_copilot.core import db as core_db

from .auth import AuthContext, get_auth_context


async def get_session() -> AsyncIterator[AsyncSession]:
    async with core_db.session_scope() as session:
        yield session


__all__ = ["AuthContext", "get_auth_context", "get_session"]


# Re-export so routers can `from .deps import auth` cleanly.
auth = Depends(get_auth_context)
session_dep = Depends(get_session)
