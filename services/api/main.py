"""FastAPI app factory.

Run with:

    uvicorn services.api.main:app --host 0.0.0.0 --port 8000

The factory pattern lets tests build an isolated app instance with
overridden dependencies, and lets Phase 6 wrap the app in OpenTelemetry
instrumentation without touching the route definitions.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from segmentation_copilot.config import get_settings
from segmentation_copilot.core import db as core_db

from .routers import health, matrix, proposals, runs, sgt


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    # On a SQLite dev URL we transparently create tables on startup so the
    # API is usable out of the box. Postgres / staging / prod use Alembic.
    settings = get_settings()
    if settings.db.url.startswith("sqlite"):
        await core_db.create_all()
    yield
    await core_db.dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Segmentation Copilot API",
        version="0.2.0",
        description=(
            "REST surface for the segmentation-copilot agent. "
            "Drives runs, manages the SGT dictionary, and exposes the "
            "proposal approval workflow."
        ),
        lifespan=_lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
    )
    app.include_router(health.router)
    app.include_router(runs.router)
    app.include_router(matrix.router)
    app.include_router(sgt.router)
    app.include_router(proposals.router)
    return app


app = create_app()
