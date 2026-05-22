"""Worker entry point.

  python -m services.worker.main --role worker
  python -m services.worker.main --role scheduler

Both roles can run as the same container image — set `--role` per Pod.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import socket
import sys

from segmentation_copilot.config import get_settings
from segmentation_copilot.core.events import build_bus

from .cursor import build_cursor_store
from .leader import build_leader, leader_lifecycle
from .scheduler import run_scheduler
from .worker import run_worker


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


async def _run_worker_role(consumer_name: str) -> None:
    settings = get_settings()
    bus = build_bus(settings)
    stop = asyncio.Event()
    try:
        await run_worker(bus=bus, settings=settings, consumer_name=consumer_name, stop_event=stop)
    finally:
        await bus.aclose()


async def _run_scheduler_role() -> None:
    settings = get_settings()
    bus = build_bus(settings)
    cursor = build_cursor_store(settings=settings)
    leader = build_leader(settings=settings)
    stop = asyncio.Event()
    try:
        async with leader_lifecycle(leader):
            await run_scheduler(
                bus=bus, cursor_store=cursor, leader=leader,
                settings=settings, stop_event=stop,
            )
    finally:
        await bus.aclose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Segmentation Copilot worker")
    parser.add_argument(
        "--role", choices=("worker", "scheduler"), default="worker",
        help="Which role this process plays.",
    )
    parser.add_argument(
        "--consumer-name",
        default=os.environ.get("HOSTNAME") or socket.gethostname(),
        help="Stable identifier for the worker's consumer name.",
    )
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)

    _configure_logging(args.log_level)
    if args.role == "scheduler":
        asyncio.run(_run_scheduler_role())
    else:
        asyncio.run(_run_worker_role(args.consumer_name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
