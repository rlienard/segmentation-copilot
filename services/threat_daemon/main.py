"""Threat daemon entry point.

  python -m services.threat_daemon.main \\
      --host syslog.example.com --username collector \\
      --key-filename /run/secrets/ssh_key \\
      --log-path /var/log/network/syslog

Requires at least one threat-intel provider configured
(`SCOPILOT_THREAT__ABUSEIPDB_API_KEY=...` etc.). Without a provider the
daemon refuses to start — running blind would defeat the whole point.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from typing import AsyncIterator

from segmentation_copilot.config import get_settings
from segmentation_copilot.core import db as core_db
from segmentation_copilot.core.events import build_bus
from segmentation_copilot.core.threat.aggregator import build_default_aggregator
from segmentation_copilot.sources.streaming_ssh import StreamingSSHSource

from .runner import run_daemon


@asynccontextmanager
async def _session_factory() -> AsyncIterator:
    async with core_db.session_scope() as session:
        yield session


async def _async_main(args: argparse.Namespace) -> int:
    settings = get_settings()
    aggregator = build_default_aggregator(
        settings, repository_factory=_session_factory
    )
    if aggregator is None:
        logging.error(
            "no threat-intel provider configured; set at least one of "
            "SCOPILOT_THREAT__ABUSEIPDB_API_KEY / OTX_API_KEY / VIRUSTOTAL_API_KEY"
        )
        return 2

    source = StreamingSSHSource(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        key_filename=args.key_filename,
        log_path=args.log_path,
    )
    bus = build_bus(settings)
    try:
        await run_daemon(
            source=source,
            aggregator=aggregator,
            bus=bus,
            tenant_id=args.tenant_id or settings.default_tenant_id,
        )
    finally:
        await source.aclose()
        await aggregator.aclose()
        await bus.aclose()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Segmentation Copilot threat daemon")
    parser.add_argument("--host", required=True, help="Syslog host to SSH into")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", default=None)
    parser.add_argument("--key-filename", default=None,
                        help="Path to an SSH private key (preferred over password)")
    parser.add_argument("--log-path", default="/var/log/network/syslog",
                        help="Remote file to tail")
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return asyncio.run(_async_main(args))


if __name__ == "__main__":
    sys.exit(main())
