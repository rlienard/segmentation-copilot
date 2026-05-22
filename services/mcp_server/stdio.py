"""Stdio MCP transport — for Claude Code, Claude Desktop, local CLI clients.

Run:
    python -m services.mcp_server.stdio [--allow-dictionary-edit]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .server import build_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Segmentation Copilot MCP server (stdio transport)"
    )
    parser.add_argument(
        "--allow-dictionary-edit", action="store_true",
        help="Expose set_sgt_name tool. Default is read-only on the dictionary.",
    )
    parser.add_argument("--log-level", default="WARNING",
                        help="stdio MCP is sensitive to stdout noise; default WARNING")
    args = parser.parse_args(argv)

    # stdio uses stdout for the MCP protocol — keep logs on stderr only.
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.WARNING),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    server = build_server(allow_dictionary_edit=args.allow_dictionary_edit)
    asyncio.run(server.run_stdio_async())
    return 0


if __name__ == "__main__":
    sys.exit(main())
