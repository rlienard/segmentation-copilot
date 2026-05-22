"""Streamable-HTTP MCP transport — for LibreChat and other remote MCP clients.

Run:
    uvicorn services.mcp_server.http:app --host 0.0.0.0 --port 8002

Or directly:
    python -m services.mcp_server.http [--host 0.0.0.0] [--port 8002]
                                       [--allow-dictionary-edit]

Auth: deliberately handled by the ingress (Phase 2 OIDC sidecar or an
upstream gateway). The MCP server itself trusts whatever reaches it —
pair it with a NetworkPolicy or a reverse proxy that enforces auth.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from .server import build_server


def _build_app(allow_edit: bool):
    server = build_server(allow_dictionary_edit=allow_edit)
    # FastMCP exposes a streamable-HTTP Starlette app.
    return server.streamable_http_app()


# Default app for `uvicorn services.mcp_server.http:app`; the dictionary
# edit flag also accepts an env override so the K8s manifest can flip it
# without changing the CMD.
app = _build_app(allow_edit=os.environ.get("SCOPILOT_MCP_ALLOW_EDIT", "") == "true")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Segmentation Copilot MCP server (HTTP transport)"
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8002)
    parser.add_argument("--allow-dictionary-edit", action="store_true")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    import uvicorn  # noqa: PLC0415

    uvicorn.run(
        _build_app(allow_edit=args.allow_dictionary_edit),
        host=args.host, port=args.port,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
