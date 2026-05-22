"""MCP server — same `core` import as every other service.

Two transports are shipped as separate binaries on top of one shared
tool registry (`tools.py`):

  * `stdio.py`       — `python -m services.mcp_server.stdio`
                       Suits Claude Code / Claude Desktop / any local client.
  * `http.py`        — streamable HTTP for LibreChat / remote MCP clients.

The MCP protocol is stateless — every tool takes an explicit `run_id` /
`tenant_id`, never relies on conversation-scoped state. Authorization
lives at the repo layer (already tenant-scoped from Phase 1).
"""
