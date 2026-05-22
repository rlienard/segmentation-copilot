"""MCP server tests.

The FastMCP `tool()` decorator registers each function in the server's
tool manager; we drive it through `call_tool(name, arguments)` which is
exactly what the stdio / HTTP transports would invoke. No real MCP
client needed.

The tests cover the happy path of each tool group plus the
dictionary-edit gate (`set_sgt_name` only exists when
`allow_dictionary_edit=True`).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from segmentation_copilot.core import db as core_db
from segmentation_copilot.core.repositories.sgt import SGTRepository

FIXTURE = Path(__file__).parent / "fixtures" / "sample.log"


async def _call(server, name: str, arguments: dict | None = None):
    """Invoke a tool by name via the FastMCP server."""
    return await server.call_tool(name, arguments or {})


def _result_payload(result):
    """Return the structured payload from FastMCP's CallToolResult tuple.

    FastMCP returns `(content_blocks, structured_content)` where
    `structured_content` is `{"result": <typed return value>}`. Prefer that —
    the content blocks only carry the *first* element of a list return,
    which trips up obvious-looking `.text` parsing.
    """
    if isinstance(result, tuple) and len(result) >= 2:
        structured = result[1]
        if isinstance(structured, dict) and "result" in structured:
            return structured["result"]
        if isinstance(structured, dict):
            return structured
    # Fallback: render whatever the first text block carried.
    if isinstance(result, tuple) and result and isinstance(result[0], list):
        for block in result[0]:
            text = getattr(block, "text", None)
            if text is not None:
                try:
                    return json.loads(text)
                except (json.JSONDecodeError, TypeError):
                    return text
    return result


def _fake_classify(flows, sgt_dict, client=None, model=None):
    return [(f, "business_relevant", "mcp-fake") for f in flows]


@pytest.mark.asyncio
async def test_mcp_run_lifecycle_through_tools():
    """start_run → ingest_lines → classify_run → build_matrix end-to-end."""
    await core_db.create_all()
    # Seed the SGT dictionary directly — set_sgt_name is gated and disabled
    # for this test.
    async with core_db.session_scope() as s:
        for sid, name in [(100, "Employees"), (200, "Web"), (300, "Guests"),
                          (400, "DNS"), (999, "External")]:
            await SGTRepository(s).upsert(tenant_id="test-tenant", sgt_id=sid, name=name)

    from services.mcp_server.server import build_server

    server = build_server(allow_dictionary_edit=False)

    res = await _call(server, "start_run", {"source_type": "inline"})
    payload = _result_payload(res)
    run_id = payload["run_id"]
    assert isinstance(run_id, int)

    lines = FIXTURE.read_text().splitlines()
    res = await _call(server, "ingest_lines", {"run_id": run_id, "lines": lines})
    summary = _result_payload(res)
    assert summary["parsed_events"] == 6

    with patch(
        "segmentation_copilot.core.services.classification.classify.classify_batch",
        side_effect=_fake_classify,
    ):
        res = await _call(server, "classify_run", {"run_id": run_id})
    counts = _result_payload(res)
    assert counts.get("business_relevant", 0) >= 1

    res = await _call(server, "build_matrix", {"run_id": run_id})
    matrix = _result_payload(res)
    assert "Source SGT" in matrix["markdown"]
    assert len(matrix["contracts"]) >= 1


@pytest.mark.asyncio
async def test_mcp_set_sgt_name_only_present_when_enabled():
    from services.mcp_server.server import build_server

    locked = build_server(allow_dictionary_edit=False)
    tools_locked = {t.name for t in await locked.list_tools()}
    assert "set_sgt_name" not in tools_locked
    assert "list_sgt_entries" in tools_locked

    unlocked = build_server(allow_dictionary_edit=True)
    tools_unlocked = {t.name for t in await unlocked.list_tools()}
    assert "set_sgt_name" in tools_unlocked


@pytest.mark.asyncio
async def test_mcp_proposal_flow():
    await core_db.create_all()
    from services.mcp_server.server import build_server

    server = build_server()
    aces = [{"protocol": "tcp", "src_port": "any", "dst_port": "443",
             "action": "permit", "source_category": "business_relevant"}]
    res = await _call(server, "create_proposal", {
        "src_sgt": 100, "dst_sgt": 200,
        "proposed_aces": aces,
        "rationale": "HTTPS for the web tier",
    })
    proposal = _result_payload(res)
    pid = proposal["id"]
    assert proposal["status"] == "pending"

    res = await _call(server, "approve_proposal", {
        "proposal_id": pid, "actor": "alice@example.com"
    })
    approved = _result_payload(res)
    assert approved["status"] == "applied"

    # List proposals — the approved one should appear.
    res = await _call(server, "list_proposals", {})
    items = _result_payload(res)
    assert any(p["id"] == pid for p in items)


@pytest.mark.asyncio
async def test_mcp_lookup_threat_intel_returns_error_when_unconfigured():
    """No keys configured → graceful error, not a 500."""
    from services.mcp_server.server import build_server

    server = build_server()
    res = await _call(server, "lookup_threat_intel", {"ip": "1.2.3.4"})
    payload = _result_payload(res)
    assert "error" in payload
