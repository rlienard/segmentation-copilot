"""Smoke tests for the `scopilot` CLI.

The CLI uses a sync `httpx.Client`; routing it at the in-process ASGI app
requires a sync→async bridge that's not worth the test plumbing. Instead
we mock `httpx.Client.request` so we exercise Typer's command dispatch,
argument parsing, and the CLI's HTTP-call structure. Full HTTP behavior
is covered by `test_api.py`.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
from typer.testing import CliRunner

from services.cli.main import app


FIXTURE = Path(__file__).parent / "fixtures" / "sample.log"


def _mock_client(responses: dict[tuple[str, str], httpx.Response]) -> MagicMock:
    """Build a MagicMock that stands in for `httpx.Client(...)`.

    Routes `client.request(method, path)` and `client.get/post` to the
    response keyed by `(method, path)`. Unknown routes get a 404 so missing
    expectations surface as test failures, not silent passes.
    """
    def _request(method: str, path: str, **kwargs):
        return responses.get((method.upper(), path), httpx.Response(404, text="not stubbed"))

    mock = MagicMock()
    mock.__enter__.return_value = mock
    mock.__exit__.return_value = False
    mock.request.side_effect = _request
    mock.get.side_effect = lambda path, **kw: _request("GET", path, **kw)
    mock.post.side_effect = lambda path, **kw: _request("POST", path, **kw)
    return mock


def _resp(status: int, body: dict | str) -> httpx.Response:
    if isinstance(body, str):
        return httpx.Response(status, text=body)
    return httpx.Response(status, json=body)


def test_cli_health_command():
    responses = {
        ("GET", "/healthz"): _resp(200, {"status": "ok"}),
        ("GET", "/readyz"): _resp(200, {"status": "ready"}),
    }
    with patch("services.cli.main.httpx.Client", return_value=_mock_client(responses)):
        result = CliRunner().invoke(app, ["health"])
    assert result.exit_code == 0, result.output
    assert "/healthz" in result.output and "/readyz" in result.output


def test_cli_sgt_set():
    responses = {
        ("POST", "/v1/sgt"): _resp(201, {"sgt_id": 100, "name": "Employees"}),
    }
    with patch("services.cli.main.httpx.Client", return_value=_mock_client(responses)):
        result = CliRunner().invoke(app, ["sgt", "set", "100", "Employees"])
    assert result.exit_code == 0, result.output
    assert "Employees" in result.output


def test_cli_run_start_drives_full_pipeline():
    responses = {
        ("POST", "/v1/runs"): _resp(201, {"run": {"id": 7}}),
        ("POST", "/v1/runs/7/ingest"): _resp(
            200, {"run_id": 7, "raw_lines": 7, "parsed_events": 6,
                  "unique_flows": 5, "unique_sgts": [100, 200]}
        ),
        ("POST", "/v1/runs/7/classify"): _resp(
            200, {"run_id": 7, "counts": {"business_relevant": 5}}
        ),
        ("POST", "/v1/runs/7/matrix"): _resp(
            200, {"run_id": 7, "contracts": [],
                  "markdown": "| Source SGT | ... |"}
        ),
    }
    with patch("services.cli.main.httpx.Client", return_value=_mock_client(responses)):
        result = CliRunner().invoke(app, ["run", "start", str(FIXTURE)])
    assert result.exit_code == 0, result.output
    assert "created run" in result.output
    assert "id=7" in result.output


def test_cli_proposal_approve():
    responses = {
        ("POST", "/v1/proposals/abc-123/decision"): _resp(
            200, {"proposal": {"id": "abc-123", "status": "approved"}}
        ),
    }
    with patch("services.cli.main.httpx.Client", return_value=_mock_client(responses)):
        result = CliRunner().invoke(app, ["proposal", "approve", "abc-123"])
    assert result.exit_code == 0, result.output
    assert "approved" in result.output
