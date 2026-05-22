"""`scopilot` — command-line client of the Segmentation Copilot REST API.

Install with `pip install -e ".[cli]"` then run `scopilot --help`.

Environment:
  SCOPILOT_API_BASE   default http://localhost:8000
  SCOPILOT_API_TOKEN  bearer token (required when the API has auth on)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(add_completion=False, help="Segmentation Copilot CLI")
runs_app = typer.Typer(help="Manage analysis runs")
sgt_app = typer.Typer(help="Manage the SGT dictionary")
proposal_app = typer.Typer(help="List and decide on rule proposals")
app.add_typer(runs_app, name="run")
app.add_typer(sgt_app, name="sgt")
app.add_typer(proposal_app, name="proposal")

console = Console()


def _client() -> httpx.Client:
    base = os.environ.get("SCOPILOT_API_BASE", "http://localhost:8000")
    headers: dict[str, str] = {}
    token = os.environ.get("SCOPILOT_API_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=base, headers=headers, timeout=60.0)


def _bail(resp: httpx.Response) -> None:
    console.print(f"[red]HTTP {resp.status_code}[/red]: {resp.text}")
    raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# scopilot health
# ---------------------------------------------------------------------------


@app.command()
def health() -> None:
    """Check the API's liveness + readiness."""
    with _client() as c:
        for path in ("/healthz", "/readyz"):
            r = c.get(path)
            status = "[green]OK[/green]" if r.is_success else f"[red]{r.status_code}[/red]"
            console.print(f"{path:10s} {status}")


# ---------------------------------------------------------------------------
# scopilot run …
# ---------------------------------------------------------------------------


@runs_app.command("list")
def list_runs(limit: int = 20) -> None:
    """List recent runs for the current tenant."""
    with _client() as c:
        r = c.get("/v1/runs", params={"limit": limit})
        if not r.is_success:
            _bail(r)
        data = r.json()["runs"]

    table = Table(title="Runs")
    table.add_column("id", justify="right")
    table.add_column("started_at")
    table.add_column("source")
    table.add_column("status")
    table.add_column("trigger")
    for run in data:
        table.add_row(
            str(run["id"]), run["started_at"], run["source_type"],
            run["status"], run["trigger"],
        )
    console.print(table)


@runs_app.command("start")
def start_run(
    log_file: Path = typer.Argument(..., exists=True, readable=True,
                                    help="Path to a syslog file to ingest"),
    classify: bool = typer.Option(
        True, "--classify/--no-classify",
        help="Run Claude classification after ingest",
    ),
    build_matrix: bool = typer.Option(
        True, "--matrix/--no-matrix", help="Build the contract matrix",
    ),
) -> None:
    """Create a run, upload a local log file, optionally classify and build the matrix."""
    lines = log_file.read_text(encoding="utf-8").splitlines()
    with _client() as c:
        r = c.post("/v1/runs", json={"source_type": "inline"})
        if r.status_code != 201:
            _bail(r)
        run_id = r.json()["run"]["id"]
        console.print(f"[green]created run[/green] id={run_id}")

        r = c.post(f"/v1/runs/{run_id}/ingest", json={"lines": lines})
        if not r.is_success:
            _bail(r)
        console.print_json(json.dumps(r.json()))

        if classify:
            r = c.post(f"/v1/runs/{run_id}/classify")
            if not r.is_success:
                _bail(r)
            console.print_json(json.dumps(r.json()))

        if build_matrix:
            r = c.post(f"/v1/runs/{run_id}/matrix")
            if not r.is_success:
                _bail(r)
            console.print(r.json()["markdown"])


@runs_app.command("matrix")
def show_matrix(run_id: int) -> None:
    """Print the markdown matrix for a run."""
    with _client() as c:
        r = c.get(f"/v1/runs/{run_id}/matrix")
        if not r.is_success:
            _bail(r)
        console.print(r.json()["markdown"])


# ---------------------------------------------------------------------------
# scopilot sgt …
# ---------------------------------------------------------------------------


@sgt_app.command("list")
def list_sgt() -> None:
    """List the SGT id→name dictionary for the current tenant."""
    with _client() as c:
        r = c.get("/v1/sgt")
        if not r.is_success:
            _bail(r)
        entries = r.json()["entries"]
    table = Table(title="SGT dictionary")
    table.add_column("id", justify="right")
    table.add_column("name")
    for e in entries:
        table.add_row(str(e["sgt_id"]), e["name"])
    console.print(table)


@sgt_app.command("set")
def set_sgt(sgt_id: int, name: str) -> None:
    """Upsert a single SGT id→name."""
    with _client() as c:
        r = c.post("/v1/sgt", json={"sgt_id": sgt_id, "name": name})
        if r.status_code != 201:
            _bail(r)
    console.print(f"[green]set[/green] {sgt_id} → {name}")


@sgt_app.command("load")
def load_sgt(
    path: Path = typer.Argument(..., exists=True, readable=True,
                                help="Path to a JSON file of {sgt_id: name} mappings"),
) -> None:
    """Bulk-load a JSON dictionary file."""
    data: dict[str, Any] = json.loads(path.read_text())
    entries = {str(k): str(v) for k, v in data.items()}
    with _client() as c:
        r = c.post("/v1/sgt/bulk", json={"entries": entries})
        if r.status_code != 201:
            _bail(r)
    console.print(f"[green]upserted[/green] {r.json()['upserted']} entries")


# ---------------------------------------------------------------------------
# scopilot proposal …
# ---------------------------------------------------------------------------


@proposal_app.command("list")
def list_proposals(
    status: str | None = typer.Option(None, help="pending / notified / approved / rejected"),
) -> None:
    """List proposals."""
    params: dict[str, str] = {}
    if status:
        params["status"] = status
    with _client() as c:
        r = c.get("/v1/proposals", params=params)
        if not r.is_success:
            _bail(r)
        proposals = r.json()["proposals"]
    if not proposals:
        console.print("[dim]no proposals[/dim]")
        return
    table = Table(title="Proposals")
    table.add_column("id")
    table.add_column("src→dst")
    table.add_column("status")
    table.add_column("trigger")
    table.add_column("rationale")
    for p in proposals:
        table.add_row(
            p["id"][:8], f"{p['src_sgt']}→{p['dst_sgt']}",
            p["status"], p["trigger"], p["rationale"][:60],
        )
    console.print(table)


@proposal_app.command("approve")
def approve(proposal_id: str) -> None:
    """Approve a proposal."""
    _decide(proposal_id, "approved")


@proposal_app.command("reject")
def reject(proposal_id: str) -> None:
    """Reject a proposal."""
    _decide(proposal_id, "rejected")


def _decide(proposal_id: str, decision: str) -> None:
    with _client() as c:
        r = c.post(f"/v1/proposals/{proposal_id}/decision",
                   json={"decision": decision})
        if not r.is_success:
            _bail(r)
    console.print(f"[green]{decision}[/green] {proposal_id}")


def main() -> None:  # entry point for `scopilot` console script
    app()


if __name__ == "__main__":
    main()
