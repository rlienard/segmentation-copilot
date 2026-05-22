"""FastAPI integration tests.

Spin up the app with an in-memory SQLite database and auth disabled, then
drive the full Phase-1 pipeline (create run → ingest → classify → matrix)
plus the proposal CRUD surface entirely over HTTP.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


FIXTURE = Path(__file__).parent / "fixtures" / "sample.log"


@pytest_asyncio.fixture
async def client(monkeypatch: pytest.MonkeyPatch):
    """Yield an httpx AsyncClient bound to the FastAPI app over ASGI.

    Disables auth so requests don't need an Authorization header, and uses
    the in-memory SQLite engine from the autouse fixture in conftest.py.
    """
    monkeypatch.setenv("SCOPILOT_API__REQUIRE_AUTH", "false")
    from segmentation_copilot import config
    from segmentation_copilot.core import db as core_db
    from services.api.main import create_app

    config.get_settings.cache_clear()
    await core_db.create_all()
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    await core_db.dispose_engine()


def _fake_classify(flows, sgt_dict, client=None, model=None):
    return [(f, "business_relevant", "api-fake") for f in flows]


@pytest.mark.asyncio
async def test_healthz(client: AsyncClient):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_readyz(client: AsyncClient):
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}


@pytest.mark.asyncio
async def test_full_pipeline_over_http(client: AsyncClient):
    # 1. seed the SGT dictionary
    resp = await client.post(
        "/v1/sgt/bulk",
        json={"entries": {"100": "Employees", "200": "Web", "300": "Guests",
                          "400": "DNS", "999": "External"}},
    )
    assert resp.status_code == 201
    assert resp.json()["upserted"] == 5

    # 2. create a run
    resp = await client.post("/v1/runs", json={"source_type": "inline"})
    assert resp.status_code == 201
    run_id = resp.json()["run"]["id"]

    # 3. ingest log lines
    lines = FIXTURE.read_text().splitlines()
    resp = await client.post(f"/v1/runs/{run_id}/ingest", json={"lines": lines})
    assert resp.status_code == 200
    summary = resp.json()
    assert summary["parsed_events"] == 6
    assert summary["raw_lines"] == 7

    # 4. classify (LLM patched to a deterministic fake)
    with patch(
        "segmentation_copilot.core.services.classification.classify.classify_batch",
        side_effect=_fake_classify,
    ):
        resp = await client.post(f"/v1/runs/{run_id}/classify")
    assert resp.status_code == 200
    counts = resp.json()["counts"]
    assert counts["business_relevant"] >= 1

    # 5. build the matrix
    resp = await client.post(f"/v1/runs/{run_id}/matrix")
    assert resp.status_code == 200
    matrix = resp.json()
    assert "Source SGT" in matrix["markdown"]
    assert len(matrix["contracts"]) >= 1


@pytest.mark.asyncio
async def test_missing_sgts(client: AsyncClient):
    resp = await client.post("/v1/runs", json={"source_type": "inline"})
    run_id = resp.json()["run"]["id"]
    lines = [
        "Jun 18 10:00:00: %RBM-6-SGACLHIT: protocol='tcp' sgt='42' dgt='43' "
        "src-port='1' dest-port='2' logging_interval_hits='1'"
    ]
    await client.post(f"/v1/runs/{run_id}/ingest", json={"lines": lines})

    resp = await client.get(f"/v1/runs/{run_id}/missing-sgts")
    assert resp.status_code == 200
    assert resp.json()["missing"] == [42, 43]

    await client.post("/v1/sgt", json={"sgt_id": 42, "name": "FortyTwo"})
    resp = await client.get(f"/v1/runs/{run_id}/missing-sgts")
    assert resp.json()["missing"] == [43]


@pytest.mark.asyncio
async def test_proposal_create_idempotent_and_decide(client: AsyncClient):
    ace = {"protocol": "tcp", "src_port": "any", "dst_port": "445", "action": "deny",
           "source_category": "harmful"}
    body = {
        "src_sgt": 100, "dst_sgt": 200,
        "proposed_aces": [ace],
        "rationale": "SMB exposed to user VLAN",
        "trigger": "manual",
    }
    first = await client.post("/v1/proposals", json=body)
    assert first.status_code == 201
    pid = first.json()["proposal"]["id"]

    # Re-posting the same shape returns the same proposal (idempotent).
    second = await client.post("/v1/proposals", json=body)
    assert second.status_code == 201
    assert second.json()["proposal"]["id"] == pid

    # Approve.
    decision = await client.post(
        f"/v1/proposals/{pid}/decision", json={"decision": "approved"}
    )
    assert decision.status_code == 200
    assert decision.json()["proposal"]["status"] == "approved"

    # Second decision conflicts with optimistic lock.
    again = await client.post(
        f"/v1/proposals/{pid}/decision", json={"decision": "rejected"}
    )
    assert again.status_code == 409


@pytest.mark.asyncio
async def test_auth_required_when_enabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SCOPILOT_API__REQUIRE_AUTH", "true")
    monkeypatch.setenv("SCOPILOT_API__API_KEYS", '["secret-test-token"]')
    from segmentation_copilot import config
    from segmentation_copilot.core import db as core_db
    from services.api.main import create_app

    config.get_settings.cache_clear()
    await core_db.create_all()
    app = create_app()
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # No token: 401.
            resp = await ac.get("/v1/runs")
            assert resp.status_code == 401

            # Wrong token: 401.
            resp = await ac.get(
                "/v1/runs", headers={"Authorization": "Bearer wrong-token"}
            )
            assert resp.status_code == 401

            # Correct token: 200.
            resp = await ac.get(
                "/v1/runs", headers={"Authorization": "Bearer secret-test-token"}
            )
            assert resp.status_code == 200
    finally:
        await core_db.dispose_engine()
