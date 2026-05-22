"""WebEx bot tests.

Exercise the four things the bot must get right:

  1. HMAC verification rejects unsigned / tampered webhooks.
  2. Adaptive card payload shape includes the proposal id in each button's
     `data` so the decision dispatcher can find it back.
  3. The `attachmentActions.created` webhook path drives
     `ProposalService.decide()` with the right actor + channel.
  4. The inline `approve <id>` command path produces the same outcome.

Outgoing HTTP to webexapis.com is fully mocked — no live network.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from segmentation_copilot.core.models.domain import (
    ACE,
    ProposalRecord,
    ProposalStatus,
    ProposalTrigger,
)
from segmentation_copilot.core.services.proposal import ProposalService
from services.webex_bot.cards import decision_summary, proposal_card
from services.webex_bot.verify import compute_signature, verify_signature


def _ace(port: str = "445", action: str = "deny") -> ACE:
    return ACE(protocol="tcp", src_port="any", dst_port=port, action=action,
               source_category="harmful")


# ---------------------------------------------------------------------------
# Unit: HMAC verify
# ---------------------------------------------------------------------------


def test_verify_signature_accepts_valid():
    body = b'{"hello":"world"}'
    sig = compute_signature(body, "shh")
    assert verify_signature(body, sig, "shh") is True


def test_verify_signature_rejects_tampered():
    body = b'{"hello":"world"}'
    sig = compute_signature(body, "shh")
    tampered = body + b" "
    assert verify_signature(tampered, sig, "shh") is False


def test_verify_signature_rejects_missing():
    assert verify_signature(b"x", None, "shh") is False
    assert verify_signature(b"x", "deadbeef", "") is False


# ---------------------------------------------------------------------------
# Unit: card builder
# ---------------------------------------------------------------------------


def _fake_proposal(**overrides: Any) -> ProposalRecord:
    defaults: dict[str, Any] = {
        "id": "abc-1234567890",
        "tenant_id": "t",
        "run_id": None,
        "trigger": ProposalTrigger.THREAT,
        "trigger_ref": None,
        "src_sgt": 100,
        "dst_sgt": 200,
        "proposed_aces": [_ace("445")],
        "rationale": "SMB exposed to user VLAN",
        "threat_context": None,
        "status": ProposalStatus.PENDING,
        "created_at": "2026-05-22T12:00:00",
        "notified_at": None,
        "decided_at": None,
        "decided_by": None,
        "decision_channel": None,
        "expires_at": "2026-05-23T12:00:00",
        "idempotency_key": "k",
    }
    defaults.update(overrides)
    return ProposalRecord(**defaults)


def test_proposal_card_embeds_proposal_id_in_actions():
    card = proposal_card(_fake_proposal())
    actions = card["content"]["actions"]
    assert {a["data"]["action"] for a in actions} == {"approve", "reject"}
    assert all(a["data"]["proposal_id"] == "abc-1234567890" for a in actions)


def test_decision_summary_renders_actor():
    p = _fake_proposal(status=ProposalStatus.APPLIED, decided_by="alice@example.com")
    summary = decision_summary(p)
    assert "alice@example.com" in summary
    assert "applied" in summary


# ---------------------------------------------------------------------------
# Integration: webhook dispatch through the FastAPI app
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def bot_client(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SCOPILOT_WEBEX__BOT_ACCESS_TOKEN", "fake-bot-token")
    monkeypatch.setenv("SCOPILOT_WEBEX__WEBHOOK_SECRET", "shh")
    monkeypatch.setenv("SCOPILOT_WEBEX__OPERATORS_ROOM_ID", "room-xyz")
    from segmentation_copilot import config
    from segmentation_copilot.core import db as core_db
    from services.webex_bot.main import create_app

    config.get_settings.cache_clear()
    await core_db.create_all()
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    await core_db.dispose_engine()


def _signed_headers(body: bytes, secret: str = "shh") -> dict[str, str]:
    return {"X-Spark-Signature": compute_signature(body, secret),
            "Content-Type": "application/json"}


@pytest.mark.asyncio
async def test_webhook_rejects_bad_signature(bot_client: AsyncClient):
    body = json.dumps({"resource": "messages"}).encode()
    resp = await bot_client.post(
        "/webhooks/webex", content=body,
        headers={"X-Spark-Signature": "deadbeef", "Content-Type": "application/json"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_webhook_ignores_unknown_resource(bot_client: AsyncClient):
    body = json.dumps({"resource": "rooms", "event": "created"}).encode()
    resp = await bot_client.post(
        "/webhooks/webex", content=body, headers=_signed_headers(body)
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ignored"}


@pytest.mark.asyncio
async def test_webhook_card_action_approves_proposal(
    bot_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
):
    # Seed a pending proposal.
    from segmentation_copilot.core import db as core_db

    async with core_db.session_scope() as session:
        service = ProposalService(session)
        proposal, _ = await service.propose(
            tenant_id="default",
            trigger=ProposalTrigger.MANUAL,
            src_sgt=100, dst_sgt=200,
            proposed_aces=[_ace("443", "permit")],
            rationale="HTTPS",
            expires_in=timedelta(hours=1),
        )
    proposal_id = proposal.id

    # Mock WebExClient so the webhook handler does no real HTTP.
    posted: list[dict[str, Any]] = []

    class _FakeWebExClient:
        def __init__(self, *args, **kwargs) -> None: ...

        @classmethod
        def from_settings(cls, settings):
            return cls()

        async def get_attachment_action(self, action_id: str) -> dict[str, Any]:
            return {"inputs": {"action": "approve", "proposal_id": proposal_id}}

        async def post_message(self, **kwargs):
            posted.append(kwargs)
            return {"id": "msg-1"}

        async def aclose(self) -> None: ...

    monkeypatch.setattr("services.webex_bot.main.WebExClient", _FakeWebExClient)

    payload = {
        "resource": "attachmentActions",
        "event": "created",
        "data": {"id": "action-1", "personId": "user-1", "roomId": "room-xyz"},
    }
    body = json.dumps(payload).encode()
    resp = await bot_client.post(
        "/webhooks/webex", content=body, headers=_signed_headers(body)
    )
    assert resp.status_code == 200

    async with core_db.session_scope() as session:
        decided = await ProposalService(session).proposals.get(proposal_id)
    assert decided is not None
    assert decided.status is ProposalStatus.APPLIED
    assert decided.decided_by == "webex:user-1"
    assert decided.decision_channel == "webex"

    # Operators got an acknowledgement message.
    assert any("approved" in (m.get("text") or "") for m in posted)


@pytest.mark.asyncio
async def test_webhook_message_command_rejects_proposal(
    bot_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
):
    from segmentation_copilot.core import db as core_db

    async with core_db.session_scope() as session:
        service = ProposalService(session)
        proposal, _ = await service.propose(
            tenant_id="default",
            trigger=ProposalTrigger.MANUAL,
            src_sgt=100, dst_sgt=200,
            proposed_aces=[_ace("3389", "deny")],
            rationale="r",
            expires_in=timedelta(hours=1),
        )
    proposal_id = proposal.id

    posted: list[dict[str, Any]] = []

    class _FakeWebExClient:
        def __init__(self, *args, **kwargs) -> None: ...

        @classmethod
        def from_settings(cls, settings):
            return cls()

        async def get_message(self, message_id: str):
            return {"text": f"reject {proposal_id}"}

        async def post_message(self, **kwargs):
            posted.append(kwargs)
            return {"id": "msg-2"}

        async def aclose(self) -> None: ...

    monkeypatch.setattr("services.webex_bot.main.WebExClient", _FakeWebExClient)

    payload = {
        "resource": "messages",
        "event": "created",
        "data": {"id": "msg-1", "personId": "user-2", "roomId": "room-xyz"},
    }
    body = json.dumps(payload).encode()
    resp = await bot_client.post(
        "/webhooks/webex", content=body, headers=_signed_headers(body)
    )
    assert resp.status_code == 200

    async with core_db.session_scope() as session:
        decided = await ProposalService(session).proposals.get(proposal_id)
    assert decided is not None and decided.status is ProposalStatus.REJECTED
    assert any("rejected" in (m.get("text") or "") for m in posted)


@pytest.mark.asyncio
async def test_webhook_card_action_handles_race(
    bot_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
):
    """If another operator already decided, the bot must not crash."""
    from segmentation_copilot.core import db as core_db

    async with core_db.session_scope() as session:
        service = ProposalService(session)
        proposal, _ = await service.propose(
            tenant_id="default",
            trigger=ProposalTrigger.MANUAL,
            src_sgt=100, dst_sgt=200,
            proposed_aces=[_ace("445")],
            rationale="r",
            expires_in=timedelta(hours=1),
        )
        # Decide before the webhook arrives.
        await service.decide(
            proposal_id=proposal.id,
            decision=ProposalStatus.REJECTED,
            actor="alice",
            channel="api",
        )

    class _FakeWebExClient:
        def __init__(self, *args, **kwargs) -> None: ...

        @classmethod
        def from_settings(cls, settings):
            return cls()

        async def get_attachment_action(self, action_id: str):
            return {"inputs": {"action": "approve", "proposal_id": proposal.id}}

        async def post_message(self, **kwargs):
            return {"id": "msg-3"}

        async def aclose(self) -> None: ...

    monkeypatch.setattr("services.webex_bot.main.WebExClient", _FakeWebExClient)

    payload = {
        "resource": "attachmentActions",
        "event": "created",
        "data": {"id": "action-2", "personId": "user-3", "roomId": "room-xyz"},
    }
    body = json.dumps(payload).encode()
    resp = await bot_client.post(
        "/webhooks/webex", content=body, headers=_signed_headers(body)
    )
    assert resp.status_code == 200  # graceful — no crash on race.
