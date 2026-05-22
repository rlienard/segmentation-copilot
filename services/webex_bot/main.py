"""WebEx bot — webhook receiver + decision dispatcher.

Single endpoint:

  POST /webhooks/webex  — WebEx callback. HMAC-verified, then dispatched
                          by resource type. `attachmentActions.created`
                          drives the approval loop; `messages.created`
                          handles inline commands (full streaming chat
                          arrives with Phase 4's SSE endpoint).

Run with:

    uvicorn services.webex_bot.main:app --host 0.0.0.0 --port 8001
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from segmentation_copilot.config import Settings, get_settings
from segmentation_copilot.core import db as core_db
from segmentation_copilot.core.models.domain import ProposalStatus
from segmentation_copilot.core.repositories.proposals import ProposalConflictError
from segmentation_copilot.core.services.notifier import get_notifier
from segmentation_copilot.core.services.proposal import (
    ProposalApplyError,
    ProposalService,
)

from .cards import decision_summary
from .client import WebExClient
from .verify import verify_signature


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield
    await core_db.dispose_engine()


def create_app() -> FastAPI:
    app = FastAPI(title="Segmentation Copilot WebEx bot", lifespan=_lifespan)
    app.include_router(_build_router())
    return app


async def _get_session() -> AsyncIterator[AsyncSession]:
    async with core_db.session_scope() as session:
        yield session


def _build_router():
    from fastapi import APIRouter

    router = APIRouter()

    @router.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @router.post("/webhooks/webex")
    async def webex_webhook(
        request: Request,
        x_spark_signature: str | None = Header(default=None),
        session: AsyncSession = Depends(_get_session),
        settings: Settings = Depends(get_settings),
    ) -> dict[str, str]:
        body = await request.body()
        if settings.webex.webhook_secret:
            if not verify_signature(body, x_spark_signature, settings.webex.webhook_secret):
                raise HTTPException(status_code=401, detail="invalid X-Spark-Signature")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"invalid JSON: {exc}") from exc

        resource = payload.get("resource")
        event = payload.get("event")
        if resource == "attachmentActions" and event == "created":
            await _handle_card_action(payload, session, settings)
            return {"status": "dispatched"}
        if resource == "messages" and event == "created":
            await _handle_message(payload, session, settings)
            return {"status": "dispatched"}
        return {"status": "ignored"}

    return router


# ---------------------------------------------------------------------------
# Webhook handlers
# ---------------------------------------------------------------------------


async def _handle_card_action(
    payload: dict[str, Any], session: AsyncSession, settings: Settings
) -> None:
    """Approve/Reject button → ProposalService.decide()."""
    data = payload.get("data") or {}
    action_id = data.get("id")
    actor_id = data.get("personId") or "webex:unknown"
    if not action_id:
        return

    client = WebExClient.from_settings(settings)
    try:
        action = await client.get_attachment_action(action_id)
    finally:
        await client.aclose()

    inputs = action.get("inputs") or {}
    proposal_id = inputs.get("proposal_id")
    decision_key = inputs.get("action")
    if not proposal_id or decision_key not in ("approve", "reject"):
        return

    target_status = (
        ProposalStatus.APPROVED if decision_key == "approve" else ProposalStatus.REJECTED
    )
    service = ProposalService(session)
    try:
        decided = await service.decide(
            proposal_id=proposal_id,
            decision=target_status,
            actor=f"webex:{actor_id}",
            channel="webex",
        )
    except ProposalConflictError:
        # Someone else already decided — surface the current state, don't bail.
        decided = await service.proposals.get(proposal_id)
        if decided is not None:
            await get_notifier().proposal_decided(decided)
        return
    except ProposalApplyError:
        decided = await service.proposals.get(proposal_id)
        if decided is not None:
            await get_notifier().proposal_decided(decided)
        return

    # Inline acknowledgement so operators see the outcome in-thread.
    room_id = payload.get("data", {}).get("roomId") or settings.webex.operators_room_id
    if room_id and settings.webex.bot_access_token:
        ack_client = WebExClient.from_settings(settings)
        try:
            await ack_client.post_message(room_id=room_id, text=decision_summary(decided))
        finally:
            await ack_client.aclose()


async def _handle_message(
    payload: dict[str, Any], session: AsyncSession, settings: Settings
) -> None:
    """Inline commands. Phase-3 scope: `list pending`, `approve <id>`, `reject <id>`.

    Streaming agent chat lands with the SSE endpoint in Phase 4 — for now
    these terse commands cover the operator use cases the WebEx UX needs.
    """
    data = payload.get("data") or {}
    message_id = data.get("id")
    actor_id = data.get("personId") or "webex:unknown"
    room_id = data.get("roomId")
    if not (message_id and room_id and settings.webex.bot_access_token):
        return

    client = WebExClient.from_settings(settings)
    try:
        message = await client.get_message(message_id)
        text = (message.get("text") or "").strip()
        reply = await _execute_command(text, session, actor_id, settings)
        if reply:
            await client.post_message(room_id=room_id, text=reply)
    finally:
        await client.aclose()


async def _execute_command(
    text: str, session: AsyncSession, actor_id: str, settings: Settings
) -> str | None:
    if not text:
        return None
    parts = text.split()
    cmd = parts[0].lower()
    service = ProposalService(session)

    if cmd in ("help", "?"):
        return (
            "**Commands:**\n"
            "- `list pending` — show pending proposals\n"
            "- `approve <proposal-id>` — approve a proposal\n"
            "- `reject <proposal-id>` — reject a proposal"
        )

    if cmd == "list" and len(parts) > 1 and parts[1].lower() == "pending":
        pending = await service.proposals.list_for_tenant(
            tenant_id=settings.default_tenant_id, status=ProposalStatus.PENDING
        )
        notified = await service.proposals.list_for_tenant(
            tenant_id=settings.default_tenant_id, status=ProposalStatus.NOTIFIED
        )
        rows = pending + notified
        if not rows:
            return "No pending proposals."
        return "\n".join(
            f"- `{p.id[:8]}` SGT {p.src_sgt}→{p.dst_sgt} ({p.trigger.value})"
            for p in rows
        )

    if cmd in ("approve", "reject") and len(parts) > 1:
        decision = (
            ProposalStatus.APPROVED if cmd == "approve" else ProposalStatus.REJECTED
        )
        try:
            decided = await service.decide(
                proposal_id=parts[1],
                decision=decision,
                actor=f"webex:{actor_id}",
                channel="webex",
            )
        except (ProposalConflictError, ProposalApplyError) as exc:
            return f"Cannot {cmd}: {exc}"
        except LookupError:
            return f"Proposal `{parts[1]}` not found."
        return decision_summary(decided)

    return None


app = create_app()
