"""Flow-unknown consumer loop.

Consumes `events.flow.unknown` in a consumer group, classifies the flow
via Claude, and turns the verdict into a `ProposalService.propose()`
call. Idempotency-key handling lives in the bus; this loop trusts that
two deliveries with the same payload hash will collapse / be dedup'd at
the proposal layer.

Run as one or more replicas — they share the consumer group so each
event is processed exactly once across the fleet.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from anthropic import Anthropic

from segmentation_copilot import classify as classify_mod
from segmentation_copilot.aggregator import AggregatedFlow, FlowKey
from segmentation_copilot.config import Settings
from segmentation_copilot.core import db as core_db
from segmentation_copilot.core.events import (
    STREAM_FLOW_UNKNOWN,
    STREAM_PROPOSAL_CREATED,
    EventBus,
    FlowUnknownPayload,
    ProposalCreatedPayload,
)
from segmentation_copilot.core.models.domain import ACE, ProposalTrigger
from segmentation_copilot.core.repositories.sgt import SGTRepository
from segmentation_copilot.core.services.classification import ClassificationService
from segmentation_copilot.core.services.notifier import get_notifier
from segmentation_copilot.core.services.proposal import ProposalService

CONSUMER_GROUP_FLOW_UNKNOWN = "scopilot.workers.flow_unknown.v1"


log = logging.getLogger(__name__)


def _action_for_category(category: str) -> str:
    return "deny" if category in {"business_irrelevant", "harmful"} else "permit"


async def _classify_single_flow(
    *,
    tenant_id: str,
    flow: AggregatedFlow,
    settings: Settings,
) -> tuple[str, str]:
    """Classify one flow. Honours the 7d cache before paying Claude."""
    async with core_db.session_scope() as session:
        cache_hit = await ClassificationService(session).classifications.recent_for_flow(
            tenant_id=tenant_id,
            sgt=flow.key.sgt,
            dgt=flow.key.dgt,
            protocol=flow.key.protocol,
            src_port=flow.key.src_port,
            dst_port=flow.key.dst_port,
            within=timedelta(days=settings.scheduler.classification_cache_days),
        )
        sgt_dict = await SGTRepository(session).as_dictionary(tenant_id)

    if cache_hit is not None:
        return cache_hit.category.value, cache_hit.rationale or ""

    client = (
        Anthropic(api_key=settings.anthropic.api_key)
        if settings.anthropic.api_key
        else Anthropic()
    )
    results = classify_mod.classify_batch(
        [flow], sgt_dict, client=client, model=settings.anthropic.model
    )
    if not results:
        return "default", "classifier returned no result; defaulted"
    _, category, rationale = results[0]
    return category, rationale


async def _handle_flow_unknown(
    payload: FlowUnknownPayload,
    bus: EventBus,
    settings: Settings,
) -> str | None:
    """Classify the flow and propose a rule. Returns the proposal id."""
    flow = AggregatedFlow(
        key=FlowKey(
            sgt=payload.src_sgt,
            dgt=payload.dst_sgt,
            protocol=payload.protocol,
            src_port=payload.src_port,
            dst_port=payload.dst_port,
        ),
        total_hits=payload.total_hits,
    )
    category, rationale = await _classify_single_flow(
        tenant_id=payload.tenant_id, flow=flow, settings=settings
    )
    ace = ACE(
        protocol=payload.protocol,
        src_port=payload.src_port,
        dst_port=payload.dst_port,
        action=_action_for_category(category),
        source_category=category,
    )
    async with core_db.session_scope() as session:
        proposal, created = await ProposalService(session).propose(
            tenant_id=payload.tenant_id,
            trigger=ProposalTrigger(payload.trigger),
            src_sgt=payload.src_sgt,
            dst_sgt=payload.dst_sgt,
            proposed_aces=[ace],
            rationale=f"[{category}] {rationale}",
            trigger_ref=payload.trigger_ref,
            threat_context=payload.threat_context,
        )

    if created:
        await bus.publish(
            stream=STREAM_PROPOSAL_CREATED,
            payload=ProposalCreatedPayload(
                proposal_id=proposal.id,
                tenant_id=proposal.tenant_id,
                src_sgt=proposal.src_sgt,
                dst_sgt=proposal.dst_sgt,
                trigger=proposal.trigger.value,
                created_at=proposal.created_at,
            ).model_dump(mode="json"),
            idempotency_key=f"created:{proposal.id}",
        )
        # The notifier is still the primary fan-out path for now —
        # Phase 6 may wire WebEx as a stream consumer instead.
        try:
            await get_notifier().proposal_created(proposal)
        except Exception:
            log.exception("notifier fan-out failed for proposal=%s", proposal.id)

    return proposal.id


async def run_worker(
    *,
    bus: EventBus,
    settings: Settings,
    consumer_name: str,
    stop_event: asyncio.Event | None = None,
    max_iterations: int | None = None,
) -> None:
    """Consume events.flow.unknown until stopped.

    `max_iterations` exists for tests; production passes None and the
    loop runs until `stop_event` fires.
    """
    stop_event = stop_event or asyncio.Event()
    await bus.ensure_group(stream=STREAM_FLOW_UNKNOWN, group=CONSUMER_GROUP_FLOW_UNKNOWN)
    iterations = 0
    while not stop_event.is_set():
        envelopes = await bus.consume(
            stream=STREAM_FLOW_UNKNOWN,
            group=CONSUMER_GROUP_FLOW_UNKNOWN,
            consumer=consumer_name,
            count=10,
            block_ms=1000,
        )
        for env in envelopes:
            try:
                payload = FlowUnknownPayload.model_validate(env.payload)
                await _handle_flow_unknown(payload, bus, settings)
                await bus.ack(
                    stream=STREAM_FLOW_UNKNOWN,
                    group=CONSUMER_GROUP_FLOW_UNKNOWN,
                    event_ids=[env.event_id],
                )
            except Exception:
                log.exception("flow_unknown handler failed event_id=%s", env.event_id)
                # No ack — Redis will redeliver on consumer timeout, in-memory
                # bus will move on (next_index already advanced). Phase 6
                # adds a dead-letter stream.

        iterations += 1
        if max_iterations is not None and iterations >= max_iterations:
            return
