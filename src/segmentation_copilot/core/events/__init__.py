"""Event bus — Redis Streams in prod, in-memory fake for tests.

`build_bus()` picks the right implementation from settings. Every event
carries an `idempotency_key` so the bus can dedupe republishes without
involving the consumer.
"""

from .bus import EventBus, EventEnvelope, InMemoryBus, build_bus
from .streams import (
    EVENT_TTL_SECONDS,
    STREAM_FLOW_UNKNOWN,
    STREAM_PROPOSAL_CREATED,
    STREAM_PROPOSAL_DECIDED,
    STREAM_SCAN_SCHEDULED,
    FlowUnknownPayload,
    ProposalCreatedPayload,
    ProposalDecidedPayload,
    ScanScheduledPayload,
)

__all__ = [
    "EVENT_TTL_SECONDS",
    "EventBus",
    "EventEnvelope",
    "FlowUnknownPayload",
    "InMemoryBus",
    "ProposalCreatedPayload",
    "ProposalDecidedPayload",
    "STREAM_FLOW_UNKNOWN",
    "STREAM_PROPOSAL_CREATED",
    "STREAM_PROPOSAL_DECIDED",
    "STREAM_SCAN_SCHEDULED",
    "ScanScheduledPayload",
    "build_bus",
]
