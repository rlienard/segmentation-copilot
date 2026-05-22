"""Stream names + payload schemas.

One file lists every stream + its envelope so a reader can audit the
event surface in one place. Stream names embed a version suffix so future
schema breaks can coexist with the old consumers during a rollout.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel

STREAM_SCAN_SCHEDULED = "scopilot.events.scan.scheduled.v1"
STREAM_FLOW_UNKNOWN = "scopilot.events.flow.unknown.v1"
STREAM_PROPOSAL_CREATED = "scopilot.events.proposal.created.v1"
STREAM_PROPOSAL_DECIDED = "scopilot.events.proposal.decided.v1"

# Idempotency keys live in Redis for this long. Long enough to swallow a
# duplicate burst from a misbehaving publisher; short enough to bound key
# growth. 24h matches the proposal expiry default.
EVENT_TTL_SECONDS = 24 * 3600


class ScanScheduledPayload(BaseModel):
    """Scheduler tick — asks a worker to run a baseline scan for a tenant."""

    tenant_id: str
    since: datetime | None = None
    scheduled_at: datetime


class FlowUnknownPayload(BaseModel):
    """A flow not covered by the latest matrix_version baseline.

    Fired by either the scheduler (baseline scan) or the threat-daemon
    (real-time tail). The worker classifies the flow and turns it into a
    rule proposal.
    """

    tenant_id: str
    src_sgt: int
    dst_sgt: int
    protocol: str
    src_port: str
    dst_port: str
    total_hits: int
    sample_src_ips: list[str] = []
    sample_dst_ips: list[str] = []
    trigger: str = "scheduled"
    """One of: scheduled, threat."""
    trigger_ref: str | None = None
    threat_context: dict[str, Any] | None = None
    detected_at: datetime


class ProposalCreatedPayload(BaseModel):
    proposal_id: str
    tenant_id: str
    src_sgt: int
    dst_sgt: int
    trigger: str
    created_at: datetime


class ProposalDecidedPayload(BaseModel):
    proposal_id: str
    tenant_id: str
    status: str
    actor: str
    channel: str
    decided_at: datetime
