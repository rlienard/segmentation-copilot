"""Pydantic domain models — the public surface of the core library.

Services accept and return these; FastAPI serializes them; the agent's
tools operate on them. They are deliberately decoupled from the ORM so a
detached `RunRecord` can be passed across async boundaries without a live
session attached.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ProposalStatus(str, Enum):
    PENDING = "pending"
    NOTIFIED = "notified"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    APPLIED = "applied"
    FAILED = "failed"


class ProposalTrigger(str, Enum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    THREAT = "threat"


class FlowCategory(str, Enum):
    BUSINESS_RELEVANT = "business_relevant"
    DEFAULT = "default"
    BUSINESS_IRRELEVANT = "business_irrelevant"
    HARMFUL = "harmful"


class _ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class RunRecord(_ORMModel):
    id: int
    tenant_id: str
    started_at: datetime
    source_type: str
    source_config: dict[str, Any] | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    status: str
    trigger: str


class FlowEventRecord(_ORMModel):
    id: int
    run_id: int
    tenant_id: str
    ts: datetime | None
    ingestion_ts: datetime
    sgt: int
    dgt: int
    protocol: str
    src_port: str
    dst_port: str
    src_ip: str | None = None
    dst_ip: str | None = None
    hits: int
    sgacl_name: str | None = None
    observed_action: str | None = None


class ClassificationRecord(_ORMModel):
    id: int
    run_id: int
    tenant_id: str
    sgt: int
    dgt: int
    protocol: str
    src_port: str
    dst_port: str
    category: FlowCategory
    rationale: str | None = None
    total_hits: int
    classified_at: datetime


class ACE(BaseModel):
    protocol: str
    src_port: str
    dst_port: str
    action: str
    source_category: str | None = None


class ContractRecord(_ORMModel):
    id: int
    run_id: int
    tenant_id: str
    src_sgt: int
    dst_sgt: int
    src_sgt_name: str
    dst_sgt_name: str
    name: str
    aces: list[ACE] = Field(default_factory=list)


class SGTEntryRecord(_ORMModel):
    tenant_id: str
    sgt_id: int
    name: str
    updated_at: datetime


class ProposalRecord(_ORMModel):
    id: str
    tenant_id: str
    run_id: int | None
    trigger: ProposalTrigger
    trigger_ref: str | None
    src_sgt: int
    dst_sgt: int
    proposed_aces: list[ACE]
    rationale: str
    threat_context: dict[str, Any] | None = None
    status: ProposalStatus
    created_at: datetime
    notified_at: datetime | None
    decided_at: datetime | None
    decided_by: str | None
    decision_channel: str | None
    expires_at: datetime
    idempotency_key: str


class ThreatVerdictRecord(_ORMModel):
    provider: str
    target: str
    score: int
    categories: list[str]
    fetched_at: datetime
    raw: dict[str, Any] | None = None


class MatrixVersionRecord(_ORMModel):
    id: int
    tenant_id: str
    parent_id: int | None
    contracts: dict[str, Any]
    created_at: datetime
    created_by: str | None
    note: str | None


__all__ = [
    "ACE",
    "ClassificationRecord",
    "ContractRecord",
    "FlowCategory",
    "FlowEventRecord",
    "MatrixVersionRecord",
    "ProposalRecord",
    "ProposalStatus",
    "ProposalTrigger",
    "RunRecord",
    "SGTEntryRecord",
    "ThreatVerdictRecord",
]
