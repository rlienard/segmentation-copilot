"""API-layer Pydantic schemas.

Distinct from `core.models.domain` because:
  - API requests have a different shape than persisted records (no IDs).
  - API responses sometimes wrap collections with pagination metadata.
  - We don't want every internal field on the wire.

Keeping these separate also means a domain-model change doesn't silently
break clients.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from segmentation_copilot.core.models.domain import (
    ACE,
    ClassificationRecord,
    ContractRecord,
    ProposalRecord,
    ProposalStatus,
    RunRecord,
    SGTEntryRecord,
)

# ---------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------


class CreateRunRequest(BaseModel):
    source_type: str = "inline"
    source_config: dict[str, Any] | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    trigger: str = "manual"


class IngestLinesRequest(BaseModel):
    lines: list[str] = Field(min_length=1)


class IngestSummary(BaseModel):
    run_id: int
    raw_lines: int
    parsed_events: int
    unique_flows: int
    unique_sgts: list[int]


class ClassifyResponse(BaseModel):
    run_id: int
    counts: dict[str, int]


class RunResponse(BaseModel):
    run: RunRecord


class RunsListResponse(BaseModel):
    runs: list[RunRecord]


class ClassificationsResponse(BaseModel):
    classifications: list[ClassificationRecord]


# ---------------------------------------------------------------------------
# Matrix
# ---------------------------------------------------------------------------


class MatrixResponse(BaseModel):
    run_id: int
    contracts: list[ContractRecord]
    markdown: str


# ---------------------------------------------------------------------------
# SGT dictionary
# ---------------------------------------------------------------------------


class SGTUpsertRequest(BaseModel):
    sgt_id: int
    name: str


class SGTBulkUpsertRequest(BaseModel):
    entries: dict[str, str] = Field(
        description='Mapping of "<sgt_id>": "<name>", e.g. {"100": "Employees"}',
    )


class SGTListResponse(BaseModel):
    entries: list[SGTEntryRecord]


class MissingSGTsResponse(BaseModel):
    missing: list[int]


# ---------------------------------------------------------------------------
# Proposals
# ---------------------------------------------------------------------------


class ProposalCreateRequest(BaseModel):
    src_sgt: int
    dst_sgt: int
    proposed_aces: list[ACE]
    rationale: str
    trigger: str = "manual"
    trigger_ref: str | None = None
    run_id: int | None = None
    expires_in_hours: int = 24


class ProposalDecideRequest(BaseModel):
    decision: ProposalStatus
    """Must be APPROVED or REJECTED."""


class ProposalsListResponse(BaseModel):
    proposals: list[ProposalRecord]


class ProposalResponse(BaseModel):
    proposal: ProposalRecord
