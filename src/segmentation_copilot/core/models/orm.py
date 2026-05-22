"""SQLAlchemy 2.0 ORM models.

These map 1:1 to the Alembic schema. `tenant_id` is on every tenant-scoped
table from day one (backfilling later is painful, even if today there's
only one tenant). Natural unique keys are defined for upsert idempotency.

Tables introduced in Phase 1:

* runs                    — one analysis pass
* flow_events             — raw parsed SGACLHIT entries
* flow_classifications    — per-flow category + rationale
* contracts / contract_aces — TrustSec matrix output
* sgt_entries             — per-tenant SGT id→name dictionary
* matrix_versions         — immutable approved baselines (Phase 3 uses them)
* proposals / proposal_audit — agent rule proposals + approval audit trail
* threat_lookups          — record-of-truth for threat-intel verdicts (Phase 5)
* audit_events            — append-only system audit log
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _utcnow() -> datetime:
    return datetime.utcnow()


# SQLite only supports autoincrement on INTEGER PRIMARY KEY (not BIGINT).
# Use BigInt on Postgres / MySQL where row volumes warrant it; degrade to
# Integer on SQLite so dev/tests get working auto-incrementing IDs.
BigIntPK = BigInteger().with_variant(Integer, "sqlite")


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_config: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    window_start: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="in_progress")
    trigger: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    """One of: manual, scheduled, threat."""

    flow_events: Mapped[list[FlowEvent]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    classifications: Mapped[list[FlowClassification]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    contracts: Mapped[list[Contract]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class FlowEvent(Base):
    __tablename__ = "flow_events"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ts: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ingestion_ts: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)
    """Wall-clock time when we ingested this line. Authoritative for ordering
    in the 24/7 daemon (syslog timestamps lack year/TZ)."""
    sgt: Mapped[int] = mapped_column(Integer, nullable=False)
    dgt: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    src_port: Mapped[str] = mapped_column(String(16), nullable=False)
    dst_port: Mapped[str] = mapped_column(String(16), nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hits: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    sgacl_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    observed_action: Mapped[str | None] = mapped_column(String(32), nullable=True)

    run: Mapped[Run] = relationship(back_populates="flow_events")

    __table_args__ = (
        Index("ix_flow_events_tenant_sgt_dgt", "tenant_id", "sgt", "dgt"),
    )


class FlowClassification(Base):
    __tablename__ = "flow_classifications"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sgt: Mapped[int] = mapped_column(Integer, nullable=False)
    dgt: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    src_port: Mapped[str] = mapped_column(String(16), nullable=False)
    dst_port: Mapped[str] = mapped_column(String(16), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    classified_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)

    run: Mapped[Run] = relationship(back_populates="classifications")

    __table_args__ = (
        UniqueConstraint(
            "run_id", "sgt", "dgt", "protocol", "src_port", "dst_port",
            name="uq_classification_run_flow",
        ),
        Index(
            "ix_classifications_flow_cache",
            "tenant_id", "sgt", "dgt", "protocol", "src_port", "dst_port", "classified_at",
        ),
    )


class Contract(Base):
    __tablename__ = "contracts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    src_sgt: Mapped[int] = mapped_column(Integer, nullable=False)
    dst_sgt: Mapped[int] = mapped_column(Integer, nullable=False)
    src_sgt_name: Mapped[str] = mapped_column(String(128), nullable=False)
    dst_sgt_name: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)

    run: Mapped[Run] = relationship(back_populates="contracts")
    aces: Mapped[list[ContractACE]] = relationship(
        back_populates="contract", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("run_id", "src_sgt", "dst_sgt", name="uq_contract_run_pair"),
    )


class ContractACE(Base):
    __tablename__ = "contract_aces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(
        ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    src_port: Mapped[str] = mapped_column(String(16), nullable=False)
    dst_port: Mapped[str] = mapped_column(String(16), nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    source_category: Mapped[str | None] = mapped_column(String(32), nullable=True)

    contract: Mapped[Contract] = relationship(back_populates="aces")


class SGTEntry(Base):
    __tablename__ = "sgt_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sgt_id: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow, onupdate=_utcnow
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "sgt_id", name="uq_sgt_tenant_id"),
    )


class MatrixVersion(Base):
    """Immutable approved matrix baseline. Each approval creates a new row;
    rollback is a pointer flip in `tenant_matrix_pointer` (Phase 3)."""

    __tablename__ = "matrix_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("matrix_versions.id"), nullable=True
    )
    contracts: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    """Snapshot of the full matrix as JSON for cheap diffing."""
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)
    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


class Proposal(Base):
    __tablename__ = "proposals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    run_id: Mapped[int | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    trigger: Mapped[str] = mapped_column(String(32), nullable=False)
    """One of: manual, scheduled, threat."""
    trigger_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    src_sgt: Mapped[int] = mapped_column(Integer, nullable=False)
    dst_sgt: Mapped[int] = mapped_column(Integer, nullable=False)
    proposed_aces: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    threat_context: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    """pending → notified → (approved | rejected | expired); approved → applied | failed."""
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)
    notified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decision_channel: Mapped[str | None] = mapped_column(String(32), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_proposal_idem"),
        Index("ix_proposals_pending_pair", "tenant_id", "src_sgt", "dst_sgt", "status"),
    )


class ProposalAudit(Base):
    __tablename__ = "proposal_audit"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    proposal_id: Mapped[str] = mapped_column(
        ForeignKey("proposals.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)


class ThreatLookup(Base):
    __tablename__ = "threat_lookups"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    """IP, CIDR, or domain that was looked up."""
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    categories: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    raw: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)

    __table_args__ = (
        Index("ix_threat_target_provider", "target", "provider", "fetched_at"),
    )


class AuditEvent(Base):
    """Append-only system audit log. Postgres trigger blocks UPDATE/DELETE
    in production (Phase 6); in dev SQLite the table is simply append-only
    by convention."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)
    actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    channel: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    before: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    after: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


__all__ = [
    "Base",
    "Run",
    "FlowEvent",
    "FlowClassification",
    "Contract",
    "ContractACE",
    "SGTEntry",
    "MatrixVersion",
    "Proposal",
    "ProposalAudit",
    "ThreatLookup",
    "AuditEvent",
]
