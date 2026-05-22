"""FastMCP server + tool registry shared by stdio and HTTP transports.

Each tool is a thin async wrapper around an existing `core.services.*`
operation. Tools take an explicit `tenant_id` so the same server instance
can serve multiple tenants if the front-door auth provides one — for
single-tenant deployments, leave it at the default.

`register_sgt_name` and `set_sgt_dictionary_bulk` are gated by the
`allow_dictionary_edit` setting; the MCP client is not the right place
for an unprivileged user to silently rename SGTs.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from segmentation_copilot.config import get_settings
from segmentation_copilot.core import db as core_db
from segmentation_copilot.core.models.domain import (
    ACE,
    ProposalStatus,
    ProposalTrigger,
)
from segmentation_copilot.core.repositories.classifications import (
    ClassificationRepository,
)
from segmentation_copilot.core.repositories.events import FlowEventRepository
from segmentation_copilot.core.repositories.proposals import ProposalRepository
from segmentation_copilot.core.repositories.runs import RunRepository
from segmentation_copilot.core.repositories.sgt import SGTRepository
from segmentation_copilot.core.services import (
    ClassificationService,
    IngestionService,
    MatrixService,
)
from segmentation_copilot.core.services.proposal import (
    ProposalApplyError,
    ProposalConflictError,
    ProposalService,
)
from segmentation_copilot.core.threat.aggregator import build_default_aggregator

log = logging.getLogger(__name__)


SERVER_INSTRUCTIONS = """\
Segmentation Copilot MCP server.

Tools fall into four groups:
  - Runs: start_run, ingest_lines, classify_run, build_matrix, list_runs,
    get_run, list_missing_sgts.
  - SGT dictionary: list_sgt_entries, set_sgt_name (gated).
  - Proposals: list_proposals, get_proposal, approve_proposal,
    reject_proposal.
  - Threat intel: lookup_threat_intel.

Always pass an explicit run_id for any per-run operation. Tenant defaults
to the server's configured tenant; multi-tenant deployments may pass
tenant_id explicitly.
"""


def build_server(*, allow_dictionary_edit: bool | None = None) -> FastMCP:
    settings = get_settings()
    allow_edit = (
        allow_dictionary_edit
        if allow_dictionary_edit is not None
        else False  # default: read-only dictionary; flip via CLI flag.
    )
    default_tenant = settings.default_tenant_id

    mcp = FastMCP(name="segmentation-copilot", instructions=SERVER_INSTRUCTIONS)

    # ------------------------------------------------------------------
    # Runs
    # ------------------------------------------------------------------

    @mcp.tool()
    async def start_run(
        source_type: str = "inline",
        trigger: str = "manual",
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a new analysis run. Returns `{run_id, started_at}`."""
        tenant = tenant_id or default_tenant
        async with core_db.session_scope() as session:
            run = await RunRepository(session).create(
                tenant_id=tenant, source_type=source_type, trigger=trigger,
            )
        return {"run_id": run.id, "started_at": run.started_at.isoformat()}

    @mcp.tool()
    async def ingest_lines(
        run_id: int,
        lines: list[str],
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Ingest raw syslog lines into an existing run."""
        tenant = tenant_id or default_tenant
        async with core_db.session_scope() as session:
            result = await IngestionService(session).ingest_lines(
                tenant_id=tenant, lines=lines, run_id=run_id,
            )
        return result.summary()

    @mcp.tool()
    async def list_missing_sgts(
        run_id: int, tenant_id: str | None = None
    ) -> list[int]:
        """SGT IDs observed in this run that aren't in the dictionary."""
        tenant = tenant_id or default_tenant
        async with core_db.session_scope() as session:
            ids = await FlowEventRepository(session).distinct_sgt_dgt_for_run(run_id)
            return await SGTRepository(session).missing_ids(
                tenant_id=tenant, ids=ids
            )

    @mcp.tool()
    async def classify_run(
        run_id: int, tenant_id: str | None = None
    ) -> dict[str, int]:
        """Classify all aggregated flows for the run. Returns category counts."""
        tenant = tenant_id or default_tenant
        async with core_db.session_scope() as session:
            ingestion = IngestionService(session)
            flows = await ingestion.aggregated_for_run(run_id)
            if not flows:
                return {}
            counts = await ClassificationService(session).classify(
                tenant_id=tenant, run_id=run_id, flows=flows,
            )
        return counts

    @mcp.tool()
    async def build_matrix(
        run_id: int, tenant_id: str | None = None
    ) -> dict[str, Any]:
        """Build (or rebuild) the contract matrix for a run. Returns markdown + JSON."""
        tenant = tenant_id or default_tenant
        async with core_db.session_scope() as session:
            svc = MatrixService(session)
            contracts = await svc.build(tenant_id=tenant, run_id=run_id)
            md = await svc.render_markdown(run_id=run_id)
        return {
            "run_id": run_id,
            "markdown": md,
            "contracts": [c.model_dump(mode="json") for c in contracts],
        }

    @mcp.tool()
    async def list_runs(
        limit: int = 20, tenant_id: str | None = None
    ) -> list[dict[str, Any]]:
        """List recent runs for the tenant."""
        tenant = tenant_id or default_tenant
        async with core_db.session_scope() as session:
            runs = await RunRepository(session).list_for_tenant(tenant, limit=limit)
        return [r.model_dump(mode="json") for r in runs]

    @mcp.tool()
    async def get_run(
        run_id: int, tenant_id: str | None = None
    ) -> dict[str, Any] | None:
        """Fetch a single run by id."""
        tenant = tenant_id or default_tenant
        async with core_db.session_scope() as session:
            run = await RunRepository(session).get(run_id)
        if run is None or run.tenant_id != tenant:
            return None
        return run.model_dump(mode="json")

    @mcp.tool()
    async def list_classifications(
        run_id: int, tenant_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Per-flow classifications for a run."""
        tenant = tenant_id or default_tenant
        async with core_db.session_scope() as session:
            run = await RunRepository(session).get(run_id)
            if run is None or run.tenant_id != tenant:
                return []
            records = await ClassificationRepository(session).list_for_run(run_id)
        return [c.model_dump(mode="json") for c in records]

    # ------------------------------------------------------------------
    # SGT dictionary
    # ------------------------------------------------------------------

    @mcp.tool()
    async def list_sgt_entries(
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List the SGT id→name dictionary for the tenant."""
        tenant = tenant_id or default_tenant
        async with core_db.session_scope() as session:
            entries = await SGTRepository(session).list_for_tenant(tenant)
        return [e.model_dump(mode="json") for e in entries]

    if allow_edit:

        @mcp.tool()
        async def set_sgt_name(
            sgt_id: int, name: str, tenant_id: str | None = None
        ) -> dict[str, Any]:
            """Upsert one SGT id→name. Only available with --allow-dictionary-edit."""
            tenant = tenant_id or default_tenant
            async with core_db.session_scope() as session:
                record = await SGTRepository(session).upsert(
                    tenant_id=tenant, sgt_id=sgt_id, name=name
                )
            return record.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Proposals
    # ------------------------------------------------------------------

    @mcp.tool()
    async def list_proposals(
        status: str | None = None,
        limit: int = 50,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List rule proposals. `status` filters by lifecycle state."""
        tenant = tenant_id or default_tenant
        status_filter = ProposalStatus(status) if status else None
        async with core_db.session_scope() as session:
            proposals = await ProposalRepository(session).list_for_tenant(
                tenant_id=tenant, status=status_filter, limit=limit,
            )
        return [p.model_dump(mode="json") for p in proposals]

    @mcp.tool()
    async def get_proposal(
        proposal_id: str, tenant_id: str | None = None
    ) -> dict[str, Any] | None:
        """Fetch a proposal by id."""
        tenant = tenant_id or default_tenant
        async with core_db.session_scope() as session:
            proposal = await ProposalRepository(session).get(proposal_id)
        if proposal is None or proposal.tenant_id != tenant:
            return None
        return proposal.model_dump(mode="json")

    @mcp.tool()
    async def create_proposal(
        src_sgt: int,
        dst_sgt: int,
        proposed_aces: list[dict[str, Any]],
        rationale: str,
        run_id: int | None = None,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Create (or storm-collapse into) a rule proposal."""
        tenant = tenant_id or default_tenant
        aces = [ACE(**a) for a in proposed_aces]
        async with core_db.session_scope() as session:
            proposal, _ = await ProposalService(session).propose(
                tenant_id=tenant,
                trigger=ProposalTrigger.MANUAL,
                src_sgt=src_sgt,
                dst_sgt=dst_sgt,
                proposed_aces=aces,
                rationale=rationale,
                run_id=run_id,
            )
        return proposal.model_dump(mode="json")

    @mcp.tool()
    async def approve_proposal(
        proposal_id: str,
        actor: str,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Approve a proposal — creates a new matrix_version. Optimistic-locked."""
        return await _decide(proposal_id, ProposalStatus.APPROVED, actor,
                             tenant_id or default_tenant)

    @mcp.tool()
    async def reject_proposal(
        proposal_id: str,
        actor: str,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Reject a proposal."""
        return await _decide(proposal_id, ProposalStatus.REJECTED, actor,
                             tenant_id or default_tenant)

    async def _decide(proposal_id: str, decision: ProposalStatus, actor: str,
                      tenant: str) -> dict[str, Any]:
        async with core_db.session_scope() as session:
            service = ProposalService(session)
            existing = await service.proposals.get(proposal_id)
            if existing is None or existing.tenant_id != tenant:
                return {"error": "proposal not found"}
            try:
                decided = await service.decide(
                    proposal_id=proposal_id, decision=decision,
                    actor=actor, channel="mcp",
                )
            except ProposalConflictError as exc:
                return {"error": "conflict", "detail": str(exc)}
            except ProposalApplyError as exc:
                return {"error": "apply_failed", "detail": str(exc)}
        return decided.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Threat intel
    # ------------------------------------------------------------------

    @mcp.tool()
    async def lookup_threat_intel(
        ip: str,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Run the configured threat-intel providers against an IP."""
        tenant = tenant_id or default_tenant
        aggregator = build_default_aggregator()
        if aggregator is None:
            return {"error": "no threat-intel providers configured"}
        try:
            decision = await aggregator.lookup_ip(tenant_id=tenant, ip=ip)
        finally:
            await aggregator.aclose()
        return {
            "ip": decision.target,
            "is_malicious": decision.is_malicious,
            "max_score": decision.max_score,
            "triggering_providers": decision.triggering_providers,
            "verdicts": [
                {
                    "provider": v.provider,
                    "score": v.score,
                    "categories": v.categories,
                }
                for v in decision.verdicts
            ],
        }

    return mcp
