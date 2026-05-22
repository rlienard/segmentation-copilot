"""Service-layer tests.

End-to-end through the new core, using the existing log fixture but
short-circuiting the Anthropic call with a fake classifier so the test
suite stays hermetic and free.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from segmentation_copilot.aggregator import AggregatedFlow
from segmentation_copilot.core.repositories import (
    ClassificationRepository,
    MatrixVersionRepository,
    SGTRepository,
)
from segmentation_copilot.core.services import (
    BaselineService,
    ClassificationService,
    IngestionService,
    MatrixService,
)


TENANT = "test-tenant"
FIXTURE = Path(__file__).parent / "fixtures" / "sample.log"


@pytest.mark.asyncio
async def test_ingestion_from_lines_persists_events(session):
    ingestion = IngestionService(session)
    result = await ingestion.ingest_lines(
        tenant_id=TENANT, lines=FIXTURE.read_text().splitlines()
    )
    assert result.raw_lines == 7
    assert result.parsed_events == 6
    assert result.unique_sgts == [100, 200, 300, 400, 999]
    assert len(result.aggregated_flows) >= 1


def _fake_classify(flows, sgt_dict, client=None, model=None):
    # Treat everything as business_relevant for the test.
    return [(f, "business_relevant", "fixture-fake") for f in flows]


@pytest.mark.asyncio
async def test_classification_then_matrix_build(session):
    sgt = SGTRepository(session)
    await sgt.upsert(tenant_id=TENANT, sgt_id=100, name="Employees")
    await sgt.upsert(tenant_id=TENANT, sgt_id=200, name="Web")
    await sgt.upsert(tenant_id=TENANT, sgt_id=300, name="Guests")
    await sgt.upsert(tenant_id=TENANT, sgt_id=400, name="DNS")
    await sgt.upsert(tenant_id=TENANT, sgt_id=999, name="External")

    ingestion = IngestionService(session)
    result = await ingestion.ingest_lines(
        tenant_id=TENANT, lines=FIXTURE.read_text().splitlines()
    )

    with patch(
        "segmentation_copilot.core.services.classification.classify.classify_batch",
        side_effect=_fake_classify,
    ):
        counts = await ClassificationService(session).classify(
            tenant_id=TENANT,
            run_id=result.run.id,
            flows=result.aggregated_flows,
            client="fake-client",  # bypassed by the patched classify_batch
        )
    assert sum(counts.values()) == len(result.aggregated_flows)
    assert counts["business_relevant"] == len(result.aggregated_flows)

    contracts = await MatrixService(session).build(tenant_id=TENANT, run_id=result.run.id)
    assert len(contracts) >= 1
    # Every ACE should be permit since we classified everything as relevant.
    for c in contracts:
        for ace in c.aces:
            assert ace.action == "permit"

    md = await MatrixService(session).render_markdown(run_id=result.run.id)
    assert "Source SGT" in md
    assert "Employees" in md


@pytest.mark.asyncio
async def test_classification_uses_recent_cache(session):
    sgt = SGTRepository(session)
    await sgt.upsert(tenant_id=TENANT, sgt_id=100, name="Employees")
    await sgt.upsert(tenant_id=TENANT, sgt_id=200, name="Web")

    ingestion = IngestionService(session)
    first_run = await ingestion.ingest_lines(
        tenant_id=TENANT,
        lines=[
            "Jun 18 10:00:00: %RBM-6-SGACLHIT: protocol='tcp' "
            "sgt='100' dgt='200' src-port='55555' dest-port='443' "
            "logging_interval_hits='3'"
        ],
    )
    with patch(
        "segmentation_copilot.core.services.classification.classify.classify_batch",
        side_effect=_fake_classify,
    ) as mocked:
        await ClassificationService(session).classify(
            tenant_id=TENANT,
            run_id=first_run.run.id,
            flows=first_run.aggregated_flows,
        )
    assert mocked.call_count == 1

    # Second run with the same flow tuple — classification cache should
    # absorb it without a fresh classify_batch call.
    second_run = await ingestion.ingest_lines(
        tenant_id=TENANT,
        lines=[
            "Jun 19 10:00:00: %RBM-6-SGACLHIT: protocol='tcp' "
            "sgt='100' dgt='200' src-port='44444' dest-port='443' "
            "logging_interval_hits='1'"
        ],
    )
    with patch(
        "segmentation_copilot.core.services.classification.classify.classify_batch",
        side_effect=_fake_classify,
    ) as mocked:
        await ClassificationService(session).classify(
            tenant_id=TENANT,
            run_id=second_run.run.id,
            flows=second_run.aggregated_flows,
        )
    assert mocked.call_count == 0  # served from the 7d cache


@pytest.mark.asyncio
async def test_baseline_diff_against_matrix_version(session):
    matrix = MatrixVersionRepository(session)
    await matrix.create(
        tenant_id=TENANT,
        contracts={
            "contracts": [
                {
                    "src_sgt": 100, "dst_sgt": 200,
                    "aces": [
                        {"protocol": "tcp", "src_port": "any", "dst_port": "443",
                         "action": "permit"},
                    ],
                },
            ]
        },
    )
    baseline = BaselineService(session)
    from segmentation_copilot.aggregator import FlowKey

    flows = [
        AggregatedFlow(key=FlowKey(100, 200, "tcp", "any", "443"), total_hits=10),
        AggregatedFlow(key=FlowKey(100, 200, "tcp", "any", "22"), total_hits=2),
    ]
    diff = await baseline.diff(tenant_id=TENANT, flows=flows)
    assert len(diff.covered) == 1 and diff.covered[0].key.dst_port == "443"
    assert len(diff.uncovered) == 1 and diff.uncovered[0].key.dst_port == "22"
