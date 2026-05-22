"""Classification service — Claude-driven flow classification with a
recent-flow cache that lets the scheduler skip already-classified flows."""

from __future__ import annotations

from datetime import timedelta

from anthropic import Anthropic
from sqlalchemy.ext.asyncio import AsyncSession

from ... import aggregator, classify
from ...config import get_settings
from ..models.domain import FlowCategory
from ..repositories.classifications import ClassificationRepository
from ..repositories.sgt import SGTRepository


class ClassificationService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.classifications = ClassificationRepository(session)
        self.sgt = SGTRepository(session)

    async def classify(
        self,
        *,
        tenant_id: str,
        run_id: int,
        flows: list[aggregator.AggregatedFlow],
        client: Anthropic | None = None,
        cache_window: timedelta | None = None,
    ) -> dict[str, int]:
        """Classify the supplied aggregated flows for the given run.

        Flows already classified for this tenant within `cache_window`
        are skipped — their cached classification is upserted into this
        run so the matrix is complete without paying for re-classification.
        Returns category counts for the run.
        """
        if not flows:
            return {c.value: 0 for c in FlowCategory}

        settings = get_settings()
        cache_window = cache_window or timedelta(days=settings.scheduler.classification_cache_days)

        sgt_dict = await self.sgt.as_dictionary(tenant_id)

        cached: list[tuple[aggregator.AggregatedFlow, str, str]] = []
        to_classify: list[aggregator.AggregatedFlow] = []
        for flow in flows:
            hit = await self.classifications.recent_for_flow(
                tenant_id=tenant_id,
                sgt=flow.key.sgt,
                dgt=flow.key.dgt,
                protocol=flow.key.protocol,
                src_port=flow.key.src_port,
                dst_port=flow.key.dst_port,
                within=cache_window,
            )
            if hit is not None:
                cached.append((flow, hit.category.value, hit.rationale or ""))
            else:
                to_classify.append(flow)

        fresh: list[tuple[aggregator.AggregatedFlow, str, str]] = []
        if to_classify:
            anthropic_client = client or _build_anthropic_client()
            batch_size = settings.scheduler.flow_batch_size
            for chunk_start in range(0, len(to_classify), batch_size):
                chunk = to_classify[chunk_start : chunk_start + batch_size]
                fresh.extend(
                    classify.classify_batch(
                        chunk,
                        sgt_dict,
                        client=anthropic_client,
                        model=settings.anthropic.model,
                    )
                )

        await self.classifications.upsert_batch(
            run_id=run_id, tenant_id=tenant_id, classified=cached + fresh
        )
        return await self.classifications.counts_for_run(run_id)


def _build_anthropic_client() -> Anthropic:
    api_key = get_settings().anthropic.api_key
    return Anthropic(api_key=api_key) if api_key else Anthropic()
