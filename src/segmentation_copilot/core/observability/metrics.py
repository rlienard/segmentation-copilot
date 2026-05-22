"""Prometheus counters + histograms used across services.

We export a process-global registry so every counter is summed without
the caller knowing the registry exists. Mount `make_metrics_endpoint()`
on FastAPI / Starlette to expose `/metrics`.

Counters are deliberately coarse — labels are kept low-cardinality
(category names, status names — never IPs or proposal ids) so Prometheus
storage stays bounded.
"""

from __future__ import annotations

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

flow_unknown_published_counter = Counter(
    "scopilot_flow_unknown_published_total",
    "Number of events.flow.unknown published.",
    labelnames=("tenant_id", "trigger"),
)

flow_unknown_consumed_counter = Counter(
    "scopilot_flow_unknown_consumed_total",
    "Number of events.flow.unknown consumed and classified.",
    labelnames=("tenant_id", "outcome"),
)

classifications_counter = Counter(
    "scopilot_classifications_total",
    "Per-category classification counts.",
    labelnames=("tenant_id", "category"),
)

proposals_counter = Counter(
    "scopilot_proposals_total",
    "Proposal lifecycle transitions.",
    labelnames=("tenant_id", "status"),
)

threat_lookups_counter = Counter(
    "scopilot_threat_lookups_total",
    "Threat-intel lookups by provider and outcome.",
    labelnames=("provider", "outcome"),
)

# ---------------------------------------------------------------------------
# Histograms (Phase 6 baseline; downstream code will add observe() calls).
# ---------------------------------------------------------------------------

http_request_duration = Histogram(
    "scopilot_http_request_duration_seconds",
    "FastAPI request duration.",
    labelnames=("route", "method", "status_class"),
)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


def make_metrics_endpoint():
    """Return an ASGI-compatible handler that renders the global registry.

    Usage:
        from starlette.routing import Route
        app.add_route("/metrics", make_metrics_endpoint(), methods=["GET"])
    """
    from starlette.responses import Response

    async def metrics(request):  # noqa: ARG001
        return Response(content=generate_latest(),
                        media_type=CONTENT_TYPE_LATEST)

    return metrics
