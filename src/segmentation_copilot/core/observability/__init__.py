"""Observability helpers — structured logs + Prometheus metrics.

Kept deliberately lightweight: every service can `from
segmentation_copilot.core.observability import metrics, configure_logging`
and get sensible defaults without an OpenTelemetry collector running.

The Prometheus registry is process-global; services that expose
`/metrics` mount `make_metrics_app()` (FastAPI) or
`make_metrics_endpoint()` (Starlette plain).
"""

from .logging import configure_logging
from .metrics import (
    classifications_counter,
    flow_unknown_consumed_counter,
    flow_unknown_published_counter,
    make_metrics_endpoint,
    proposals_counter,
    threat_lookups_counter,
)

__all__ = [
    "classifications_counter",
    "configure_logging",
    "flow_unknown_consumed_counter",
    "flow_unknown_published_counter",
    "make_metrics_endpoint",
    "proposals_counter",
    "threat_lookups_counter",
]
