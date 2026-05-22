"""Service orchestration layer.

Each service is a thin façade that:
  - opens an async session (or accepts one for nesting),
  - drives one or more repositories,
  - wraps pure-function logic from the existing `parser`, `aggregator`,
    `contracts`, `classify` modules,
  - returns Pydantic domain models.

Services are the only thing the agent's tools should call. They are
idempotent — every method takes a `run_id` (or natural key) and produces
the same outcome on rerun.
"""

from .baseline import BaselineService
from .classification import ClassificationService
from .ingestion import IngestionService
from .matrix import MatrixService

__all__ = ["BaselineService", "ClassificationService", "IngestionService", "MatrixService"]
