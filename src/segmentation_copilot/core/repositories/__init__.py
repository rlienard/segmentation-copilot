"""Async repository layer — the only place SQLAlchemy ORM objects exist.

Repositories accept primitive values + Pydantic domain models and return
detached Pydantic records. This keeps ORM sessions out of the service /
API / agent layers.
"""

from .classifications import ClassificationRepository
from .contracts import ContractRepository
from .events import FlowEventRepository
from .matrix import MatrixVersionRepository
from .proposals import ProposalRepository
from .runs import RunRepository
from .sgt import SGTRepository

__all__ = [
    "ClassificationRepository",
    "ContractRepository",
    "FlowEventRepository",
    "MatrixVersionRepository",
    "ProposalRepository",
    "RunRepository",
    "SGTRepository",
]
