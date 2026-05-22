"""SQLAlchemy ORM models + Pydantic domain models.

ORM models (`orm.py`) are the persistence layer and back the Alembic
migrations. Pydantic domain models (`domain.py`) are the API surface —
what services accept and return, what FastAPI serializes, and what the
agent's tools work with.

Keeping them separate avoids leaking ORM concerns (sessions, lazy loads)
into the service / API layers.
"""

from . import domain, orm

__all__ = ["domain", "orm"]
