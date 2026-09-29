"""
NETRA — Models package.

Import all models here so that:
1. SQLAlchemy can resolve all forward references (string-based relationships)
2. Alembic can see all models for autogeneration
3. Circular imports between model files are avoided
"""

# Import order matters: base first, then tables in FK dependency order
from backend.app.models.base import Base  # noqa: F401
from backend.app.models.sources import Source  # noqa: F401
from backend.app.models.events import PolicyDecision, Event, Evidence, MerkleBatch  # noqa: F401
from backend.app.models.entities import Entity, Observation  # noqa: F401
from backend.app.models.actors import (  # noqa: F401
    Actor,
    ActorEntity,
    PersonaLink,
    LinkEvidence,
    InfraFinding,
    Post,
    Alert,
    WatchlistItem,
    AuditLog,
    User,
)
