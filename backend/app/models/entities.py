"""
NETRA — Entity and observation models (§6.1).

Entities are the atomic identifiers: handles, PGP fingerprints, wallets,
emails, domains, onions, contact IDs, etc.  Observations link entities to
the events where they were seen.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base


class Entity(Base):
    """
    An extracted identifier.

    kind + normalized must be unique.  This means the same wallet address
    extracted from two different events creates ONE entity row and TWO
    observation rows.
    """

    __tablename__ = "entities"

    entity_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    kind: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment=(
            "handle | pgp | wallet | email | domain | onion | "
            "contact_id | avatar_hash | ip | favicon_hash | cert_fp | ssh_key"
        ),
    )
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    normalized: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        comment="Lowercased, stripped, canonical form for dedup",
    )
    first_seen: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )
    last_seen: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )

    # Relationships
    observations: Mapped[list["Observation"]] = relationship(back_populates="entity")
    actor_links: Mapped[list["ActorEntity"]] = relationship(back_populates="entity")
    watchlist_entries: Mapped[list["WatchlistItem"]] = relationship(back_populates="entity")

    __table_args__ = (
        UniqueConstraint("kind", "normalized", name="uq_entities_kind_normalized"),
        Index("ix_entities_kind", "kind"),
        Index("ix_entities_normalized", "normalized"),
    )


class Observation(Base):
    """Links an entity to the event where it was observed."""

    __tablename__ = "observations"

    obs_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("events.event_id", ondelete="CASCADE"),
        nullable=False,
    )
    entity_id: Mapped[str] = mapped_column(
        ForeignKey("entities.entity_id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="extracted",
        comment="extracted | author | recipient | infrastructure",
    )
    observed_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )

    # Relationships
    event: Mapped["Event"] = relationship(back_populates="observations")
    entity: Mapped["Entity"] = relationship(back_populates="observations")

    __table_args__ = (
        Index("ix_observations_event", "event_id"),
        Index("ix_observations_entity", "entity_id"),
        # Prevent duplicate observations of the same entity in the same event
        UniqueConstraint("event_id", "entity_id", "role", name="uq_obs_event_entity_role"),
    )



