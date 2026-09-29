"""
NETRA — Actor, persona link, and infrastructure models (§6.1).

Actors are resolved identities.  PersonaLink connects two actors with
a scored, evidence-backed link.  LinkEvidence stores the individual
evidence items that contributed to a link.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Numeric,
    SmallInteger,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base


class Actor(Base):
    """A resolved threat actor identity."""

    __tablename__ = "actors"

    actor_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    label: Mapped[str] = mapped_column(String(256), nullable=False)
    category: Mapped[str | None] = mapped_column(
        String(64),
        comment="vendor | buyer | admin | mixer | unknown",
    )
    first_seen: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )
    last_seen: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="active",
        comment="active | dormant | merged | unknown",
    )
    last_scan_at: Mapped[datetime | None] = mapped_column()

    # Relationships
    entities: Mapped[list["ActorEntity"]] = relationship(back_populates="actor")

    __table_args__ = (
        Index("ix_actors_label", "label"),
        Index("ix_actors_status", "status"),
    )


class ActorEntity(Base):
    """Many-to-many: which entities belong to which actor."""

    __tablename__ = "actor_entities"

    actor_id: Mapped[str] = mapped_column(
        ForeignKey("actors.actor_id", ondelete="CASCADE"),
        primary_key=True,
    )
    entity_id: Mapped[str] = mapped_column(
        ForeignKey("entities.entity_id", ondelete="CASCADE"),
        primary_key=True,
    )
    added_by: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="system",
        comment="system | analyst:<user_id>",
    )
    added_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )

    # Relationships
    actor: Mapped["Actor"] = relationship(back_populates="entities")
    entity: Mapped["Entity"] = relationship(back_populates="actor_links")


class PersonaLink(Base):
    """A scored link between two actors with evidence backing."""

    __tablename__ = "persona_links"

    link_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_a: Mapped[str] = mapped_column(
        ForeignKey("actors.actor_id", ondelete="CASCADE"),
        nullable=False,
    )
    actor_b: Mapped[str] = mapped_column(
        ForeignKey("actors.actor_id", ondelete="CASCADE"),
        nullable=False,
    )
    link_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="persona_migration | shared_identity | co_operator | financial_link",
    )
    score: Mapped[float] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )
    band: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="VERY_HIGH | HIGH | MODERATE | LOW | WEAK",
    )
    computed_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )
    model_version: Mapped[str | None] = mapped_column(String(64))
    analyst_status: Mapped[str] = mapped_column(
        String(32),
        default="pending",
        comment="pending | confirmed | rejected | needs_info",
    )

    # Relationships
    evidence_items: Mapped[list["LinkEvidence"]] = relationship(back_populates="link")

    __table_args__ = (
        CheckConstraint("actor_a != actor_b", name="no_self_link"),
        CheckConstraint(
            "band IN ('VERY_HIGH', 'HIGH', 'MODERATE', 'LOW', 'WEAK')",
            name="valid_band",
        ),
        CheckConstraint(
            "analyst_status IN ('pending', 'confirmed', 'rejected', 'needs_info')",
            name="valid_analyst_status",
        ),
        Index("ix_persona_links_actors", "actor_a", "actor_b"),
        Index("ix_persona_links_band", "band"),
    )


class LinkEvidence(Base):
    """Individual evidence item contributing to a persona link."""

    __tablename__ = "link_evidence"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    link_id: Mapped[str] = mapped_column(
        ForeignKey("persona_links.link_id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="pgp_fingerprint | wallet_cluster | stylometry | temporal_overlap | ...",
    )
    raw_value: Mapped[dict] = mapped_column(JSONB, default=dict)
    llr: Mapped[float] = mapped_column(
        Numeric(8, 4),
        nullable=False,
        comment="Log-likelihood ratio for this evidence item",
    )
    source_id: Mapped[str | None] = mapped_column(
        ForeignKey("sources.source_id", ondelete="SET NULL"),
    )
    reliability: Mapped[str | None] = mapped_column(
        String(1),
        comment="Admiralty reliability: A-F",
    )
    credibility: Mapped[int | None] = mapped_column(
        SmallInteger,
        comment="Admiralty credibility: 1-6",
    )
    note: Mapped[str | None] = mapped_column(Text)

    # Relationships
    link: Mapped["PersonaLink"] = relationship(back_populates="evidence_items")

    __table_args__ = (
        Index("ix_link_evidence_link", "link_id"),
    )


class InfraFinding(Base):
    """Infrastructure correlation finding: onion ↔ clearnet match."""

    __tablename__ = "infra_findings"

    finding_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    onion_entity: Mapped[str] = mapped_column(
        ForeignKey("entities.entity_id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="cert_san | favicon | banner | server_status | ssh_key | header_order | error_page",
    )
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)
    matched_clearnet: Mapped[dict] = mapped_column(JSONB, default=dict)
    confidence: Mapped[float] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )
    detected_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )
    source_id: Mapped[str] = mapped_column(
        ForeignKey("sources.source_id", ondelete="RESTRICT"),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_infra_onion", "onion_entity"),
    )


class Post(Base):
    """Forum/marketplace post for full-text search and stylometry."""

    __tablename__ = "posts"

    post_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("events.event_id", ondelete="CASCADE"),
        nullable=False,
    )
    actor_id: Mapped[str | None] = mapped_column(
        ForeignKey("actors.actor_id", ondelete="SET NULL"),
    )
    handle: Mapped[str | None] = mapped_column(String(256))
    market: Mapped[str | None] = mapped_column(String(256))
    text: Mapped[str] = mapped_column(Text, nullable=False)
    posted_at: Mapped[datetime | None] = mapped_column()

    # tsvector column for Postgres full-text search
    # Populated by a trigger or on insert
    tsv: Mapped[str | None] = mapped_column(TSVECTOR)

    __table_args__ = (
        Index("ix_posts_tsv", "tsv", postgresql_using="gin"),
        Index("ix_posts_actor", "actor_id"),
        Index("ix_posts_handle", "handle"),
        Index("ix_posts_market", "market"),
    )


class Alert(Base):
    """System-generated alert (persona migration, watchlist hit, etc.)."""

    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="persona_migration | watchlist_hit | new_actor | infra_leak",
    )
    subject: Mapped[dict] = mapped_column(JSONB, nullable=False)
    score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    status: Mapped[str] = mapped_column(
        String(32),
        default="open",
        comment="open | acknowledged | resolved | false_positive",
    )
    # created_at inherited from Base

    __table_args__ = (
        Index("ix_alerts_type", "alert_type"),
        Index("ix_alerts_status", "status"),
    )


class WatchlistItem(Base):
    """Analyst watchlist: entities to monitor for new observations."""

    __tablename__ = "watchlist"

    item_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    entity_id: Mapped[str] = mapped_column(
        ForeignKey("entities.entity_id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    # created_at inherited from Base

    # Relationships
    entity: Mapped["Entity"] = relationship(back_populates="watchlist_entries")


class AuditLog(Base):
    """
    Immutable audit trail (OWASP A09).

    Every actor view, link review, export, and source toggle is logged.
    This table should never be truncated or have rows deleted.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="user_id or 'system'",
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(256), nullable=False)
    at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)

    __table_args__ = (
        Index("ix_audit_actor", "actor"),
        Index("ix_audit_action", "action"),
        Index("ix_audit_at", "at"),
    )


class User(Base):
    """
    Local user account (OWASP A07).

    MVP uses simple local auth.  Production would integrate with
    an agency's IdP via SAML/OIDC.
    """

    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
    )
    hashed_password: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="viewer",
        comment="viewer | analyst | admin",
    )
    is_active: Mapped[bool] = mapped_column(default=True)
    last_login: Mapped[datetime | None] = mapped_column()
    failed_login_count: Mapped[int] = mapped_column(
        default=0,
        comment="OWASP A07: track failed attempts for lockout",
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        comment="Account lockout after too many failed attempts",
    )

    __table_args__ = (
        CheckConstraint(
            "role IN ('viewer', 'analyst', 'admin')",
            name="valid_user_role",
        ),
    )


