"""
NETRA — Event, policy decision, and evidence models (§6.1).

Events are immutable records of collected observations.
Policy decisions record every allow/block before collection.
Evidence rows + Merkle batches provide tamper-evident provenance.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base


class PolicyDecision(Base):
    """Record of every policy gate decision — allow, block, or redact_allow."""

    __tablename__ = "policy_decisions"

    decision_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_id: Mapped[str] = mapped_column(
        ForeignKey("sources.source_id", ondelete="RESTRICT"),
        nullable=False,
    )
    event_id: Mapped[str | None] = mapped_column(
        String(36),
        comment="Null if blocked (no event created)",
    )
    rule_hits: Mapped[dict] = mapped_column(JSONB, default=dict)
    decision: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    decided_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )

    __table_args__ = (
        CheckConstraint(
            "decision IN ('allow', 'block', 'redact_allow')",
            name="valid_decision",
        ),
        Index("ix_policy_decisions_source", "source_id"),
        Index("ix_policy_decisions_decided_at", "decided_at"),
    )


class Event(Base):
    """An observed item that passed the policy + safety gates."""

    __tablename__ = "events"

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_id: Mapped[str] = mapped_column(
        ForeignKey("sources.source_id", ondelete="RESTRICT"),
        nullable=False,
    )
    mode: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="live | replay | authorized",
    )
    observed_at: Mapped[datetime] = mapped_column(nullable=False)
    collected_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )
    content_hash: Mapped[str] = mapped_column(
        String(71),
        nullable=False,
        unique=True,
        comment="sha256:hex — also serves as dedup key",
    )
    payload_ref: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        comment="s3://netra-snapshots/...",
    )
    language: Mapped[str] = mapped_column(String(8), default="en")
    raw_metadata: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Relationships
    observations: Mapped[list["Observation"]] = relationship(back_populates="event")
    evidence: Mapped["Evidence | None"] = relationship(back_populates="event")

    __table_args__ = (
        Index("ix_events_source", "source_id"),
        Index("ix_events_observed_at", "observed_at"),
        Index("ix_events_content_hash", "content_hash"),
    )


class Evidence(Base):
    """Provenance record: links an event to its content hash and Merkle batch."""

    __tablename__ = "evidence"

    evidence_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("events.event_id", ondelete="CASCADE"),
        nullable=False,
    )
    content_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    merkle_batch_id: Mapped[str | None] = mapped_column(
        ForeignKey("merkle_batches.batch_id", ondelete="SET NULL"),
    )
    collected_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )
    source_id: Mapped[str] = mapped_column(
        ForeignKey("sources.source_id", ondelete="RESTRICT"),
        nullable=False,
    )

    # Relationships
    event: Mapped["Event"] = relationship(back_populates="evidence")
    batch: Mapped["MerkleBatch | None"] = relationship(back_populates="leaves")

    __table_args__ = (
        Index("ix_evidence_event", "event_id"),
        Index("ix_evidence_batch", "merkle_batch_id"),
    )


class MerkleBatch(Base):
    """A batch of evidence hashes combined into one Merkle root for provenance."""

    __tablename__ = "merkle_batches"

    batch_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    root_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    leaf_count: Mapped[int] = mapped_column(Integer, nullable=False)
    # created_at inherited from Base
    anchor_ref: Mapped[str | None] = mapped_column(
        String(256),
        comment="OpenTimestamps or testnet tx ref (stretch)",
    )
    anchor_type: Mapped[str | None] = mapped_column(
        String(64),
        comment="opentimestamps | btc_testnet | eth_sepolia",
    )

    # Relationships
    leaves: Mapped[list["Evidence"]] = relationship(back_populates="batch")


