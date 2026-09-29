"""
NETRA — Source registry model (§6.1 sources table).

The source registry is the control point for all collection.
No adapter may collect from a source without a registry entry
with authorization_status = 'approved' or 'authorized'.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, CheckConstraint, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base


class Source(Base):
    """Registered data source — the gate for all collection."""

    __tablename__ = "sources"

    source_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    source_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="synthetic | replay | osint_feed | clearnet_intel | blockchain | discovery | lab | authorized",
    )
    collection_method: Mapped[str | None] = mapped_column(String(256))
    authorization_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="approved",
        comment="approved | authorized | disabled",
    )
    authorization_ref: Mapped[str | None] = mapped_column(
        String(512),
        comment="Required for 'authorized' sources — signed JWT reference",
    )
    permitted_use: Mapped[str | None] = mapped_column(Text)
    retention_days: Mapped[int] = mapped_column(default=365)
    pii_policy: Mapped[str | None] = mapped_column(String(256))
    reliability_grade: Mapped[str] = mapped_column(
        String(1),
        default="C",
        comment="Admiralty reliability: A-F",
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scan_at: Mapped[datetime | None] = mapped_column()
    # created_at inherited from Base

    __table_args__ = (
        CheckConstraint(
            "authorization_status IN ('approved', 'authorized', 'disabled')",
            name="valid_auth_status",
        ),
        CheckConstraint(
            "reliability_grade IN ('A', 'B', 'C', 'D', 'E', 'F')",
            name="valid_reliability_grade",
        ),
        # If authorized, must have a reference (OWASP A01 — access control)
        CheckConstraint(
            "(authorization_status != 'authorized') OR (authorization_ref IS NOT NULL)",
            name="authorized_needs_ref",
        ),
    )
