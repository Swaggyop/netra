"""
NETRA — Sources API (§14).

Registry of all data sources with authorization status, grades,
and toggle capability (admin only, audit-logged).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.deps import CurrentUser, DbSession, RequireAdmin, require_role
from backend.app.core.security import AuditAction, Role, build_audit_entry
from backend.app.models.actors import AuditLog
from backend.app.models.sources import Source

router = APIRouter(prefix="/sources", tags=["sources"])


class SourceResponse(BaseModel):
    source_id: str
    name: str
    source_type: str
    authorization_status: str
    reliability_grade: str
    enabled: bool
    retention_days: int
    pii_policy: str | None
    last_scan_at: datetime | None
    created_at: datetime


@router.get("", response_model=list[SourceResponse])
async def list_sources(
    db: DbSession,
    current_user: CurrentUser,
) -> list[SourceResponse]:
    """List all registered sources."""
    result = await db.execute(select(Source).order_by(Source.source_id))
    sources = result.scalars().all()
    return [
        SourceResponse(
            source_id=s.source_id,
            name=s.name,
            source_type=s.source_type,
            authorization_status=s.authorization_status,
            reliability_grade=s.reliability_grade,
            enabled=s.enabled,
            retention_days=s.retention_days,
            pii_policy=s.pii_policy,
            last_scan_at=s.last_scan_at,
            created_at=s.created_at,
        )
        for s in sources
    ]


@router.post(
    "/{source_id}/toggle",
    dependencies=[Depends(require_role(Role.ADMIN))],
)
async def toggle_source(
    source_id: str,
    db: DbSession,
    current_user: CurrentUser,
) -> dict[str, Any]:
    """Enable or disable a source (admin only, audit-logged)."""
    result = await db.execute(
        select(Source).where(Source.source_id == source_id)
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")

    previous = source.enabled
    source.enabled = not source.enabled

    # Audit
    db.add(AuditLog(**build_audit_entry(
        actor=current_user.sub,
        action=AuditAction.SOURCE_TOGGLE,
        target=source_id,
        detail={"previous": previous, "new": source.enabled},
    )))

    return {
        "source_id": source_id,
        "enabled": source.enabled,
        "previous": previous,
    }
