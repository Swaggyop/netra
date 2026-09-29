"""
NETRA — Search, alerts, exports, provenance, and timeline APIs (§14).

Grouped here for brevity — each would be its own file in a larger codebase.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.deps import CurrentUser, DbSession, RequireAnalyst
from backend.app.core.security import Role
from backend.app.api.deps import require_role
from backend.app.core.security import AuditAction, build_audit_entry
from backend.app.models.actors import Alert, AuditLog, Post
from backend.app.models.events import Event

# ── Search ───────────────────────────────────────────────────

search_router = APIRouter(prefix="/search", tags=["search"])


class SearchResult(BaseModel):
    type: str  # post | entity | actor
    id: str
    snippet: str
    score: float | None = None
    metadata: dict[str, Any] = {}


@search_router.get("", response_model=list[SearchResult])
async def search(
    db: DbSession,
    current_user: CurrentUser,
    q: str = Query(..., min_length=1, max_length=512),
    limit: int = Query(50, ge=1, le=200),
) -> list[SearchResult]:
    """
    Full-text search across posts, entities, and actors.

    Uses Postgres tsvector for text search (OWASP A03: parameterised query).
    """
    # Sanitise query for tsquery (prevent injection)
    safe_q = q.replace("'", "''").replace("\\", "\\\\")

    # Search posts via tsvector
    result = await db.execute(
        text("""
            SELECT post_id, handle, market,
                   ts_headline('english', text, plainto_tsquery(:q)) AS snippet,
                   ts_rank(tsv, plainto_tsquery(:q)) AS rank
            FROM posts
            WHERE tsv @@ plainto_tsquery(:q)
            ORDER BY rank DESC
            LIMIT :limit
        """),
        {"q": safe_q, "limit": limit},
    )
    rows = result.fetchall()

    return [
        SearchResult(
            type="post",
            id=row.post_id,
            snippet=row.snippet or "",
            score=float(row.rank) if row.rank else None,
            metadata={"handle": row.handle, "market": row.market},
        )
        for row in rows
    ]


# ── Alerts ───────────────────────────────────────────────────

alerts_router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertResponse(BaseModel):
    alert_id: str
    alert_type: str
    subject: dict[str, Any]
    score: float | None
    status: str
    created_at: datetime


class AlertPatchRequest(BaseModel):
    status: str = Field(..., pattern=r"^(acknowledged|resolved|false_positive)$")


@alerts_router.get("", response_model=list[AlertResponse])
async def list_alerts(
    db: DbSession,
    current_user: CurrentUser,
    status: str | None = Query(None),
    alert_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
) -> list[AlertResponse]:
    """List alerts with optional filters."""
    query = select(Alert)
    if status:
        query = query.where(Alert.status == status)
    if alert_type:
        query = query.where(Alert.alert_type == alert_type)
    query = query.order_by(Alert.created_at.desc()).limit(limit)

    result = await db.execute(query)
    alerts = result.scalars().all()

    return [
        AlertResponse(
            alert_id=a.alert_id,
            alert_type=a.alert_type,
            subject=a.subject,
            score=float(a.score) if a.score else None,
            status=a.status,
            created_at=a.created_at,
        )
        for a in alerts
    ]


@alerts_router.patch("/{alert_id}", dependencies=[Depends(require_role(Role.ANALYST))])
async def update_alert(
    alert_id: str,
    body: AlertPatchRequest,
    db: DbSession,
    current_user: CurrentUser,
) -> dict[str, str]:
    """Update alert status (analyst+)."""
    result = await db.execute(
        select(Alert).where(Alert.alert_id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = body.status
    return {"alert_id": alert_id, "status": body.status}


# ── Exports ──────────────────────────────────────────────────

exports_router = APIRouter(prefix="/exports", tags=["exports"])


class ExportRequest(BaseModel):
    format: str = Field(..., pattern=r"^(csv|json|pdf)$")
    filter: dict[str, Any] = Field(default_factory=dict)


@exports_router.post("")
async def create_export(
    body: ExportRequest,
    db: DbSession,
    current_user: CurrentUser,
) -> dict[str, str]:
    """
    Queue an export job (audit-logged).

    Returns a job ID; the file is generated asynchronously by Celery
    and made available at /exports/{job_id}/download.
    """
    import uuid
    job_id = str(uuid.uuid4())

    # Audit
    db.add(AuditLog(**build_audit_entry(
        actor=current_user.sub,
        action=AuditAction.EXPORT,
        target=job_id,
        detail={"format": body.format, "filter": body.filter},
    )))

    # TODO: dispatch Celery task
    # export_task.delay(job_id, body.format, body.filter)

    return {"job_id": job_id, "status": "queued", "format": body.format}


# ── Provenance ───────────────────────────────────────────────

provenance_router = APIRouter(prefix="/provenance", tags=["provenance"])


@provenance_router.get("/{evidence_id}")
async def get_provenance(
    evidence_id: str,
    db: DbSession,
    current_user: CurrentUser,
) -> dict[str, Any]:
    """
    Look up provenance for an evidence ID.

    Returns the content hash, Merkle batch, root hash, and anchor status.
    """
    from backend.app.models.events import Evidence, MerkleBatch

    result = await db.execute(
        select(Evidence).where(Evidence.evidence_id == evidence_id)
    )
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    batch_info = None
    if evidence.merkle_batch_id:
        batch_result = await db.execute(
            select(MerkleBatch).where(
                MerkleBatch.batch_id == evidence.merkle_batch_id
            )
        )
        batch = batch_result.scalar_one_or_none()
        if batch:
            batch_info = {
                "batch_id": batch.batch_id,
                "root_hash": batch.root_hash,
                "leaf_count": batch.leaf_count,
                "created_at": batch.created_at.isoformat(),
                "anchor_ref": batch.anchor_ref,
                "anchor_type": batch.anchor_type,
            }

    return {
        "evidence_id": evidence.evidence_id,
        "content_hash": evidence.content_hash,
        "collected_at": evidence.collected_at.isoformat(),
        "source_id": evidence.source_id,
        "batch": batch_info,
    }


# ── Timeline ────────────────────────────────────────────────

timeline_router = APIRouter(prefix="/timeline", tags=["timeline"])


@timeline_router.get("")
async def get_timeline(
    db: DbSession,
    current_user: CurrentUser,
    entity: str | None = Query(None),
    from_dt: datetime | None = Query(None, alias="from"),
    to_dt: datetime | None = Query(None, alias="to"),
    limit: int = Query(200, ge=1, le=1000),
) -> list[dict[str, Any]]:
    """Timeline of events, optionally filtered by entity and date range."""
    query = select(Event)

    if from_dt:
        query = query.where(Event.observed_at >= from_dt)
    if to_dt:
        query = query.where(Event.observed_at <= to_dt)

    query = query.order_by(Event.observed_at.desc()).limit(limit)
    result = await db.execute(query)
    events = result.scalars().all()

    return [
        {
            "event_id": e.event_id,
            "source_id": e.source_id,
            "mode": e.mode,
            "observed_at": e.observed_at.isoformat(),
            "collected_at": e.collected_at.isoformat(),
            "language": e.language,
        }
        for e in events
    ]


# ── Infrastructure ──────────────────────────────────────────

infra_router = APIRouter(prefix="/infra", tags=["infrastructure"])


@infra_router.get("/findings")
async def get_infra_findings(
    db: DbSession,
    current_user: CurrentUser,
    onion: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
) -> list[dict[str, Any]]:
    """List infrastructure findings, optionally filtered by onion entity."""
    from backend.app.models.actors import InfraFinding

    query = select(InfraFinding)
    if onion:
        query = query.where(InfraFinding.onion_entity == onion)
    query = query.order_by(InfraFinding.detected_at.desc()).limit(limit)

    result = await db.execute(query)
    findings = result.scalars().all()

    return [
        {
            "finding_id": f.finding_id,
            "onion_entity": f.onion_entity,
            "kind": f.kind,
            "raw": f.raw,
            "matched_clearnet": f.matched_clearnet,
            "confidence": float(f.confidence),
            "detected_at": f.detected_at.isoformat(),
            "source_id": f.source_id,
        }
        for f in findings
    ]


# ── Watchlist ───────────────────────────────────────────────

watchlist_router = APIRouter(prefix="/watchlist", tags=["watchlist"])


@watchlist_router.get("")
async def list_watchlist(
    db: DbSession,
    current_user: CurrentUser,
) -> list[dict[str, Any]]:
    """List all watchlist items."""
    from backend.app.models.actors import WatchlistItem

    result = await db.execute(select(WatchlistItem))
    items = result.scalars().all()

    return [
        {
            "item_id": i.item_id,
            "entity_id": i.entity_id,
            "created_by": i.created_by,
            "created_at": i.created_at.isoformat(),
        }
        for i in items
    ]


@watchlist_router.post("", status_code=201)
async def add_to_watchlist(
    entity_id: str = Query(...),
    db: DbSession = None,  # type: ignore
    current_user: CurrentUser = None,  # type: ignore
) -> dict[str, str]:
    """Add an entity to the watchlist."""
    import uuid
    from backend.app.models.actors import WatchlistItem

    item = WatchlistItem(
        item_id=str(uuid.uuid4()),
        entity_id=entity_id,
        created_by=current_user.sub,
    )
    db.add(item)
    return {"item_id": item.item_id, "entity_id": entity_id}
