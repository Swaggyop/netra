"""
NETRA — Actors API (§14).

Actor profiles, graph queries, and persona link review.
Every actor view is audit-logged (OWASP A09).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.deps import CurrentUser, DbSession, RequireAnalyst, require_role
from backend.app.core.security import AuditAction, Role, build_audit_entry
from backend.app.models.actors import (
    Actor,
    ActorEntity,
    AuditLog,
    PersonaLink,
    LinkEvidence,
)
from backend.app.models.entities import Entity

router = APIRouter(prefix="/actors", tags=["actors"])


# ── Response schemas ─────────────────────────────────────────

class ActorSummary(BaseModel):
    actor_id: str
    label: str
    category: str | None
    status: str
    first_seen: datetime
    last_seen: datetime
    entity_count: int = 0


class ActorDetail(BaseModel):
    actor_id: str
    label: str
    category: str | None
    status: str
    first_seen: datetime
    last_seen: datetime
    last_scan_at: datetime | None
    entities: list[dict[str, Any]]
    links: list[dict[str, Any]]


class LinkReviewRequest(BaseModel):
    status: str = Field(..., pattern=r"^(confirmed|rejected|needs_info)$")
    note: str | None = None


class LinkEvidenceResponse(BaseModel):
    link_id: str
    actor_a: str
    actor_b: str
    score: float
    band: str
    analyst_status: str
    evidence: list[dict[str, Any]]
    why: list[str]


class CreateActorRequest(BaseModel):
    """Request to create a new actor dossier."""
    label: str = Field(..., min_length=1, max_length=256, description="Actor handle / name")
    category: str | None = Field(None, description="vendor | buyer | admin | mixer | unknown")
    status: str = Field("active", description="active | dormant | merged | unknown")
    notes: str | None = Field(None, max_length=2000)


# ── Endpoints ────────────────────────────────────────────────

@router.post("", status_code=201)
async def create_actor(
    body: CreateActorRequest,
    db: DbSession,
    current_user: RequireAnalyst,
) -> dict[str, Any]:
    """Create a new actor dossier (the 'New Dossier' action)."""
    import uuid

    actor_id = str(uuid.uuid4())
    now = datetime.now()
    actor = Actor(
        actor_id=actor_id,
        label=body.label,
        category=body.category or "unknown",
        status=body.status,
        first_seen=now,
        last_seen=now,
    )
    db.add(actor)

    # Audit log
    db.add(AuditLog(**build_audit_entry(
        actor=current_user.sub,
        action=AuditAction.CREATE_ACTOR,
        target=actor_id,
        detail={"action": "create_actor", "label": body.label},
    )))
    await db.commit()

    return {
        "actor_id": actor_id,
        "label": body.label,
        "category": body.category or "unknown",
        "status": body.status,
        "created": True,
    }


@router.get("", response_model=list[ActorSummary])
async def list_actors(
    db: DbSession,
    current_user: CurrentUser,
    q: str | None = Query(None, max_length=256),
    category: str | None = Query(None),
    status: str | None = Query(None),
    min_score: float | None = Query(None, ge=0, le=100),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> list[ActorSummary]:
    """List actors with optional filters."""
    query = select(Actor)

    if q:
        query = query.where(Actor.label.ilike(f"%{q}%"))
    if category:
        query = query.where(Actor.category == category)
    if status:
        query = query.where(Actor.status == status)

    query = query.order_by(Actor.last_seen.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    actors = result.scalars().all()

    return [
        ActorSummary(
            actor_id=a.actor_id,
            label=a.label,
            category=a.category,
            status=a.status,
            first_seen=a.first_seen,
            last_seen=a.last_seen,
        )
        for a in actors
    ]


@router.get("/{actor_id}", response_model=ActorDetail)
async def get_actor(
    actor_id: str,
    db: DbSession,
    current_user: CurrentUser,
) -> ActorDetail:
    """Get full actor profile with entities and links."""
    result = await db.execute(
        select(Actor).where(Actor.actor_id == actor_id)
    )
    actor = result.scalar_one_or_none()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    # Audit: log actor view (OWASP A09)
    db.add(AuditLog(**build_audit_entry(
        actor=current_user.sub,
        action=AuditAction.VIEW_ACTOR,
        target=actor_id,
    )))

    # Fetch entities
    entity_result = await db.execute(
        select(Entity)
        .join(ActorEntity, ActorEntity.entity_id == Entity.entity_id)
        .where(ActorEntity.actor_id == actor_id)
    )
    entities = [
        {"entity_id": e.entity_id, "kind": e.kind, "value": e.value,
         "first_seen": e.first_seen.isoformat(), "last_seen": e.last_seen.isoformat()}
        for e in entity_result.scalars().all()
    ]

    # Fetch links
    link_result = await db.execute(
        select(PersonaLink)
        .where(
            (PersonaLink.actor_a == actor_id) | (PersonaLink.actor_b == actor_id)
        )
        .order_by(PersonaLink.score.desc())
    )
    links = [
        {"link_id": lnk.link_id, "actor_a": lnk.actor_a, "actor_b": lnk.actor_b,
         "link_type": lnk.link_type, "score": float(lnk.score), "band": lnk.band,
         "analyst_status": lnk.analyst_status}
        for lnk in link_result.scalars().all()
    ]

    return ActorDetail(
        actor_id=actor.actor_id,
        label=actor.label,
        category=actor.category,
        status=actor.status,
        first_seen=actor.first_seen,
        last_seen=actor.last_seen,
        last_scan_at=actor.last_scan_at,
        entities=entities,
        links=links,
    )


class UpdateActorRequest(BaseModel):
    """Request to update actor fields."""
    label: str | None = None
    category: str | None = None
    status: str | None = None
    notes: str | None = None


@router.patch("/{actor_id}")
async def update_actor(
    actor_id: str,
    body: UpdateActorRequest,
    db: DbSession,
    current_user: RequireAnalyst,
) -> dict[str, Any]:
    """Update an existing actor's fields."""
    result = await db.execute(
        select(Actor).where(Actor.actor_id == actor_id)
    )
    actor = result.scalar_one_or_none()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    if body.label is not None:
        actor.label = body.label
    if body.category is not None:
        actor.category = body.category
    if body.status is not None:
        actor.status = body.status
    actor.last_seen = datetime.now()

    await db.commit()
    return {
        "actor_id": actor.actor_id,
        "label": actor.label,
        "category": actor.category,
        "status": actor.status,
        "updated": True,
    }


@router.get("/graph/overview")
async def get_overview_graph(
    current_user: CurrentUser,
    limit: int = Query(300, ge=10, le=1000),
) -> dict[str, Any]:
    """Get the knowledge graph overview for the Graph Explorer dashboard."""
    from backend.app.graph.schema import get_neo4j_session

    async with get_neo4j_session() as session:
        query = f"""
        MATCH (n)
        OPTIONAL MATCH (n)-[r]->(m)
        WITH collect(DISTINCT n)[..{limit}] AS raw_nodes, collect(DISTINCT r)[..{limit * 3}] AS raw_rels
        RETURN raw_nodes AS nodes, raw_rels AS relationships
        """
        result = await session.run(query)
        record = await result.single()
        if not record:
            return {"nodes": [], "edges": [], "relationships": []}

        nodes = []
        for n in record["nodes"]:
            d = dict(n)
            labels = list(n.labels)
            d["labels"] = labels
            kind = labels[0] if labels else "Entity"
            label_val = (
                d.get("label")
                or d.get("value")
                or d.get("fingerprint")
                or d.get("address")
                or d.get("name")
                or d.get("id")
            )
            nodes.append({
                "id": d.get("id"),
                "label": label_val,
                "kind": kind,
                "properties": d,
            })

        edges = []
        for r in record["relationships"]:
            if r:
                try:
                    start_id = r.start_node.get("id") if hasattr(r, "start_node") and r.start_node else None
                    end_id = r.end_node.get("id") if hasattr(r, "end_node") and r.end_node else None
                except Exception:
                    start_id = None
                    end_id = None
                if start_id and end_id:
                    edges.append({
                        "source": start_id,
                        "target": end_id,
                        "relation": r.type,
                        "properties": dict(r),
                    })

        return {"nodes": nodes, "edges": edges, "relationships": edges}


@router.get("/{actor_id}/graph")
async def get_actor_graph_view(
    actor_id: str,
    current_user: CurrentUser,
    depth: int = Query(2, ge=1, le=5),
) -> dict[str, Any]:
    """Get the ego graph around an actor for the Cytoscape dashboard."""
    from backend.app.graph.schema import get_neo4j_session, get_actor_graph

    async with get_neo4j_session() as session:
        return await get_actor_graph(session, actor_id, depth=depth)


@router.get("/links/{link_id}/evidence", response_model=LinkEvidenceResponse)
async def get_link_evidence(
    link_id: str,
    db: DbSession,
    current_user: CurrentUser,
) -> LinkEvidenceResponse:
    """Get the full evidence chain for a persona link."""
    # Fetch link
    result = await db.execute(
        select(PersonaLink).where(PersonaLink.link_id == link_id)
    )
    link = result.scalar_one_or_none()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    # Fetch evidence items
    ev_result = await db.execute(
        select(LinkEvidence).where(LinkEvidence.link_id == link_id)
    )
    evidence_items = ev_result.scalars().all()

    evidence = [
        {
            "type": ev.evidence_type,
            "llr": float(ev.llr),
            "raw_value": ev.raw_value,
            "reliability": ev.reliability,
            "credibility": ev.credibility,
            "source_id": ev.source_id,
            "note": ev.note,
        }
        for ev in evidence_items
    ]

    # Build "why" list from evidence
    why = _build_why_list(evidence_items)

    return LinkEvidenceResponse(
        link_id=link.link_id,
        actor_a=link.actor_a,
        actor_b=link.actor_b,
        score=float(link.score),
        band=link.band,
        analyst_status=link.analyst_status,
        evidence=evidence,
        why=why,
    )


@router.post(
    "/links/{link_id}/review",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def review_link(
    link_id: str,
    body: LinkReviewRequest,
    db: DbSession,
    current_user: CurrentUser,
) -> dict[str, str]:
    """Analyst confirms or rejects a persona link (audit-logged)."""
    result = await db.execute(
        select(PersonaLink).where(PersonaLink.link_id == link_id)
    )
    link = result.scalar_one_or_none()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    link.analyst_status = body.status

    # Audit
    db.add(AuditLog(**build_audit_entry(
        actor=current_user.sub,
        action=AuditAction.REVIEW_LINK,
        target=link_id,
        detail={"new_status": body.status, "note": body.note},
    )))

    return {"status": "updated", "link_id": link_id, "new_status": body.status}


# ── Helpers ──────────────────────────────────────────────────

_WHY_TEMPLATES = {
    "pgp_fingerprint": "Same PGP fingerprint",
    "ssh_key": "Same SSH host key",
    "contact_id": "Same contact identifier",
    "wallet_cluster": "Same wallet cluster",
    "wallet_transfer": "Direct wallet-to-wallet transfer",
    "cert_san": "TLS certificate names clearnet domain",
    "favicon": "Same favicon hash",
    "handle_exact": "Exact handle match",
    "handle_similar": "Similar handle",
    "stylometry": "Similar writing profile",
    "temporal_overlap": "Overlapping activity window",
    "banner": "Same server banner",
    "avatar_hash": "Same avatar hash",
    "code_switch": "Similar code-switch pattern",
}


def _build_why_list(evidence_items: list) -> list[str]:
    """Build human-readable 'why' list from evidence items."""
    return [
        _WHY_TEMPLATES.get(ev.evidence_type, f"Evidence: {ev.evidence_type}")
        for ev in evidence_items
    ]
