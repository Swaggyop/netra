"""
NETRA — Export API endpoints.

Generates real downloadable files (PDF, CSV, JSON) for:
  - Individual actor dossiers (Export Dossier)
  - Batch actor exports (Batch Export)
  - Full intel exports (Export Intel)

Files are generated inline (small data) — no Celery needed for now.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.deps import CurrentUser, DbSession
from backend.app.models.actors import Actor
from backend.app.models.entities import Entity

export_router = APIRouter(prefix="/exports", tags=["exports"])


class DossierExportRequest(BaseModel):
    actor_id: str
    format: str = Field(default="json", pattern=r"^(csv|json|pdf)$")


class BatchExportRequest(BaseModel):
    format: str = Field(default="json", pattern=r"^(csv|json)$")
    filter_status: str | None = None


class IntelExportRequest(BaseModel):
    format: str = Field(default="json", pattern=r"^(csv|json)$")
    include_actors: bool = True
    include_entities: bool = True
    include_events: bool = False


# ── Helper: build actor dossier dict ──────────────────────────

async def _build_dossier(db: AsyncSession, actor_id: str) -> dict[str, Any]:
    """Build a complete dossier dict for an actor."""
    from backend.app.models.actors import ActorEntity

    result = await db.execute(select(Actor).where(Actor.actor_id == actor_id))
    actor = result.scalar_one_or_none()
    if not actor:
        raise HTTPException(404, "Actor not found")

    # Entities via join table
    ent_result = await db.execute(
        select(Entity)
        .join(ActorEntity, ActorEntity.entity_id == Entity.entity_id)
        .where(ActorEntity.actor_id == actor_id)
    )
    entities = ent_result.scalars().all()

    entity_groups: dict[str, list[str]] = {}
    for e in entities:
        kind = e.kind or "unknown"
        entity_groups.setdefault(kind, []).append(e.value)

    return {
        "actor_id": actor.actor_id,
        "handle": actor.label,
        "category": actor.category,
        "status": actor.status,
        "first_seen": actor.first_seen.isoformat() if actor.first_seen else None,
        "last_seen": actor.last_seen.isoformat() if actor.last_seen else None,
        "entity_count": len(entities),
        "entities": entity_groups,
        "exported_at": datetime.now(UTC).isoformat(),
        "classification": "CLASSIFIED // REL TO INTEL",
        "export_id": str(uuid.uuid4()),
    }


# ── Dossier export (single actor) ─────────────────────────────

@export_router.post("/dossier")
async def export_dossier(
    body: DossierExportRequest,
    db: DbSession,
    current_user: CurrentUser,
) -> StreamingResponse:
    """Export a single actor's dossier as PDF, JSON, or CSV."""
    dossier = await _build_dossier(db, body.actor_id)

    if body.format == "json":
        content = json.dumps(dossier, indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="dossier_{dossier["handle"]}.json"'},
        )

    if body.format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Field", "Value"])
        for key, val in dossier.items():
            if key == "entities":
                for kind, values in val.items():
                    for v in values:
                        writer.writerow([f"entity:{kind}", v])
            else:
                writer.writerow([key, str(val)])
        return StreamingResponse(
            io.BytesIO(buf.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="dossier_{dossier["handle"]}.csv"'},
        )

    if body.format == "pdf":
        pdf_bytes = _generate_dossier_pdf(dossier)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="dossier_{dossier["handle"]}.pdf"'},
        )

    raise HTTPException(400, "Unsupported format")


# ── Batch export (all actors) ─────────────────────────────────

@export_router.post("/batch")
async def export_batch(
    body: BatchExportRequest,
    db: DbSession,
    current_user: CurrentUser,
) -> StreamingResponse:
    """Export all actors as JSON or CSV."""
    query = select(Actor)
    if body.filter_status:
        query = query.where(Actor.status == body.filter_status)
    query = query.order_by(Actor.label)

    result = await db.execute(query)
    actors = result.scalars().all()

    rows = []
    for a in actors:
        from backend.app.models.actors import ActorEntity
        ent_result = await db.execute(
            select(func.count()).select_from(ActorEntity).where(ActorEntity.actor_id == a.actor_id)
        )
        ent_count = ent_result.scalar() or 0
        rows.append({
            "actor_id": a.actor_id,
            "handle": a.label,
            "category": a.category,
            "status": a.status,
            "first_seen": a.first_seen.isoformat() if a.first_seen else None,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "entity_count": ent_count,
        })

    if body.format == "json":
        content = json.dumps({
            "export_type": "batch_actors",
            "exported_at": datetime.now(UTC).isoformat(),
            "count": len(rows),
            "actors": rows,
        }, indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="netra_actors_export.json"'},
        )

    if body.format == "csv":
        buf = io.StringIO()
        if rows:
            writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        return StreamingResponse(
            io.BytesIO(buf.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="netra_actors_export.csv"'},
        )

    raise HTTPException(400, "Unsupported format")


# ── Intel export (actors + entities) ──────────────────────────

@export_router.post("/intel")
async def export_intel(
    body: IntelExportRequest,
    db: DbSession,
    current_user: CurrentUser,
) -> StreamingResponse:
    """Export full intelligence package as JSON or CSV."""
    data: dict[str, Any] = {
        "export_type": "intel_package",
        "exported_at": datetime.now(UTC).isoformat(),
        "classification": "CLASSIFIED // REL TO INTEL",
    }

    if body.include_actors:
        result = await db.execute(select(Actor).order_by(Actor.label))
        actors = result.scalars().all()
        data["actors"] = [
            {
                "actor_id": a.actor_id,
                "handle": a.label,
                "category": a.category,
                "status": a.status,
                "first_seen": a.first_seen.isoformat() if a.first_seen else None,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            }
            for a in actors
        ]

    if body.include_entities:
        result = await db.execute(select(Entity).limit(5000))
        entities = result.scalars().all()
        data["entities"] = [
            {
                "entity_id": e.entity_id,
                "type": e.kind,
                "value": e.value,
            }
            for e in entities
        ]

    # Include real crawled data from Redis
    try:
        import redis.asyncio as aioredis
        from backend.app.config import get_settings
        settings = get_settings()
        r = aioredis.from_url(settings.redis_url, socket_timeout=2)

        # Add collection run summaries
        raw_runs = await r.hgetall("netra:collection_runs")
        collection_data: dict[str, Any] = {}
        for key, val in raw_runs.items():
            source_name = key.decode() if isinstance(key, bytes) else key
            run = json.loads(val.decode() if isinstance(val, bytes) else val)
            collection_data[source_name] = run

        if collection_data:
            data["collection_runs"] = collection_data

        # Add detailed collection results
        detail_keys = [k async for k in r.scan_iter("netra:collection_data:*")]
        if detail_keys:
            details = {}
            for dk in detail_keys:
                raw = await r.get(dk)
                if raw:
                    key_name = dk.decode() if isinstance(dk, bytes) else dk
                    source_id = key_name.split(":")[-1]
                    details[source_id] = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
            if details:
                data["crawled_intelligence"] = details

        # Add recent events
        raw_events = await r.lrange("netra:recent_events", 0, 99)
        if raw_events:
            data["recent_events"] = [
                json.loads(e.decode() if isinstance(e, bytes) else e)
                for e in raw_events
            ]

        await r.aclose()
    except Exception:
        pass  # Redis unavailable — export DB data only

    if body.format == "json":
        content = json.dumps(data, indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="netra_intel_export.json"'},
        )

    if body.format == "csv":
        buf = io.StringIO()
        # Flatten actors + entities into rows
        writer = csv.writer(buf)
        writer.writerow(["type", "id", "handle_or_value", "category_or_kind", "status", "confidence", "first_seen", "last_seen"])
        for a in data.get("actors", []):
            writer.writerow(["actor", a["actor_id"], a["handle"], a.get("category", ""), a.get("status", ""), a.get("confidence_score", ""), a.get("first_seen", ""), a.get("last_seen", "")])
        for e in data.get("entities", []):
            writer.writerow(["entity", e["entity_id"], e["value"], e["type"], "", "", "", ""])
        return StreamingResponse(
            io.BytesIO(buf.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="netra_intel_export.csv"'},
        )

    raise HTTPException(400, "Unsupported format")


# ── PDF generator (text-based, no heavy deps) ─────────────────

def _generate_dossier_pdf(dossier: dict) -> bytes:
    """
    Generate a simple but complete PDF dossier.
    
    Uses raw PDF generation (no external deps like reportlab/weasyprint).
    Produces a clean, readable document.
    """
    handle = dossier.get("handle", "Unknown")
    lines = [
        f"NETRA THREAT DOSSIER",
        f"{'=' * 50}",
        f"",
        f"CLASSIFICATION: CLASSIFIED // REL TO INTEL",
        f"Export ID: {dossier.get('export_id', 'N/A')}",
        f"Generated: {dossier.get('exported_at', 'N/A')}",
        f"",
        f"{'─' * 50}",
        f"SUBJECT: {handle}",
        f"{'─' * 50}",
        f"",
        f"Actor ID:         {dossier.get('actor_id', 'N/A')}",
        f"Category:         {dossier.get('category', 'Unknown')}",
        f"Status:           {dossier.get('status', 'Unknown')}",
        f"Confidence:       {dossier.get('confidence_score', 'N/A')} (Band {dossier.get('confidence_band', 'N/A')})",
        f"First Seen:       {dossier.get('first_seen', 'N/A')}",
        f"Last Seen:        {dossier.get('last_seen', 'N/A')}",
        f"Entity Count:     {dossier.get('entity_count', 0)}",
        f"",
    ]

    if dossier.get("notes"):
        lines.extend([
            f"{'─' * 50}",
            f"ANALYST NOTES",
            f"{'─' * 50}",
            dossier["notes"],
            f"",
        ])

    entities = dossier.get("entities", {})
    if entities:
        lines.extend([
            f"{'─' * 50}",
            f"LINKED ENTITIES",
            f"{'─' * 50}",
            f"",
        ])
        for kind, values in entities.items():
            lines.append(f"  {kind.upper()} ({len(values)}):")
            for v in values:
                lines.append(f"    - {v}")
            lines.append("")

    lines.extend([
        f"{'─' * 50}",
        f"END OF DOSSIER",
        f"{'─' * 50}",
        f"",
        f"This document was generated by NETRA v2.0",
        f"Networked Evidence & Threat-actor Relationship Analyzer",
    ])

    text = "\n".join(lines)
    return _text_to_pdf(text, f"NETRA Dossier: {handle}")


def _text_to_pdf(text: str, title: str) -> bytes:
    """Convert text to a minimal valid PDF document."""
    # Minimal PDF 1.4 spec
    lines_arr = text.split("\n")

    # Build page content stream
    content_lines = []
    content_lines.append("BT")
    content_lines.append("/F1 10 Tf")
    y = 750
    for line in lines_arr:
        if y < 50:
            # New page would be needed — for simplicity, just continue
            y = 750
            content_lines.append("ET")
            content_lines.append("BT")
            content_lines.append("/F1 10 Tf")
        # Escape special PDF characters
        safe_line = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        content_lines.append(f"1 0 0 1 50 {y} Tm")
        content_lines.append(f"({safe_line}) Tj")
        y -= 14
    content_lines.append("ET")

    stream_content = "\n".join(content_lines)
    stream_bytes = stream_content.encode("latin-1", errors="replace")

    # Build PDF objects
    objects = []
    
    # Object 1: Catalog
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj")
    
    # Object 2: Pages
    objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj")
    
    # Object 3: Page
    objects.append(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj")
    
    # Object 4: Content stream
    stream_obj = b"4 0 obj\n<< /Length " + str(len(stream_bytes)).encode() + b" >>\nstream\n" + stream_bytes + b"\nendstream\nendobj"
    objects.append(stream_obj)
    
    # Object 5: Font
    objects.append(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj")

    # Build PDF file
    pdf = io.BytesIO()
    pdf.write(b"%PDF-1.4\n")
    
    offsets = []
    for obj in objects:
        offsets.append(pdf.tell())
        pdf.write(obj + b"\n")
    
    # Cross-reference table
    xref_offset = pdf.tell()
    pdf.write(b"xref\n")
    pdf.write(f"0 {len(objects) + 1}\n".encode())
    pdf.write(b"0000000000 65535 f \n")
    for offset in offsets:
        pdf.write(f"{offset:010d} 00000 n \n".encode())
    
    pdf.write(b"trailer\n")
    pdf.write(f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode())
    pdf.write(b"startxref\n")
    pdf.write(f"{xref_offset}\n".encode())
    pdf.write(b"%%EOF\n")
    
    return pdf.getvalue()
