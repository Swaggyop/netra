"""
NETRA â€” Export API endpoints.

Generates real downloadable files (PDF, CSV, JSON) for:
  - Individual actor dossiers (Export Dossier)
  - Batch actor exports (Batch Export)
  - Full intel exports (Export Intel)

Files are generated inline (small data) â€” no Celery needed for now.
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
    format: str = Field(default="json", pattern=r"^(csv|json|pdf)$")
    include_actors: bool = True
    include_entities: bool = True
    include_events: bool = False


# â”€â”€ Helper: build actor dossier dict â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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


# â”€â”€ Dossier export (single actor) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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


# â”€â”€ Batch export (all actors) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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


# â”€â”€ Intel export (actors + entities) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        pass  # Redis unavailable â€” export DB data only

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

    if body.format == "pdf":
        pdf_bytes = _generate_intel_pdf(data)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="netra_intel_export.pdf"'},
        )

    raise HTTPException(400, "Unsupported format")


# â”€â”€ PDF generators (text-based, no heavy deps) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _sanitize_for_pdf(text: str) -> str:
    """Replace Unicode chars with ASCII equivalents safe for PDF Courier font."""
    replacements = {
        "\u2500": "-", "\u2014": "--", "\u2013": "-",
        "\u2019": "'", "\u2018": "'", "\u201c": '"', "\u201d": '"',
        "\u2026": "...", "\u2022": "*", "\u00b7": ".",
        "\u2717": "x", "\u2713": "v", "\u00d7": "x",
        "\u2192": "->", "\u2190": "<-",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _generate_intel_pdf(data: dict) -> bytes:
    """Generate a PDF for the full intel package export."""
    lines = [
        "NETRA - INTELLIGENCE PACKAGE EXPORT",
        "=" * 60, "",
        "CLASSIFICATION: CLASSIFIED // REL TO INTEL",
        f"Generated: {data.get('exported_at', 'N/A')}", "",
    ]

    actors_data = data.get("actors", [])
    lines.extend(["-" * 60, f"TRACKED ACTORS ({len(actors_data)})", "-" * 60, ""])
    for a in actors_data[:100]:
        status = (a.get("status") or "unknown").upper()
        handle = (a.get("handle") or "Unknown")[:30]
        cat = a.get("category") or "N/A"
        lines.append(f"  [{status:8s}]  {handle:30s}  cat={cat}")
        lines.append(f"             ID: {a.get('actor_id', 'N/A')}")
        first = (a.get("first_seen") or "?")[:19]
        last = (a.get("last_seen") or "?")[:19]
        lines.append(f"             Seen: {first} to {last}")
        lines.append("")

    entities_data = data.get("entities", [])
    lines.extend(["-" * 60, f"ENTITIES ({len(entities_data)})", "-" * 60, ""])
    by_type: dict[str, list[str]] = {}
    for e in entities_data[:500]:
        kind = e.get("type") or "unknown"
        by_type.setdefault(kind, []).append(e.get("value") or "N/A")
    for kind, values in by_type.items():
        lines.append(f"  {kind.upper()} ({len(values)}):")
        for v in values[:20]:
            lines.append(f"    - {str(v)[:70]}")
        if len(values) > 20:
            lines.append(f"    ... and {len(values) - 20} more")
        lines.append("")

    runs = data.get("collection_runs", {})
    if runs:
        lines.extend(["-" * 60, f"COLLECTION RUNS ({len(runs)})", "-" * 60, ""])
        for src, info in runs.items():
            items = info.get("total_items", info.get("cumulative_items", 0))
            completed = (info.get("completed_at") or "N/A")[:19]
            lines.append(f"  {str(src):25s}  items={items}  at={completed}")
        lines.append("")

    lines.extend(["-" * 60, "END OF INTEL PACKAGE", "-" * 60, "",
                  "Generated by NETRA v2.0",
                  "Networked Entity Tracking & Reconnaissance Architecture"])

    return _text_to_pdf("\n".join(lines), "NETRA Intel Package Export")


def _generate_dossier_pdf(dossier: dict) -> bytes:
    """Generate a PDF for a single actor dossier."""
    handle = dossier.get("handle", "Unknown")
    lines = [
        "NETRA THREAT DOSSIER",
        "=" * 60, "",
        "CLASSIFICATION: CLASSIFIED // REL TO INTEL",
        f"Export ID:  {dossier.get('export_id', 'N/A')}",
        f"Generated: {dossier.get('exported_at', 'N/A')}", "",
        "-" * 60, f"SUBJECT: {handle}", "-" * 60, "",
        f"Actor ID:      {dossier.get('actor_id', 'N/A')}",
        f"Category:      {dossier.get('category', 'Unknown')}",
        f"Status:        {dossier.get('status', 'Unknown')}",
        f"First Seen:    {dossier.get('first_seen', 'N/A')}",
        f"Last Seen:     {dossier.get('last_seen', 'N/A')}",
        f"Entity Count:  {dossier.get('entity_count', 0)}", "",
    ]

    if dossier.get("notes"):
        lines.extend(["-" * 60, "ANALYST NOTES", "-" * 60,
                      str(dossier["notes"])[:500], ""])

    entities = dossier.get("entities", {})
    if entities:
        lines.extend(["-" * 60, "LINKED ENTITIES", "-" * 60, ""])
        for kind, values in entities.items():
            lines.append(f"  {kind.upper()} ({len(values)}):")
            for v in values:
                lines.append(f"    - {str(v)[:70]}")
            lines.append("")

    lines.extend(["-" * 60, "END OF DOSSIER", "-" * 60, "",
                  "Generated by NETRA v2.0"])

    return _text_to_pdf("\n".join(lines), f"NETRA Dossier: {handle}")


def _text_to_pdf(text: str, title: str) -> bytes:
    """
    Convert text to a valid multi-page PDF document.

    Uses Courier 9pt with proper page breaks and ASCII-safe encoding.
    """
    text = _sanitize_for_pdf(text)
    all_lines = text.split("\n")

    # Layout
    PAGE_W, PAGE_H = 612, 792
    MARGIN_L = 50
    TOP_Y = 742
    BOT_Y = 50
    LH = 12
    FONT_SZ = 9
    MAX_CHARS = 90

    lines_per_page = (TOP_Y - BOT_Y) // LH

    # Split into pages
    pages: list[list[str]] = []
    for i in range(0, len(all_lines), lines_per_page):
        pages.append(all_lines[i:i + lines_per_page])
    if not pages:
        pages = [[""]]

    def esc(s: str) -> str:
        s = s[:MAX_CHARS]
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def make_stream(page_lines: list[str]) -> bytes:
        parts = [
            "BT",
            f"/F1 {FONT_SZ} Tf",
            f"{LH} TL",
            f"1 0 0 1 {MARGIN_L} {TOP_Y} Tm",
        ]
        for line in page_lines:
            parts.append(f"({esc(line)}) '")
        parts.append("ET")
        return "\n".join(parts).encode("latin-1", errors="replace")

    # Object numbering: 1=Catalog, 2=Pages, 3=Font, then pairs (page, stream)
    num_pages = len(pages)
    total_objs = 3 + num_pages * 2

    pdf = io.BytesIO()
    pdf.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}

    def write_obj(oid: int, body: bytes):
        offsets[oid] = pdf.tell()
        pdf.write(f"{oid} 0 obj\n".encode() + body + b"\nendobj\n")

    # Page object IDs: 4, 6, 8, ... ; stream IDs: 5, 7, 9, ...
    page_ids = [4 + i * 2 for i in range(num_pages)]

    # 1: Catalog
    write_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")

    # 2: Pages tree
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    write_obj(2, f"<< /Type /Pages /Kids [{kids}] /Count {num_pages} >>".encode())

    # 3: Font
    write_obj(3, b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

    # Each page + its content stream
    for idx, page_lines in enumerate(pages):
        page_oid = page_ids[idx]
        stream_oid = page_oid + 1
        stream_bytes = make_stream(page_lines)

        write_obj(page_oid, (
            f"<< /Type /Page /Parent 2 0 R "
            f"/MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Contents {stream_oid} 0 R "
            f"/Resources << /Font << /F1 3 0 R >> >> >>"
        ).encode())

        offsets[stream_oid] = pdf.tell()
        hdr = f"{stream_oid} 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n"
        pdf.write(hdr.encode() + stream_bytes + b"\nendstream\nendobj\n")

    # Xref table
    xref_offset = pdf.tell()
    pdf.write(b"xref\n")
    pdf.write(f"0 {total_objs + 1}\n".encode())
    pdf.write(b"0000000000 65535 f \n")
    for oid in range(1, total_objs + 1):
        pdf.write(f"{offsets.get(oid, 0):010d} 00000 n \n".encode())

    pdf.write(b"trailer\n")
    pdf.write(f"<< /Size {total_objs + 1} /Root 1 0 R >>\n".encode())
    pdf.write(b"startxref\n")
    pdf.write(f"{xref_offset}\n".encode())
    pdf.write(b"%%EOF\n")

    return pdf.getvalue()

