"""
NETRA — Event processing pipeline (§7, orchestrator).

Ties together all pipeline stages:
  1. Event consumed from bus → policy check (already passed at source)
  2. Download payload from MinIO
  3. Safety gate (post-fetch)
  4. PII redaction
  5. Content hashing + provenance
  6. Entity extraction
  7. Entity resolution + graph write
  8. Store enriched event metadata
  9. Publish to extraction topic for downstream analytics

Heavy work (stages 2–9) runs in Celery, NOT in the API request path.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


async def process_raw_event(
    event_data: dict[str, Any],
    *,
    db_session: Any = None,
    neo4j_session: Any = None,
) -> dict[str, Any]:
    """
    Full pipeline processing for a single raw event.

    This is the core function called by the Celery worker.

    Args:
        event_data: Deserialized RawEvent dict.
        db_session: SQLAlchemy async session (injected by worker).
        neo4j_session: Neo4j async session (injected by worker).

    Returns:
        Processing result dict with entities found and status.
    """
    from backend.app.core.events import RawEvent
    from backend.app.core.safety import safety_gate
    from backend.app.core.redaction import redact_pii
    from backend.app.core.provenance import (
        compute_content_hash,
        compute_evidence_id,
        MerkleBatchManager,
    )
    from backend.app.core.storage import download_payload, generate_object_key
    from backend.app.extraction.extractors import extract_all
    from backend.app.extraction.resolver import resolve_entities
    from backend.app.models.events import Event, Evidence

    event_id = event_data.get("event_id", str(uuid.uuid4()))
    source_id = event_data.get("source_id", "unknown")

    logger.info("Processing event %s from source %s", event_id[:8], source_id)

    result: dict[str, Any] = {
        "event_id": event_id,
        "source_id": source_id,
        "status": "processing",
        "entities_found": 0,
        "stages_completed": [],
    }

    try:
        # ── Stage 1: Reconstruct event ───────────────────────
        event = RawEvent.model_validate(event_data)
        result["stages_completed"].append("parse")

        # ── Stage 2: Download payload from MinIO ─────────────
        try:
            object_key = event.payload_ref.replace("s3://netra-snapshots/", "")
            content_bytes = download_payload(object_key)
        except Exception:
            # For replay/synthetic, content may be inline in metadata
            content_text = event.raw_metadata.get("text", "")
            content_bytes = content_text.encode("utf-8") if content_text else b""

        if not content_bytes:
            result["status"] = "skipped"
            result["reason"] = "empty_payload"
            return result

        result["stages_completed"].append("download")

        # ── Stage 3: Safety gate (post-fetch) ────────────────
        content_text = content_bytes.decode("utf-8", errors="replace")
        safety_result = safety_gate.post_fetch(content_text)

        if safety_result.decision == "block":
            result["status"] = "blocked"
            result["reason"] = safety_result.reason
            logger.warning("Safety gate blocked event %s: %s", event_id[:8], safety_result.reason)
            return result

        result["stages_completed"].append("safety_gate")

        # ── Stage 4: PII redaction ───────────────────────────
        redaction = redact_pii(content_text)
        content_text = redaction.redacted_text
        result["redactions"] = redaction.redactions
        result["stages_completed"].append("redaction")

        # ── Stage 5: Content hashing + provenance ────────────
        content_hash = compute_content_hash(content_text.encode("utf-8"))
        evidence_id = compute_evidence_id(content_hash, source_id)

        if db_session:
            evidence = Evidence(
                evidence_id=evidence_id,
                event_id=event_id,
                content_hash=content_hash,
                source_id=source_id,
            )
            db_session.add(evidence)

        result["content_hash"] = content_hash
        result["evidence_id"] = evidence_id
        result["stages_completed"].append("provenance")

        # ── Stage 6: Entity extraction ───────────────────────
        metadata = event.raw_metadata or {}
        hits = extract_all(content_text, metadata)

        result["entities_found"] = len(hits)
        result["entity_kinds"] = list({h.kind for h in hits})
        result["stages_completed"].append("extraction")

        # ── Stage 7: Entity resolution + graph ───────────────
        if db_session and neo4j_session and hits:
            entity_ids = await resolve_entities(
                db_session, neo4j_session,
                event_id, source_id, hits,
            )
            result["entity_ids"] = entity_ids
            result["stages_completed"].append("resolution")

        # ── Stage 8: Update event metadata ───────────────────
        if db_session:
            from sqlalchemy import select
            ev_result = await db_session.execute(
                select(Event).where(Event.event_id == event_id)
            )
            existing_event = ev_result.scalar_one_or_none()
            if existing_event:
                existing_event.raw_metadata = {
                    **existing_event.raw_metadata,
                    "entities_found": len(hits),
                    "redactions": redaction.redactions,
                    "processed_at": datetime.now(UTC).isoformat(),
                }
            result["stages_completed"].append("metadata_update")

        result["status"] = "completed"
        logger.info(
            "Event %s processed: %d entities (%s)",
            event_id[:8], len(hits),
            ", ".join(result["entity_kinds"]) if result.get("entity_kinds") else "none",
        )

    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        logger.error("Pipeline error for event %s: %s", event_id[:8], exc, exc_info=True)

    return result


async def process_batch(
    events: list[dict[str, Any]],
    *,
    db_session: Any = None,
    neo4j_session: Any = None,
) -> list[dict[str, Any]]:
    """Process a batch of events. Returns list of results."""
    results = []
    for event_data in events:
        result = await process_raw_event(
            event_data,
            db_session=db_session,
            neo4j_session=neo4j_session,
        )
        results.append(result)
    return results
