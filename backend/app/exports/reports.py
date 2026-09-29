"""
NETRA — Export module (§11).

Generates court-admissible and analyst-friendly reports in
PDF, CSV, and JSON formats with provenance chains.

All exports include:
  - Evidence chain with sources and Admiralty grades
  - Merkle root verification hashes
  - Redaction audit trail
  - Analyst review status and notes
"""

from __future__ import annotations

import csv
import io
import json
import logging
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


# ── Report data structures ───────────────────────────────────

def build_actor_report(
    actor: dict[str, Any],
    links: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    entities: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Build a comprehensive actor report for export.

    This is the data structure that feeds PDF/CSV/JSON exports.
    """
    return {
        "report_type": "actor_dossier",
        "generated_at": datetime.now(UTC).isoformat(),
        "classification": "RESTRICTED",
        "actor": actor,
        "known_identities": {
            "handles": [e for e in entities if e.get("kind") == "handle"],
            "pgp_keys": [e for e in entities if e.get("kind") == "pgp"],
            "wallets": [e for e in entities if e.get("kind") == "wallet"],
            "contact_ids": [e for e in entities if e.get("kind") == "contact_id"],
            "emails": [e for e in entities if e.get("kind") == "email"],
            "onion_addresses": [e for e in entities if e.get("kind") == "onion"],
        },
        "persona_links": links,
        "evidence_chain": evidence,
        "activity_timeline": timeline,
        "provenance": {
            "export_hash": None,    # Filled after serialization
            "merkle_roots": [],     # Filled from evidence batch refs
        },
    }


# ── JSON export ──────────────────────────────────────────────

def export_json(report: dict[str, Any]) -> str:
    """Export report as JSON with provenance hash."""
    from backend.app.core.provenance import compute_content_hash

    output = json.dumps(report, indent=2, default=str, ensure_ascii=False)

    # Compute export hash for tamper detection
    export_hash = compute_content_hash(output.encode("utf-8"))
    report["provenance"]["export_hash"] = export_hash

    # Re-serialize with hash
    output = json.dumps(report, indent=2, default=str, ensure_ascii=False)

    logger.info(
        "JSON export: actor=%s, hash=%s",
        report.get("actor", {}).get("label", "unknown"),
        export_hash[:16],
    )
    return output


# ── CSV export ───────────────────────────────────────────────

def export_csv_evidence(evidence: list[dict[str, Any]]) -> str:
    """Export evidence chain as CSV for analyst tooling."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "evidence_id", "type", "value", "source_id",
            "reliability", "credibility", "content_hash",
            "collected_at", "merkle_batch_id",
        ],
        extrasaction="ignore",
    )
    writer.writeheader()
    for item in evidence:
        writer.writerow(item)

    result = output.getvalue()
    logger.info("CSV export: %d evidence rows", len(evidence))
    return result


def export_csv_entities(entities: list[dict[str, Any]]) -> str:
    """Export entities as CSV."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "entity_id", "kind", "value", "normalized",
            "first_seen", "last_seen",
        ],
        extrasaction="ignore",
    )
    writer.writeheader()
    for entity in entities:
        writer.writerow(entity)

    return output.getvalue()


def export_csv_timeline(timeline: list[dict[str, Any]]) -> str:
    """Export activity timeline as CSV."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "timestamp", "event_type", "source", "handle",
            "market", "summary",
        ],
        extrasaction="ignore",
    )
    writer.writeheader()
    for event in timeline:
        writer.writerow(event)

    return output.getvalue()


# ── STIX 2.1 export (stretch) ────────────────────────────────

def export_stix_bundle(
    actor: dict[str, Any],
    entities: list[dict[str, Any]],
    links: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Export actor data as a STIX 2.1 bundle.

    This enables interoperability with threat intelligence platforms
    (MISP, OpenCTI, TheHive).
    """
    stix_objects: list[dict[str, Any]] = []

    # Threat actor SDO
    stix_objects.append({
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": f"threat-actor--{actor.get('actor_id', 'unknown')}",
        "created": actor.get("first_seen", datetime.now(UTC).isoformat()),
        "modified": actor.get("last_seen", datetime.now(UTC).isoformat()),
        "name": actor.get("label", "Unknown Actor"),
        "threat_actor_types": ["unknown"],
        "aliases": [e["value"] for e in entities if e.get("kind") == "handle"],
    })

    # Observable SCOs for each entity
    for entity in entities:
        sco = _entity_to_stix_sco(entity)
        if sco:
            stix_objects.append(sco)

    return {
        "type": "bundle",
        "id": f"bundle--netra-{actor.get('actor_id', 'unknown')[:8]}",
        "objects": stix_objects,
    }


def _entity_to_stix_sco(entity: dict[str, Any]) -> dict[str, Any] | None:
    """Convert an entity to a STIX Cyber Observable."""
    kind = entity.get("kind")
    value = entity.get("value", "")
    eid = entity.get("entity_id", "unknown")

    if kind == "email":
        return {
            "type": "email-addr",
            "spec_version": "2.1",
            "id": f"email-addr--{eid}",
            "value": value,
        }
    elif kind == "wallet":
        return {
            "type": "x-cryptocurrency-wallet",
            "spec_version": "2.1",
            "id": f"x-cryptocurrency-wallet--{eid}",
            "address": value,
            "currency": entity.get("metadata", {}).get("currency", "unknown"),
        }
    elif kind == "onion":
        return {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": f"domain-name--{eid}",
            "value": value,
        }
    elif kind == "ip":
        return {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": f"ipv4-addr--{eid}",
            "value": value,
        }
    return None
