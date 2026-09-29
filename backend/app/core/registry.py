"""
NETRA — Source registry access and seed data (§18).

Provides functions to query and manage the source registry,
plus the seed data that populates all approved sources at first run.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.policy import SourceRecord
from backend.app.models.sources import Source

logger = logging.getLogger(__name__)


# ── Registry access ──────────────────────────────────────────

async def get_source_record(
    session: AsyncSession,
    source_id: str,
) -> SourceRecord | None:
    """Look up a source and return a lightweight DTO for the policy gate."""
    result = await session.execute(
        select(Source).where(Source.source_id == source_id)
    )
    source = result.scalar_one_or_none()
    if not source:
        return None

    return SourceRecord(
        source_id=source.source_id,
        source_type=source.source_type,
        authorization_status=source.authorization_status,
        authorization_ref=source.authorization_ref,
        enabled=source.enabled,
        retention_days=source.retention_days,
        pii_policy=source.pii_policy,
        reliability_grade=source.reliability_grade,
    )


async def get_enabled_sources(
    session: AsyncSession,
    source_type: str | None = None,
) -> list[SourceRecord]:
    """Get all enabled, approved/authorized sources."""
    query = select(Source).where(
        Source.enabled == True,  # noqa: E712
        Source.authorization_status.in_(["approved", "authorized"]),
    )
    if source_type:
        query = query.where(Source.source_type == source_type)

    result = await session.execute(query)
    sources = result.scalars().all()

    return [
        SourceRecord(
            source_id=s.source_id,
            source_type=s.source_type,
            authorization_status=s.authorization_status,
            authorization_ref=s.authorization_ref,
            enabled=s.enabled,
            retention_days=s.retention_days,
            pii_policy=s.pii_policy,
            reliability_grade=s.reliability_grade,
        )
        for s in sources
    ]


# ── Seed data (§18 source registry) ─────────────────────────

SEED_SOURCES: list[dict] = [
    {
        "source_id": "src_synthetic",
        "name": "Synthetic Data Generator",
        "source_type": "synthetic",
        "collection_method": "datagen",
        "authorization_status": "approved",
        "permitted_use": "Training, evaluation, and demo scenarios with ground truth",
        "retention_days": 9999,
        "pii_policy": "No real PII — all synthetic",
        "reliability_grade": "A",
        "enabled": True,
    },
    {
        "source_id": "src_replay_archive",
        "name": "Archived Research Datasets",
        "source_type": "replay",
        "collection_method": "replay_engine",
        "authorization_status": "approved",
        "permitted_use": "Research-licensed datasets replayed with original timestamps",
        "retention_days": 365,
        "pii_policy": "Redact victim PII at ingestion",
        "reliability_grade": "B",
        "enabled": True,
    },
    {
        "source_id": "src_ransomware_trackers",
        "name": "Ransomware Tracker APIs",
        "source_type": "osint_feed",
        "collection_method": "api_poll",
        "authorization_status": "approved",
        "permitted_use": "Public ransomware tracker APIs — metadata only",
        "retention_days": 365,
        "pii_policy": "Redact victim identifiers",
        "reliability_grade": "B",
        "enabled": True,
    },
    {
        "source_id": "src_abusech",
        "name": "abuse.ch (URLhaus, ThreatFox, Feodo, SSLBL)",
        "source_type": "osint_feed",
        "collection_method": "api_poll",
        "authorization_status": "approved",
        "permitted_use": "Public threat intel feeds — IOC enrichment",
        "retention_days": 365,
        "pii_policy": "No victim PII in feeds",
        "reliability_grade": "A",
        "enabled": True,
    },
    {
        "source_id": "src_otx",
        "name": "AlienVault OTX",
        "source_type": "osint_feed",
        "collection_method": "api_poll",
        "authorization_status": "approved",
        "permitted_use": "Public indicator enrichment",
        "retention_days": 365,
        "pii_policy": "No victim PII",
        "reliability_grade": "B",
        "enabled": True,
    },
    {
        "source_id": "src_misp_osint",
        "name": "MISP OSINT Feeds",
        "source_type": "osint_feed",
        "collection_method": "api_poll",
        "authorization_status": "approved",
        "permitted_use": "Community MISP feeds — indicator correlation",
        "retention_days": 365,
        "pii_policy": "Redact if present",
        "reliability_grade": "C",
        "enabled": True,
    },
    {
        "source_id": "src_crtsh",
        "name": "crt.sh (Certificate Transparency)",
        "source_type": "clearnet_intel",
        "collection_method": "api_query",
        "authorization_status": "approved",
        "permitted_use": "Public CT log queries for certificate fingerprinting",
        "retention_days": 365,
        "pii_policy": "Certificates are public records",
        "reliability_grade": "A",
        "enabled": True,
    },
    {
        "source_id": "src_shodan",
        "name": "Shodan",
        "source_type": "clearnet_intel",
        "collection_method": "api_query",
        "authorization_status": "approved",
        "permitted_use": "Banner and fingerprint matching — requires API key",
        "retention_days": 365,
        "pii_policy": "Public scan data",
        "reliability_grade": "B",
        "enabled": False,  # requires API key
    },
    {
        "source_id": "src_censys",
        "name": "Censys",
        "source_type": "clearnet_intel",
        "collection_method": "api_query",
        "authorization_status": "approved",
        "permitted_use": "Host and certificate search — requires API key",
        "retention_days": 365,
        "pii_policy": "Public scan data",
        "reliability_grade": "B",
        "enabled": False,
    },
    {
        "source_id": "src_blockchain_btc",
        "name": "Bitcoin Blockchain (mempool.space / Blockstream)",
        "source_type": "blockchain",
        "collection_method": "api_query",
        "authorization_status": "approved",
        "permitted_use": "Public blockchain data — wallet analysis",
        "retention_days": 9999,
        "pii_policy": "Blockchain data is public",
        "reliability_grade": "A",
        "enabled": True,
    },
    {
        "source_id": "src_blockchain_eth",
        "name": "Ethereum (Etherscan)",
        "source_type": "blockchain",
        "collection_method": "api_query",
        "authorization_status": "approved",
        "permitted_use": "Public blockchain data — wallet analysis",
        "retention_days": 9999,
        "pii_policy": "Blockchain data is public",
        "reliability_grade": "A",
        "enabled": True,
    },
    {
        "source_id": "src_blockchain_tron",
        "name": "TRON (TronGrid)",
        "source_type": "blockchain",
        "collection_method": "api_query",
        "authorization_status": "approved",
        "permitted_use": "Public blockchain data — USDT tracking",
        "retention_days": 9999,
        "pii_policy": "Blockchain data is public",
        "reliability_grade": "A",
        "enabled": True,
    },
    {
        "source_id": "src_lab_onions",
        "name": "Lab Onion Services",
        "source_type": "lab",
        "collection_method": "tor_fetch",
        "authorization_status": "approved",
        "permitted_use": "Self-hosted lab services for infra detection demo",
        "retention_days": 9999,
        "pii_policy": "No real data",
        "reliability_grade": "A",
        "enabled": True,
    },
    {
        "source_id": "src_authorized_stub",
        "name": "Authorized Adapter (DISABLED)",
        "source_type": "authorized",
        "collection_method": "agency_deployment",
        "authorization_status": "disabled",
        "permitted_use": "Interface only — for agency deployment under legal authority",
        "retention_days": 365,
        "pii_policy": "Agency-defined",
        "reliability_grade": "C",
        "enabled": False,
    },
]


async def seed_sources(session: AsyncSession) -> int:
    """Insert seed sources if they don't already exist. Returns count inserted."""
    inserted = 0
    for src_data in SEED_SOURCES:
        existing = await session.execute(
            select(Source).where(Source.source_id == src_data["source_id"])
        )
        if existing.scalar_one_or_none() is None:
            session.add(Source(**src_data))
            inserted += 1

    if inserted:
        await session.commit()
        logger.info("Seeded %d sources", inserted)

    return inserted
