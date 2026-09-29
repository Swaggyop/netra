"""
NETRA — Source provenance registry.

Documents the legal verification, ToS status, and concrete API endpoints
for every data source used by the system. This is the paper trail for
judges and for our own review when sources change their access policies.

Every adapter MUST have a corresponding entry here before it goes live.

Last full review: 2026-09-29
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class VerificationStatus(StrEnum):
    VERIFIED = "verified"           # Endpoint tested, ToS reviewed, legal basis confirmed
    UNVERIFIED = "unverified"       # Listed but not yet tested
    FLAGGED = "flagged"             # Needs manual review before building
    DROPPED = "dropped"             # Removed from the build plan


@dataclass(frozen=True)
class SourceProvenance:
    """Verification record for a data source."""
    source_id: str
    name: str
    api_endpoint: str
    auth_required: bool
    auth_type: str                  # "none", "api_key", "oauth", "header"
    free_tier: bool
    tos_url: str
    tos_reviewed: bool
    legal_basis: str                # "public_data", "research_license", "cc_by_4.0", etc.
    verification_status: VerificationStatus
    verification_date: str
    verification_notes: str
    rate_limit: str
    data_license: str


# ── Verified sources (safe to build against) ────────────────

VERIFIED_SOURCES: list[SourceProvenance] = [
    # ── Ransomware intelligence ──────────────────────────────
    SourceProvenance(
        source_id="src_ransomware_live",
        name="ransomware.live API PRO",
        api_endpoint="https://api-pro.ransomware.live/",
        auth_required=True,
        auth_type="header:X-API-KEY",
        free_tier=True,
        tos_url="https://ransomware.live/terms",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Free API key from ransomware.live/my. 500K calls/month. Cache 30min. No redistribution as API/feed.",
        rate_limit="500K calls/month, 30min cache",
        data_license="Non-commercial research use",
    ),
    SourceProvenance(
        source_id="src_ransomlook",
        name="ransomlook.io",
        api_endpoint="https://www.ransomlook.io/api/",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://www.ransomlook.io/",
        tos_reviewed=True,
        legal_basis="cc_by_4.0",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="CC BY 4.0 license. Open source on GitHub. Exports need API key.",
        rate_limit="Fair use",
        data_license="CC BY 4.0",
    ),
    SourceProvenance(
        source_id="src_ransomwatch",
        name="Ransomwatch (GitHub)",
        api_endpoint="https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://github.com/joshhighet/ransomwatch/blob/main/LICENSE",
        tos_reviewed=True,
        legal_basis="open_source",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="GitHub raw JSON, no key. Good backup if ransomware.live rate-limits.",
        rate_limit="GitHub CDN, no documented limit",
        data_license="Open source",
    ),

    # ── abuse.ch feeds ───────────────────────────────────────
    SourceProvenance(
        source_id="src_urlhaus",
        name="abuse.ch URLhaus",
        api_endpoint="https://urlhaus-api.abuse.ch/v1/",
        auth_required=True,
        auth_type="header:Auth-Key",
        free_tier=True,
        tos_url="https://urlhaus.abuse.ch/api/",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Free Auth-Key from auth.abuse.ch. POST API. No redistribution as a feed.",
        rate_limit="Fair use",
        data_license="Non-commercial / research (no redistribution)",
    ),
    SourceProvenance(
        source_id="src_threatfox",
        name="abuse.ch ThreatFox",
        api_endpoint="https://threatfox-api.abuse.ch/api/v1/",
        auth_required=True,
        auth_type="header:Auth-Key",
        free_tier=True,
        tos_url="https://threatfox.abuse.ch/api/",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Same Auth-Key as URLhaus. POST API with JSON queries.",
        rate_limit="Fair use",
        data_license="Non-commercial / research",
    ),
    SourceProvenance(
        source_id="src_malwarebazaar",
        name="abuse.ch MalwareBazaar",
        api_endpoint="https://mb-api.abuse.ch/api/v1/",
        auth_required=True,
        auth_type="header:Auth-Key",
        free_tier=True,
        tos_url="https://bazaar.abuse.ch/api/",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Metadata ONLY — never pull actual samples. Same Auth-Key.",
        rate_limit="Fair use",
        data_license="Non-commercial / research",
    ),
    SourceProvenance(
        source_id="src_feodo",
        name="abuse.ch Feodo Tracker",
        api_endpoint="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://feodotracker.abuse.ch/",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Static JSON feed, no auth. Updated regularly.",
        rate_limit="Static feed, poll every 15min max",
        data_license="Public",
    ),

    # ── Infrastructure correlation ───────────────────────────
    SourceProvenance(
        source_id="src_crt_sh",
        name="crt.sh (Sectigo CT log search)",
        api_endpoint="https://crt.sh/?q={domain}&output=json",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://crt.sh/",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Public CT log search. No key. Fair use — avoid flooding.",
        rate_limit="Fair use, avoid flooding",
        data_license="Public (certificate transparency)",
    ),
    SourceProvenance(
        source_id="src_shodan_idb",
        name="Shodan InternetDB",
        api_endpoint="https://internetdb.shodan.io/{ip}",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://internetdb.shodan.io/",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="10K req/sec, no key. Free for non-commercial. OpenAPI spec at /openapi.json.",
        rate_limit="10,000 req/sec",
        data_license="Free for non-commercial use",
    ),

    # ── Tor network ──────────────────────────────────────────
    SourceProvenance(
        source_id="src_onionoo",
        name="Onionoo (Tor Project)",
        api_endpoint="https://onionoo.torproject.org/details",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://metrics.torproject.org/onionoo.html",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Official Tor Project API. Use gzip. Cache responses. Fair use.",
        rate_limit="Fair use (cache responses)",
        data_license="Public",
    ),

    # ── Blockchain ───────────────────────────────────────────
    SourceProvenance(
        source_id="src_mempool",
        name="mempool.space",
        api_endpoint="https://mempool.space/api/address/{addr}",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://mempool.space/docs/api",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="No key. Rate limited, returns 429 on abuse. Pagination via after_txid.",
        rate_limit="Rate limited (429 on abuse)",
        data_license="Public blockchain data",
    ),
    SourceProvenance(
        source_id="src_etherscan",
        name="Etherscan",
        api_endpoint="https://api.etherscan.io/api",
        auth_required=True,
        auth_type="query_param:apikey",
        free_tier=True,
        tos_url="https://docs.etherscan.io/",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Free key: 5 req/sec. Create account at etherscan.io.",
        rate_limit="5 req/sec (free tier)",
        data_license="Public blockchain data",
    ),

    # ── CERT advisories (Admiralty grade A) ──────────────────
    SourceProvenance(
        source_id="src_cisa",
        name="CISA Known Exploited Vulnerabilities",
        api_endpoint="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://www.cisa.gov/",
        tos_reviewed=True,
        legal_basis="us_government_public_domain",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="US government public data. Highest reliability grade (A1). Includes ransomware campaign flags.",
        rate_limit="Static JSON feed",
        data_license="US Government Public Domain",
    ),

    # ── Phase 3: Additional sources ──────────────────────────
    SourceProvenance(
        source_id="src_otx",
        name="AlienVault OTX",
        api_endpoint="https://otx.alienvault.com/api/v1/pulses/subscribed",
        auth_required=True,
        auth_type="header:X-OTX-API-KEY",
        free_tier=True,
        tos_url="https://otx.alienvault.com/api",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Free key from otx.alienvault.com. 10K req/hour. Pulses with IOCs + ATT&CK mappings.",
        rate_limit="10,000 req/hour",
        data_license="Free / community",
    ),
    SourceProvenance(
        source_id="src_greynoise",
        name="GreyNoise Community API",
        api_endpoint="https://api.greynoise.io/v3/community/{ip}",
        auth_required=True,
        auth_type="header:key",
        free_tier=True,
        tos_url="https://www.greynoise.io/terms",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Free community key. Tags scanning/attack IPs. On-demand lookups only.",
        rate_limit="Community tier (limited)",
        data_license="Free community",
    ),
    SourceProvenance(
        source_id="src_sslbl",
        name="abuse.ch SSLBL",
        api_endpoint="https://sslbl.abuse.ch/blacklist/sslblacklist.json",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://sslbl.abuse.ch/",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Static JSON feed, no auth. SSL cert fingerprints used by botnets.",
        rate_limit="Static feed",
        data_license="Non-commercial / research",
    ),
    SourceProvenance(
        source_id="src_sigmahq",
        name="SigmaHQ Detection Rules",
        api_endpoint="https://api.github.com/repos/SigmaHQ/sigma/contents/rules",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://github.com/SigmaHQ/sigma/blob/master/LICENSE",
        tos_reviewed=True,
        legal_basis="open_source",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="MIT license. YAML detection rules with MITRE ATT&CK actor/technique tags.",
        rate_limit="GitHub API: 60 req/hour unauthenticated",
        data_license="MIT",
    ),
    SourceProvenance(
        source_id="src_certstream",
        name="CertStream (real-time CT)",
        api_endpoint="wss://certstream.calidog.io/",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://github.com/CaliDog/certstream-server",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Open-source WebSocket CT feed. MIT license. Real-time cert issuance stream.",
        rate_limit="Unlimited (streaming)",
        data_license="MIT",
    ),
    SourceProvenance(
        source_id="src_tor_exits",
        name="Tor Bulk Exit List",
        api_endpoint="https://check.torproject.org/torbulkexitlist",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://www.torproject.org/",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Official Tor Project. List of current exit node IPs. Noise filter for infra correlation.",
        rate_limit="Fair use",
        data_license="Public",
    ),
    SourceProvenance(
        source_id="src_pgp_keyserver",
        name="OpenPGP Keyserver",
        api_endpoint="https://keys.openpgp.org/vks/v1/by-fingerprint/{fp}",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://keys.openpgp.org/about",
        tos_reviewed=True,
        legal_basis="public_data",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="Public keyserver. Lookup PGP keys by fingerprint/email. On-demand only.",
        rate_limit="Fair use",
        data_license="Public",
    ),
    SourceProvenance(
        source_id="src_gwern_silk_road",
        name="Gwern Silk Road Archive",
        api_endpoint="N/A — local file processing",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://www.gwern.net/DNM-archives",
        tos_reviewed=True,
        legal_basis="public_research_archive",
        verification_status=VerificationStatus.VERIFIED,
        verification_date="2026-09-29",
        verification_notes="VERIFIED public archive. Widely cited in academic literature (CMU, Oxford). Download + local processing.",
        rate_limit="N/A (local)",
        data_license="Public research",
    ),
]


# ── Flagged sources (DO NOT build until manually verified) ──

FLAGGED_SOURCES: list[SourceProvenance] = [
    SourceProvenance(
        source_id="src_dark_fail",
        name="dark.fail",
        api_endpoint="N/A — no public API",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="N/A",
        tos_reviewed=False,
        legal_basis="unknown",
        verification_status=VerificationStatus.FLAGGED,
        verification_date="2026-09-29",
        verification_notes="FLAGGED: dark.fail has asked researchers not to scrape or mirror. Use as human reference only, not automated source.",
        rate_limit="N/A",
        data_license="N/A — not a data source for automation",
    ),
    SourceProvenance(
        source_id="src_chainabuse",
        name="Chainabuse",
        api_endpoint="https://www.chainabuse.com/",
        auth_required=False,
        auth_type="none",
        free_tier=True,
        tos_url="https://www.chainabuse.com/terms",
        tos_reviewed=False,
        legal_basis="unknown",
        verification_status=VerificationStatus.FLAGGED,
        verification_date="2026-09-29",
        verification_notes="FLAGGED: ToS may prohibit scraping. Check before building adapter.",
        rate_limit="Unknown",
        data_license="Unknown — check ToS",
    ),
    SourceProvenance(
        source_id="src_dehashed",
        name="DeHashed",
        api_endpoint="https://api.dehashed.com/search",
        auth_required=True,
        auth_type="basic_auth",
        free_tier=False,
        tos_url="https://www.dehashed.com/legal",
        tos_reviewed=False,
        legal_basis="paid_service",
        verification_status=VerificationStatus.FLAGGED,
        verification_date="2026-09-29",
        verification_notes="FLAGGED: Paid service with limited free search. Do not build assuming free access.",
        rate_limit="Paid tiers only",
        data_license="Paid subscription",
    ),
]


# ── Dropped sources ─────────────────────────────────────────

DROPPED_SOURCES: list[SourceProvenance] = [
    SourceProvenance(
        source_id="src_alphabay",
        name="AlphaBay takedown data",
        api_endpoint="N/A",
        auth_required=False,
        auth_type="none",
        free_tier=False,
        tos_url="N/A",
        tos_reviewed=False,
        legal_basis="unverified",
        verification_status=VerificationStatus.DROPPED,
        verification_date="2026-09-29",
        verification_notes="DROPPED: No confirmed public DOJ/academic download link found. Cannot cite a concrete source.",
        rate_limit="N/A",
        data_license="N/A",
    ),
    SourceProvenance(
        source_id="src_hansa",
        name="Hansa takedown data",
        api_endpoint="N/A",
        auth_required=False,
        auth_type="none",
        free_tier=False,
        tos_url="N/A",
        tos_reviewed=False,
        legal_basis="unverified",
        verification_status=VerificationStatus.DROPPED,
        verification_date="2026-09-29",
        verification_notes="DROPPED: No confirmed Dutch police public release found. Cannot cite a concrete source.",
        rate_limit="N/A",
        data_license="N/A",
    ),
    SourceProvenance(
        source_id="src_telegram",
        name="Telegram Bot API (threat actor channels)",
        api_endpoint="https://api.telegram.org/",
        auth_required=True,
        auth_type="bot_token",
        free_tier=True,
        tos_url="https://core.telegram.org/api/terms",
        tos_reviewed=False,
        legal_basis="problematic",
        verification_status=VerificationStatus.DROPPED,
        verification_date="2026-09-29",
        verification_notes="DROPPED: Monitoring threat-actor Telegram channels = live-target-discovery problem. Same risk profile as onion market scraping. Remove from prototype.",
        rate_limit="N/A",
        data_license="N/A",
    ),
]


def get_verified_source(source_id: str) -> SourceProvenance | None:
    """Look up a verified source by ID."""
    for s in VERIFIED_SOURCES:
        if s.source_id == source_id:
            return s
    return None


def get_all_provenances() -> dict[str, list[SourceProvenance]]:
    """Get all source provenances grouped by status."""
    return {
        "verified": VERIFIED_SOURCES,
        "flagged": FLAGGED_SOURCES,
        "dropped": DROPPED_SOURCES,
    }
