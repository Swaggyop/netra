"""
NETRA — Tor network intelligence adapter (Phase 1).

Pulls Tor relay and network data from:
  1. Onionoo API   — structured JSON relay search (fingerprint, contact, flags, bandwidth)
  2. CollecTor     — bulk relay descriptors and consensus documents

Source provenance:
  - Onionoo: https://metrics.torproject.org/onionoo.html (verified, no auth)
    Endpoints:
      GET https://onionoo.torproject.org/summary  — lightweight relay list
      GET https://onionoo.torproject.org/details   — full relay details
      GET https://onionoo.torproject.org/bandwidth — bandwidth history
      GET https://onionoo.torproject.org/uptime    — uptime history
    Rate: fair use (implement caching, use Accept-Encoding: gzip)
  - CollecTor: https://collector.torproject.org/ (verified, no auth)
    Bulk download via HTTPS — consensus and server descriptors

Key entity extraction from relay data:
  - Contact fields often contain: email, PGP fingerprint, handle, org name
  - Platform field: OS + Tor version → infra fingerprinting
  - Fingerprint: unique relay ID → graph node
  - Flags: Guard, Exit, BadExit, Authority → behavior profiling
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from backend.app.adapters.http_client import LiveHTTPClient
from backend.app.core.events import (
    AdapterType,
    CollectionMode,
    ContentType,
    RawEvent,
    Topics,
    create_event_bus,
)
from backend.app.core.provenance import compute_content_hash

logger = logging.getLogger(__name__)


# ── Contact field parser ────────────────────────────────────

# Tor relay operators put contact info in free-form text.
# Common patterns: email, PGP fingerprint, handles, URLs

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PGP_FP_RE = re.compile(r"[0-9A-Fa-f]{40}")
PGP_SHORT_RE = re.compile(r"0x[0-9A-Fa-f]{8,16}")
URL_RE = re.compile(r"https?://[\w./?&=%-]+")
HANDLE_RE = re.compile(r"@[\w]{3,30}")


def parse_contact_field(contact: str) -> dict[str, list[str]]:
    """
    Extract structured identifiers from a Tor relay contact field.

    Relay operators often put email, PGP keys, handles, and URLs in
    their contact field. This is a rich source of entity identifiers.
    """
    if not contact:
        return {}

    result: dict[str, list[str]] = {}

    emails = EMAIL_RE.findall(contact)
    if emails:
        result["emails"] = emails

    pgp_fps = PGP_FP_RE.findall(contact)
    if pgp_fps:
        result["pgp_fingerprints"] = pgp_fps

    pgp_shorts = PGP_SHORT_RE.findall(contact)
    if pgp_shorts:
        result["pgp_short_ids"] = pgp_shorts

    urls = URL_RE.findall(contact)
    if urls:
        result["urls"] = urls

    handles = HANDLE_RE.findall(contact)
    if handles:
        result["handles"] = handles

    return result


# ── Onionoo adapter ────────────────────────────────────────

class OnionooAdapter:
    """
    Pulls Tor relay details from the Onionoo API.

    This is the richest structured source of relay data — much better
    than parsing raw CollecTor descriptors.

    Key data for NETRA:
    - Relay fingerprints → unique node IDs in the graph
    - Contact fields → email, PGP, handles, org names
    - Platform → OS/Tor version for infra fingerprinting
    - Flags → Guard/Exit/BadExit classification
    - Bandwidth → capacity profiling
    - AS number/name → network-level correlation
    """

    BASE_URL = "https://onionoo.torproject.org"
    SOURCE_ID = "src_onionoo"

    def __init__(self) -> None:
        self._client = LiveHTTPClient("onionoo")

    async def get_relay_details(
        self,
        *,
        search: str | None = None,
        flag: str | None = None,
        contact: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """
        Fetch relay details from Onionoo.

        Args:
            search: Free-text search (IP, nickname, fingerprint)
            flag: Filter by flag (e.g. 'Exit', 'Guard', 'BadExit')
            contact: Filter by contact field content
            limit: Max relays to return
        """
        params: dict[str, Any] = {"limit": limit}
        if search:
            params["search"] = search
        if flag:
            params["flag"] = flag
        if contact:
            params["contact"] = contact

        async with self._client:
            response = await self._client.get(
                f"{self.BASE_URL}/details",
                params=params,
                headers={"Accept-Encoding": "gzip"},
            )
            data = response.json()

        relays = data.get("relays", [])
        bridges = data.get("bridges", [])
        logger.info(
            "Onionoo: fetched %d relays, %d bridges",
            len(relays), len(bridges),
        )
        return relays + bridges

    async def get_relay_summary(self) -> dict[str, Any]:
        """Get lightweight summary of all running relays."""
        async with self._client:
            response = await self._client.get(
                f"{self.BASE_URL}/summary",
                headers={"Accept-Encoding": "gzip"},
            )
            return response.json()

    async def get_relay_uptime(self, fingerprint: str) -> dict[str, Any]:
        """Get uptime history for a specific relay."""
        async with self._client:
            response = await self._client.get(
                f"{self.BASE_URL}/uptime",
                params={"lookup": fingerprint},
                headers={"Accept-Encoding": "gzip"},
            )
            return response.json()

    async def collect_and_publish(self, limit: int = 500) -> dict[str, int]:
        """
        Fetch relay details and publish to event bus.

        Extracts entities from contact fields and creates events
        for each relay with its identifiers.
        """
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0
        relays_with_contact = 0

        try:
            relays = await self.get_relay_details(limit=limit)

            for relay in relays:
                try:
                    fingerprint = relay.get("fingerprint", "")
                    contact = relay.get("contact", "")
                    nickname = relay.get("nickname", "")

                    # Parse contact field for entities
                    contact_entities = parse_contact_field(contact)
                    if contact_entities:
                        relays_with_contact += 1

                    # Build metadata
                    content = json.dumps(relay, ensure_ascii=False)
                    content_hash = compute_content_hash(content.encode("utf-8"))

                    # Parse first_seen
                    observed_at = datetime.now(UTC)
                    if relay.get("first_seen"):
                        try:
                            observed_at = datetime.fromisoformat(
                                relay["first_seen"].replace(" ", "T")
                            )
                        except (ValueError, AttributeError):
                            pass

                    or_addresses = relay.get("or_addresses", [])
                    # Extract IPs from OR addresses (format: "ip:port")
                    relay_ips = []
                    for addr in or_addresses:
                        ip = addr.rsplit(":", 1)[0].strip("[]")
                        if ip:
                            relay_ips.append(ip)

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.OSINT_FEED,
                        mode=CollectionMode.LIVE,
                        observed_at=observed_at,
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/onionoo/{fingerprint[:16]}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "tor_relay",
                            "fingerprint": fingerprint,
                            "nickname": nickname,
                            "contact": contact,
                            "contact_entities": contact_entities,
                            "platform": relay.get("platform", ""),
                            "flags": relay.get("flags", []),
                            "as_number": relay.get("as", ""),
                            "as_name": relay.get("as_name", ""),
                            "country": relay.get("country", ""),
                            "relay_ips": relay_ips,
                            "bandwidth_rate": relay.get("bandwidth_rate", 0),
                            "consensus_weight": relay.get("consensus_weight", 0),
                            "first_seen": relay.get("first_seen", ""),
                            "last_seen": relay.get("last_seen", ""),
                            "running": relay.get("running", False),
                            "text": content,
                        },
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to publish relay %s: %s", fingerprint[:8], exc)
                    errors += 1

        finally:
            await bus.stop()

        return {
            "source": self.SOURCE_ID,
            "relays_fetched": len(relays),
            "relays_with_contact": relays_with_contact,
            "published": published,
            "errors": errors,
        }


# ── CERT advisory adapter ──────────────────────────────────

class CERTAdvisoryAdapter:
    """
    Pulls government CERT advisories — high-reliability source (Admiralty A1).

    Sources:
      - CISA: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
      - CERT-In: RSS feeds (manual for now)

    These advisories name ransomware groups, TTPs, and IOCs.
    They carry the highest source reliability grade (A — completely reliable).

    Source provenance:
      - CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (verified, no auth)
      - License: US government public domain
    """

    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    SOURCE_ID = "src_cisa"

    def __init__(self) -> None:
        self._client = LiveHTTPClient("default")

    async def collect_cisa_kev(self) -> list[dict[str, Any]]:
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        async with self._client:
            response = await self._client.get(self.CISA_KEV_URL)
            data = response.json()

        vulns = data.get("vulnerabilities", [])
        logger.info("CISA KEV: fetched %d known exploited vulnerabilities", len(vulns))
        return vulns

    async def collect_and_publish(self) -> dict[str, int]:
        """Fetch CISA advisories and publish to event bus."""
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0

        try:
            vulns = await self.collect_cisa_kev()

            # Only publish entries with ransomware mentions
            ransomware_keywords = {
                "ransomware", "lockbit", "blackcat", "alphv", "clop", "royal",
                "akira", "rhysida", "play", "medusa", "bianlian", "conti",
            }

            for vuln in vulns:
                try:
                    notes = (vuln.get("knownRansomwareCampaignUse", "") or "").lower()
                    short_desc = (vuln.get("shortDescription", "") or "").lower()
                    combined_text = f"{notes} {short_desc}"

                    # Check if ransomware-related
                    is_ransomware = notes == "known" or any(
                        kw in combined_text for kw in ransomware_keywords
                    )

                    if not is_ransomware:
                        continue

                    content = json.dumps(vuln, ensure_ascii=False)
                    content_hash = compute_content_hash(content.encode("utf-8"))

                    observed_at = datetime.now(UTC)
                    if vuln.get("dateAdded"):
                        try:
                            observed_at = datetime.fromisoformat(vuln["dateAdded"])
                        except (ValueError, AttributeError):
                            pass

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.OSINT_FEED,
                        mode=CollectionMode.LIVE,
                        observed_at=observed_at,
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/cisa/{vuln.get('cveID', uuid.uuid4().hex[:12])}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "cert_advisory",
                            "source_reliability": "A",  # Admiralty grade A
                            "information_credibility": "1",  # Confirmed
                            "cve_id": vuln.get("cveID", ""),
                            "vendor": vuln.get("vendorProject", ""),
                            "product": vuln.get("product", ""),
                            "vulnerability_name": vuln.get("vulnerabilityName", ""),
                            "ransomware_use": vuln.get("knownRansomwareCampaignUse", ""),
                            "description": vuln.get("shortDescription", ""),
                            "text": content,
                        },
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to publish CISA advisory: %s", exc)
                    errors += 1

        finally:
            await bus.stop()

        return {"source": self.SOURCE_ID, "published": published, "errors": errors}


# ── Orchestrator ────────────────────────────────────────────

async def collect_tor_and_infra_intel() -> dict[str, Any]:
    """Run Tor network + CERT advisory adapters."""
    results: dict[str, Any] = {"started_at": datetime.now(UTC).isoformat()}

    # 1. Onionoo relay data
    try:
        adapter = OnionooAdapter()
        results["onionoo"] = await adapter.collect_and_publish(limit=500)
    except Exception as exc:
        logger.error("Onionoo collection failed: %s", exc, exc_info=True)
        results["onionoo"] = {"error": str(exc)}

    # 2. CISA advisories
    try:
        adapter = CERTAdvisoryAdapter()
        results["cisa"] = await adapter.collect_and_publish()
    except Exception as exc:
        logger.error("CISA collection failed: %s", exc, exc_info=True)
        results["cisa"] = {"error": str(exc)}

    results["completed_at"] = datetime.now(UTC).isoformat()
    return results
