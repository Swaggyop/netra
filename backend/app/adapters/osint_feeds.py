"""
NETRA — OSINT feed aggregator adapter (Phase 3).

Pulls threat intelligence from supplementary OSINT sources:
  1. AlienVault OTX     — pulses with IOCs, malware family tags, campaign data
  2. GreyNoise Community — tags scanning/attack traffic by actor infrastructure
  3. PhishTank          — phishing URLs, dark-web-adjacent infra overlaps
  4. SSLBL (abuse.ch)   — SSL certs used by botnets (cert fingerprint pivots)

Source provenance:
  - OTX: https://otx.alienvault.com/api (verified, free key, X-OTX-API-KEY header)
    Endpoint: GET https://otx.alienvault.com/api/v1/pulses/subscribed
    Rate: 10,000 req/hour with key
  - GreyNoise: https://docs.greynoise.io/docs/community-api (verified, free community key)
    Endpoint: GET https://api.greynoise.io/v3/community/{ip}
    Rate: limited free tier
  - PhishTank: https://phishtank.org/developer_info.php (verified, free key)
    Endpoint: GET https://data.phishtank.com/data/online-valid.json
    Rate: download full feed, cache locally
  - SSLBL: https://sslbl.abuse.ch/ (verified, no auth)
    Endpoint: GET https://sslbl.abuse.ch/blacklist/sslblacklist.json
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from backend.app.adapters.http_client import LiveHTTPClient
from backend.app.config import get_settings
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


# ── AlienVault OTX adapter ──────────────────────────────────

class OTXAdapter:
    """
    Pulls threat intelligence pulses from AlienVault OTX.

    Each pulse contains IOCs (IPs, domains, hashes, URLs), malware family
    tags, and campaign references. Cross-references with actor groups.

    Endpoint: GET https://otx.alienvault.com/api/v1/pulses/subscribed
    Auth: X-OTX-API-KEY header (free, 10K req/hour)
    """

    BASE_URL = "https://otx.alienvault.com/api/v1"
    SOURCE_ID = "src_otx"

    def __init__(self) -> None:
        self._settings = get_settings()
        self._client = LiveHTTPClient("otx")

    def _headers(self) -> dict[str, str]:
        key = self._settings.otx_api_key
        if not key:
            raise ValueError("OTX_API_KEY not set — free at otx.alienvault.com")
        return {"X-OTX-API-KEY": key}

    async def get_subscribed_pulses(self, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch pulses from subscribed feeds."""
        async with self._client:
            response = await self._client.get(
                f"{self.BASE_URL}/pulses/subscribed",
                headers=self._headers(),
                params={"limit": limit, "page": 1},
            )
            data = response.json()
        pulses = data.get("results", [])
        logger.info("OTX: fetched %d subscribed pulses", len(pulses))
        return pulses

    async def search_pulses(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """Search OTX pulses by keyword."""
        async with self._client:
            response = await self._client.get(
                f"{self.BASE_URL}/search/pulses",
                headers=self._headers(),
                params={"q": query, "limit": limit, "page": 1},
            )
            data = response.json()
        return data.get("results", [])

    async def get_indicator_details(
        self, indicator_type: str, indicator: str
    ) -> dict[str, Any]:
        """
        Get details for a specific IOC.

        indicator_type: 'IPv4', 'domain', 'hostname', 'url', 'FileHash-SHA256'
        """
        async with self._client:
            response = await self._client.get(
                f"{self.BASE_URL}/indicators/{indicator_type}/{indicator}/general",
                headers=self._headers(),
            )
            return response.json()

    async def collect_and_publish(self) -> dict[str, int]:
        """Fetch pulses and publish to event bus."""
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0

        try:
            pulses = await self.get_subscribed_pulses(limit=50)

            for pulse in pulses:
                try:
                    indicators = pulse.get("indicators", [])
                    content = json.dumps(pulse, ensure_ascii=False)
                    content_hash = compute_content_hash(content.encode("utf-8"))

                    # Extract IOCs by type
                    ioc_summary: dict[str, int] = {}
                    for ind in indicators:
                        itype = ind.get("type", "unknown")
                        ioc_summary[itype] = ioc_summary.get(itype, 0) + 1

                    observed_at = datetime.now(UTC)
                    if pulse.get("created"):
                        try:
                            observed_at = datetime.fromisoformat(
                                pulse["created"].replace("Z", "+00:00")
                            )
                        except (ValueError, AttributeError):
                            pass

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.OSINT_FEED,
                        mode=CollectionMode.LIVE,
                        observed_at=observed_at,
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/otx/{pulse.get('id', uuid.uuid4().hex[:12])}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "otx_pulse",
                            "pulse_id": pulse.get("id", ""),
                            "name": pulse.get("name", ""),
                            "description": pulse.get("description", "")[:500],
                            "tags": pulse.get("tags", []),
                            "targeted_countries": pulse.get("targeted_countries", []),
                            "malware_families": pulse.get("malware_families", []),
                            "attack_ids": pulse.get("attack_ids", []),
                            "ioc_count": len(indicators),
                            "ioc_summary": ioc_summary,
                            "adversary": pulse.get("adversary", ""),
                            "text": content[:5000],
                        },
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to publish OTX pulse: %s", exc)
                    errors += 1

        finally:
            await bus.stop()

        return {"source": self.SOURCE_ID, "published": published, "errors": errors}


# ── GreyNoise Community adapter ─────────────────────────────

class GreyNoiseAdapter:
    """
    Tags internet-wide scanning/attack traffic by actor infrastructure.

    Useful for identifying when an IP found in our data is a known
    scanner, benign service, or associated with specific threat activity.

    Endpoint: GET https://api.greynoise.io/v3/community/{ip}
    Auth: key header (free community tier)
    """

    BASE_URL = "https://api.greynoise.io/v3/community"
    SOURCE_ID = "src_greynoise"

    def __init__(self) -> None:
        self._settings = get_settings()
        self._client = LiveHTTPClient("greynoise")

    def _headers(self) -> dict[str, str]:
        key = self._settings.greynoise_api_key
        if not key:
            raise ValueError("GREYNOISE_API_KEY not set")
        return {"key": key}

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Check if an IP is a known scanner/attacker."""
        async with self._client:
            response = await self._client.get(
                f"{self.BASE_URL}/{ip}",
                headers=self._headers(),
            )
            return response.json()

    async def lookup_ips_and_publish(self, ips: list[str]) -> dict[str, int]:
        """Look up multiple IPs and publish results."""
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0

        try:
            for ip in ips[:50]:  # Cap to avoid rate limits
                try:
                    data = await self.lookup_ip(ip)

                    if not data or data.get("message") == "IP not found":
                        continue

                    content = json.dumps(data, ensure_ascii=False)
                    content_hash = compute_content_hash(content.encode("utf-8"))

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.CLEARNET_INTEL,
                        mode=CollectionMode.LIVE,
                        observed_at=datetime.now(UTC),
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/greynoise/{ip.replace('.', '_')}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "ip_reputation",
                            "ip": data.get("ip", ip),
                            "noise": data.get("noise", False),
                            "riot": data.get("riot", False),
                            "classification": data.get("classification", ""),
                            "name": data.get("name", ""),
                            "link": data.get("link", ""),
                            "last_seen": data.get("last_seen", ""),
                            "text": content,
                        },
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("GreyNoise lookup failed for %s: %s", ip, exc)
                    errors += 1

        finally:
            await bus.stop()

        return {"source": self.SOURCE_ID, "published": published, "errors": errors}


# ── SSLBL adapter ───────────────────────────────────────────

class SSLBLAdapter:
    """
    SSL certificates used by botnets — cert fingerprint pivots.

    If a cert SHA1 from SSLBL matches a cert seen on an actor's infra,
    that's a direct link to botnet/malware activity.

    Endpoint: GET https://sslbl.abuse.ch/blacklist/sslblacklist.json
    Auth: none
    """

    BLOCKLIST_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.json"
    SOURCE_ID = "src_sslbl"

    def __init__(self) -> None:
        self._client = LiveHTTPClient("default")

    async def collect_and_publish(self) -> dict[str, int]:
        """Fetch SSL blacklist and publish to event bus."""
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0

        try:
            async with self._client:
                response = await self._client.get(self.BLOCKLIST_URL)
                data = response.json()

            entries = data if isinstance(data, list) else []
            logger.info("SSLBL: fetched %d SSL cert entries", len(entries))

            for entry in entries:
                try:
                    content = json.dumps(entry, ensure_ascii=False)
                    content_hash = compute_content_hash(content.encode("utf-8"))

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.OSINT_FEED,
                        mode=CollectionMode.LIVE,
                        observed_at=datetime.now(UTC),
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/sslbl/{uuid.uuid4().hex[:12]}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "ssl_blacklist",
                            "sha1": entry.get("sha1", ""),
                            "subject": entry.get("subject", ""),
                            "issuer": entry.get("issuer", ""),
                            "reason": entry.get("reason", ""),
                            "text": content,
                        },
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("SSLBL publish failed: %s", exc)
                    errors += 1

        finally:
            await bus.stop()

        return {"source": self.SOURCE_ID, "published": published, "errors": errors}


# ── Orchestrator ────────────────────────────────────────────

async def collect_osint_feeds() -> dict[str, Any]:
    """Run all OSINT feed adapters."""
    results: dict[str, Any] = {"started_at": datetime.now(UTC).isoformat()}
    settings = get_settings()

    # OTX
    if settings.otx_api_key:
        try:
            results["otx"] = await OTXAdapter().collect_and_publish()
        except Exception as exc:
            logger.error("OTX failed: %s", exc, exc_info=True)
            results["otx"] = {"error": str(exc)}
    else:
        results["otx"] = {"skipped": "OTX_API_KEY not set"}

    # SSLBL (no auth)
    try:
        results["sslbl"] = await SSLBLAdapter().collect_and_publish()
    except Exception as exc:
        logger.error("SSLBL failed: %s", exc, exc_info=True)
        results["sslbl"] = {"error": str(exc)}

    results["completed_at"] = datetime.now(UTC).isoformat()
    return results
