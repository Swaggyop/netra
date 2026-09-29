"""
NETRA — abuse.ch threat intel adapter (Phase 1).

Pulls IOCs from four abuse.ch feeds:
  1. URLhaus     — malicious URLs (many onion/dark web C2 servers)
  2. ThreatFox   — IOCs: domains, IPs, hashes linked to threat actors
  3. MalwareBazaar — malware sample hashes tied to families/actors
  4. Feodo Tracker — botnet C2 IPs (static JSON, no auth)

Source provenance:
  - URLhaus API docs: https://urlhaus-api.abuse.ch/ (verified 2024-12)
  - ThreatFox API docs: https://threatfox-api.abuse.ch/ (verified 2024-12)
  - MalwareBazaar API docs: https://bazaar.abuse.ch/api/ (verified 2024-12)
  - Feodo Tracker: https://feodotracker.abuse.ch/ (verified 2024-12)
  - Auth: free Auth-Key via https://auth.abuse.ch/ (URLhaus, ThreatFox, MalwareBazaar)
  - Feodo: no auth required
  - License: free for non-commercial / research use (fair use policy)
  - ToS verified: yes — redistribution as a feed/API is prohibited, internal use is permitted
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
from backend.app.core.redaction import redact_pii

logger = logging.getLogger(__name__)


# ── URLhaus adapter ─────────────────────────────────────────

class URLhausAdapter:
    """
    Pulls malicious URLs from URLhaus.

    Many entries are onion/dark-web C2 servers, ransomware infrastructure,
    or malware distribution points. Cross-references with actor groups via tags.

    Endpoint: POST https://urlhaus-api.abuse.ch/v1/
    Auth: Auth-Key header (free from https://auth.abuse.ch/)
    """

    API_URL = "https://urlhaus-api.abuse.ch/v1"
    SOURCE_ID = "src_urlhaus"

    def __init__(self) -> None:
        self._settings = get_settings()
        self._client = LiveHTTPClient("urlhaus")

    def _auth_header(self) -> dict[str, str]:
        key = self._settings.abuse_ch_auth_key
        if not key:
            raise ValueError("ABUSE_CH_AUTH_KEY not set — get one free at https://auth.abuse.ch/")
        return {"Auth-Key": key}

    async def collect_recent_urls(self, limit: int = 1000) -> list[dict[str, Any]]:
        """Fetch recently added malicious URLs."""
        async with self._client:
            response = await self._client.post(
                f"{self.API_URL}/urls/recent/",
                headers=self._auth_header(),
                json={"limit": str(limit)},
            )
            data = response.json()
        urls = data.get("urls", [])
        logger.info("URLhaus: fetched %d recent URLs", len(urls))
        return urls

    async def collect_urls_by_tag(self, tag: str) -> list[dict[str, Any]]:
        """Fetch URLs tagged with a specific malware family (e.g. 'LockBit')."""
        async with self._client:
            response = await self._client.post(
                f"{self.API_URL}/tag/{tag}/",
                headers=self._auth_header(),
            )
            data = response.json()
        urls = data.get("urls", [])
        logger.info("URLhaus: fetched %d URLs for tag '%s'", len(urls), tag)
        return urls

    async def collect_and_publish(self) -> dict[str, int]:
        """Fetch recent URLs and publish to event bus."""
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0

        try:
            urls = await self.collect_recent_urls(limit=500)

            for entry in urls:
                try:
                    url = entry.get("url", "")
                    content = json.dumps(entry, ensure_ascii=False)
                    redaction = redact_pii(content)
                    content_hash = compute_content_hash(
                        redaction.redacted_text.encode("utf-8")
                    )

                    # Parse date
                    observed_at = datetime.now(UTC)
                    if entry.get("date_added"):
                        try:
                            observed_at = datetime.fromisoformat(
                                entry["date_added"].replace(" ", "T").replace("Z", "+00:00")
                            )
                        except (ValueError, AttributeError):
                            pass

                    is_onion = ".onion" in url

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.OSINT_FEED,
                        mode=CollectionMode.LIVE,
                        observed_at=observed_at,
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/urlhaus/{uuid.uuid4().hex[:12]}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "malicious_url",
                            "url": url,
                            "url_status": entry.get("url_status", ""),
                            "threat": entry.get("threat", ""),
                            "tags": entry.get("tags", []),
                            "reporter": entry.get("reporter", ""),
                            "is_onion": is_onion,
                            "text": content,
                        },
                        redactions=redaction.redactions,
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to publish URLhaus entry: %s", exc)
                    errors += 1

        finally:
            await bus.stop()

        return {"source": self.SOURCE_ID, "published": published, "errors": errors}


# ── ThreatFox adapter ───────────────────────────────────────

class ThreatFoxAdapter:
    """
    Pulls IOCs from ThreatFox — domains, IPs, hashes linked to threat actors.

    Endpoint: POST https://threatfox-api.abuse.ch/api/v1/
    Auth: Auth-Key header
    """

    API_URL = "https://threatfox-api.abuse.ch/api/v1/"
    SOURCE_ID = "src_threatfox"

    def __init__(self) -> None:
        self._settings = get_settings()
        self._client = LiveHTTPClient("threatfox")

    def _auth_header(self) -> dict[str, str]:
        key = self._settings.abuse_ch_auth_key
        if not key:
            raise ValueError("ABUSE_CH_AUTH_KEY not set")
        return {"Auth-Key": key}

    async def collect_recent_iocs(self, days: int = 7) -> list[dict[str, Any]]:
        """Fetch IOCs from the last N days."""
        async with self._client:
            response = await self._client.post(
                self.API_URL,
                headers=self._auth_header(),
                json={"query": "get_iocs", "days": days},
            )
            data = response.json()
        iocs = data.get("data", [])
        logger.info("ThreatFox: fetched %d IOCs (last %d days)", len(iocs) if iocs else 0, days)
        return iocs if isinstance(iocs, list) else []

    async def search_ioc(self, search_term: str) -> list[dict[str, Any]]:
        """Search for a specific IOC (domain, IP, hash)."""
        async with self._client:
            response = await self._client.post(
                self.API_URL,
                headers=self._auth_header(),
                json={"query": "search_ioc", "search_term": search_term},
            )
            data = response.json()
        return data.get("data", []) or []

    async def collect_and_publish(self) -> dict[str, int]:
        """Fetch recent IOCs and publish to event bus."""
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0

        try:
            iocs = await self.collect_recent_iocs(days=7)

            for ioc in iocs:
                try:
                    content = json.dumps(ioc, ensure_ascii=False)
                    redaction = redact_pii(content)
                    content_hash = compute_content_hash(
                        redaction.redacted_text.encode("utf-8")
                    )

                    observed_at = datetime.now(UTC)
                    if ioc.get("first_seen"):
                        try:
                            observed_at = datetime.fromisoformat(
                                ioc["first_seen"].replace(" ", "T").replace("Z", "+00:00")
                            )
                        except (ValueError, AttributeError):
                            pass

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.OSINT_FEED,
                        mode=CollectionMode.LIVE,
                        observed_at=observed_at,
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/threatfox/{uuid.uuid4().hex[:12]}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "ioc",
                            "ioc_type": ioc.get("ioc_type", ""),
                            "ioc_value": ioc.get("ioc", ""),
                            "threat_type": ioc.get("threat_type", ""),
                            "malware": ioc.get("malware", ""),
                            "malware_alias": ioc.get("malware_alias", ""),
                            "confidence_level": ioc.get("confidence_level", 0),
                            "reporter": ioc.get("reporter", ""),
                            "tags": ioc.get("tags", []),
                            "text": content,
                        },
                        redactions=redaction.redactions,
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to publish ThreatFox IOC: %s", exc)
                    errors += 1

        finally:
            await bus.stop()

        return {"source": self.SOURCE_ID, "published": published, "errors": errors}


# ── MalwareBazaar adapter ──────────────────────────────────

class MalwareBazaarAdapter:
    """
    Pulls malware sample metadata from MalwareBazaar — hashes tied to
    malware families and actors.

    Endpoint: POST https://mb-api.abuse.ch/api/v1/
    Auth: Auth-Key header

    NOTE: We pull metadata ONLY, never actual malware samples.
    """

    API_URL = "https://mb-api.abuse.ch/api/v1/"
    SOURCE_ID = "src_malwarebazaar"

    def __init__(self) -> None:
        self._settings = get_settings()
        self._client = LiveHTTPClient("malwarebazaar")

    def _auth_header(self) -> dict[str, str]:
        key = self._settings.abuse_ch_auth_key
        if not key:
            raise ValueError("ABUSE_CH_AUTH_KEY not set")
        return {"Auth-Key": key}

    async def collect_recent_samples(self, limit: int = 100) -> list[dict[str, Any]]:
        """Fetch metadata for recently submitted samples."""
        async with self._client:
            response = await self._client.post(
                self.API_URL,
                headers=self._auth_header(),
                data={"query": "get_recent", "selector": str(limit)},
            )
            data = response.json()
        samples = data.get("data", [])
        logger.info("MalwareBazaar: fetched %d sample records", len(samples) if samples else 0)
        return samples if isinstance(samples, list) else []

    async def query_by_tag(self, tag: str) -> list[dict[str, Any]]:
        """Query samples by malware family tag (e.g. 'LockBit')."""
        async with self._client:
            response = await self._client.post(
                self.API_URL,
                headers=self._auth_header(),
                data={"query": "get_taginfo", "tag": tag, "limit": "50"},
            )
            data = response.json()
        return data.get("data", []) or []

    async def collect_and_publish(self) -> dict[str, int]:
        """Fetch recent sample metadata and publish to event bus."""
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0

        try:
            samples = await self.collect_recent_samples(limit=100)

            for sample in samples:
                try:
                    content = json.dumps(sample, ensure_ascii=False)
                    content_hash = compute_content_hash(content.encode("utf-8"))

                    observed_at = datetime.now(UTC)
                    if sample.get("first_seen"):
                        try:
                            observed_at = datetime.fromisoformat(
                                sample["first_seen"].replace(" ", "T").replace("Z", "+00:00")
                            )
                        except (ValueError, AttributeError):
                            pass

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.OSINT_FEED,
                        mode=CollectionMode.LIVE,
                        observed_at=observed_at,
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/malwarebazaar/{uuid.uuid4().hex[:12]}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "malware_sample_metadata",
                            "sha256_hash": sample.get("sha256_hash", ""),
                            "md5_hash": sample.get("md5_hash", ""),
                            "file_type": sample.get("file_type", ""),
                            "signature": sample.get("signature", ""),
                            "tags": sample.get("tags", []),
                            "reporter": sample.get("reporter", ""),
                            "delivery_method": sample.get("delivery_method", ""),
                            "text": content,
                        },
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to publish MalwareBazaar entry: %s", exc)
                    errors += 1

        finally:
            await bus.stop()

        return {"source": self.SOURCE_ID, "published": published, "errors": errors}


# ── Feodo Tracker adapter ──────────────────────────────────

class FeodoTrackerAdapter:
    """
    Pulls botnet C2 IP data from Feodo Tracker.

    Endpoint: GET https://feodotracker.abuse.ch/downloads/ipblocklist.json
    Auth: NONE (static JSON feed, no key required)
    """

    BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    SOURCE_ID = "src_feodo"

    def __init__(self) -> None:
        self._client = LiveHTTPClient("feodo")

    async def collect_c2_ips(self) -> list[dict[str, Any]]:
        """Fetch the current C2 IP blocklist."""
        async with self._client:
            response = await self._client.get(self.BLOCKLIST_URL)
            data = response.json()
        entries = data if isinstance(data, list) else []
        logger.info("Feodo: fetched %d C2 IP entries", len(entries))
        return entries

    async def collect_and_publish(self) -> dict[str, int]:
        """Fetch C2 IPs and publish to event bus."""
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0

        try:
            entries = await self.collect_c2_ips()

            for entry in entries:
                try:
                    content = json.dumps(entry, ensure_ascii=False)
                    content_hash = compute_content_hash(content.encode("utf-8"))

                    observed_at = datetime.now(UTC)
                    if entry.get("first_seen"):
                        try:
                            observed_at = datetime.fromisoformat(
                                str(entry["first_seen"]).replace(" ", "T")
                            )
                        except (ValueError, AttributeError):
                            pass

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.OSINT_FEED,
                        mode=CollectionMode.LIVE,
                        observed_at=observed_at,
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/feodo/{uuid.uuid4().hex[:12]}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "c2_ip",
                            "ip_address": entry.get("ip_address", entry.get("dst_ip", "")),
                            "port": entry.get("dst_port", entry.get("port", "")),
                            "malware": entry.get("malware", ""),
                            "status": entry.get("status", ""),
                            "as_number": entry.get("as_number", ""),
                            "as_name": entry.get("as_name", ""),
                            "country": entry.get("country", ""),
                            "text": content,
                        },
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to publish Feodo entry: %s", exc)
                    errors += 1

        finally:
            await bus.stop()

        return {"source": self.SOURCE_ID, "published": published, "errors": errors}


# ── Orchestrator: run all abuse.ch feeds ────────────────────

async def collect_abuse_ch_intel() -> dict[str, Any]:
    """
    Run all abuse.ch adapters and return combined results.

    Called by the Celery task 'collect_abuse_ch_intel'.
    """
    results: dict[str, Any] = {"started_at": datetime.now(UTC).isoformat()}
    settings = get_settings()

    # 1. URLhaus
    if settings.abuse_ch_auth_key:
        try:
            results["urlhaus"] = await URLhausAdapter().collect_and_publish()
        except Exception as exc:
            logger.error("URLhaus collection failed: %s", exc, exc_info=True)
            results["urlhaus"] = {"error": str(exc)}
    else:
        results["urlhaus"] = {"skipped": "ABUSE_CH_AUTH_KEY not set"}

    # 2. ThreatFox
    if settings.abuse_ch_auth_key:
        try:
            results["threatfox"] = await ThreatFoxAdapter().collect_and_publish()
        except Exception as exc:
            logger.error("ThreatFox collection failed: %s", exc, exc_info=True)
            results["threatfox"] = {"error": str(exc)}
    else:
        results["threatfox"] = {"skipped": "ABUSE_CH_AUTH_KEY not set"}

    # 3. MalwareBazaar
    if settings.abuse_ch_auth_key:
        try:
            results["malwarebazaar"] = await MalwareBazaarAdapter().collect_and_publish()
        except Exception as exc:
            logger.error("MalwareBazaar collection failed: %s", exc, exc_info=True)
            results["malwarebazaar"] = {"error": str(exc)}
    else:
        results["malwarebazaar"] = {"skipped": "ABUSE_CH_AUTH_KEY not set"}

    # 4. Feodo (no auth needed)
    try:
        results["feodo"] = await FeodoTrackerAdapter().collect_and_publish()
    except Exception as exc:
        logger.error("Feodo collection failed: %s", exc, exc_info=True)
        results["feodo"] = {"error": str(exc)}

    results["completed_at"] = datetime.now(UTC).isoformat()
    logger.info("abuse.ch collection complete: %s", results)
    return results
