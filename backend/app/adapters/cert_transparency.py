"""
NETRA — Certificate transparency & infrastructure correlation adapter (Phase 1).

Sources:
  1. crt.sh         — certificate transparency log search (no auth, JSON)
  2. CertStream     — real-time WebSocket cert issuance feed (no auth)
  3. Shodan InternetDB — free IP lookup: ports, CVEs, hostnames (no auth, 10K req/sec)

Source provenance:
  - crt.sh: https://crt.sh/ — run by Sectigo, public CT log search.
    Endpoint: GET https://crt.sh/?q={domain}&output=json  (verified, no auth, fair use)
  - CertStream: https://certstream.calidog.io/ — open WebSocket feed of CT logs.
    Endpoint: wss://certstream.calidog.io/  (verified, no auth)
    Python client: pip install certstream  (verified on PyPI)
  - Shodan InternetDB: https://internetdb.shodan.io/ — free, no auth, 10K req/sec.
    Endpoint: GET https://internetdb.shodan.io/{ip}  (verified)
    OpenAPI spec: https://internetdb.shodan.io/openapi.json
    ToS: free for non-commercial use
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


# ── crt.sh adapter ──────────────────────────────────────────

class CrtShAdapter:
    """
    Searches Certificate Transparency logs via crt.sh for certificates
    that may link .onion services to clearnet domains.

    Key use case: An onion operator who gets a TLS cert with both a
    .onion and a clearnet domain in the Subject Alternative Names (SAN)
    → direct deanonymization signal.

    Endpoint: GET https://crt.sh/?q={query}&output=json
    Auth: none
    Rate: fair use — avoid flooding
    """

    BASE_URL = "https://crt.sh"
    SOURCE_ID = "src_crt_sh"

    def __init__(self) -> None:
        self._client = LiveHTTPClient("crt_sh")

    async def search_domain(self, domain: str) -> list[dict[str, Any]]:
        """
        Search crt.sh for certificates mentioning a domain.

        Args:
            domain: Domain to search (e.g., 'example.com' or '%.onion')
        """
        async with self._client:
            response = await self._client.get(
                self.BASE_URL + "/",
                params={"q": domain, "output": "json"},
            )
            results = response.json()

        if not isinstance(results, list):
            return []

        logger.info("crt.sh: found %d certs for '%s'", len(results), domain)
        return results

    async def search_onion_certs(self) -> list[dict[str, Any]]:
        """
        Search for certificates that mention .onion domains in their SANs.

        This catches operators who accidentally (or deliberately) get a
        certificate for both their .onion and clearnet domain.
        """
        return await self.search_domain("%.onion")

    async def search_ransomware_domains(
        self, domain_patterns: list[str]
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Search crt.sh for certs matching known ransomware group domain patterns.

        Args:
            domain_patterns: List of domain patterns from ransomware.live
                             group data (e.g., ['lockbit.com', 'blackcat.*'])
        """
        results: dict[str, list[dict[str, Any]]] = {}
        for pattern in domain_patterns[:20]:  # cap to avoid rate limits
            try:
                certs = await self.search_domain(pattern)
                if certs:
                    results[pattern] = certs
            except Exception as exc:
                logger.warning("crt.sh search failed for '%s': %s", pattern, exc)
        return results

    async def collect_and_publish(
        self, domains: list[str] | None = None
    ) -> dict[str, int]:
        """
        Search for onion-related certs and publish to event bus.

        Args:
            domains: Optional list of specific domains to search.
                     If None, searches for .onion certs.
        """
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0

        try:
            if domains:
                all_certs = []
                for domain in domains[:10]:
                    certs = await self.search_domain(domain)
                    all_certs.extend(certs)
            else:
                all_certs = await self.search_onion_certs()

            for cert in all_certs:
                try:
                    # Parse SAN field — contains domain names, sometimes
                    # both .onion and clearnet in the same cert
                    name_value = cert.get("name_value", "")
                    san_domains = [
                        d.strip()
                        for d in name_value.split("\n")
                        if d.strip() and not d.strip().startswith("*")
                    ]

                    has_onion = any(".onion" in d for d in san_domains)
                    has_clearnet = any(
                        not d.endswith(".onion") and "." in d
                        for d in san_domains
                    )

                    # If both .onion and clearnet in same cert → strong signal
                    is_san_leak = has_onion and has_clearnet

                    content = json.dumps(cert, ensure_ascii=False)
                    content_hash = compute_content_hash(content.encode("utf-8"))

                    observed_at = datetime.now(UTC)
                    if cert.get("entry_timestamp"):
                        try:
                            observed_at = datetime.fromisoformat(cert["entry_timestamp"])
                        except (ValueError, AttributeError):
                            pass

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.CLEARNET_INTEL,
                        mode=CollectionMode.LIVE,
                        observed_at=observed_at,
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/crt_sh/{uuid.uuid4().hex[:12]}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "certificate",
                            "common_name": cert.get("common_name", ""),
                            "san_domains": san_domains,
                            "issuer_name": cert.get("issuer_name", ""),
                            "serial_number": cert.get("serial_number", ""),
                            "not_before": cert.get("not_before", ""),
                            "not_after": cert.get("not_after", ""),
                            "has_onion": has_onion,
                            "has_clearnet": has_clearnet,
                            "is_san_leak": is_san_leak,
                            "text": content,
                        },
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to publish crt.sh cert: %s", exc)
                    errors += 1

        finally:
            await bus.stop()

        return {
            "source": self.SOURCE_ID,
            "certs_found": len(all_certs),
            "published": published,
            "errors": errors,
        }


# ── Shodan InternetDB adapter ──────────────────────────────

class ShodanInternetDBAdapter:
    """
    Free IP intelligence from Shodan InternetDB.

    Returns: ports, CPEs, hostnames, tags, CVEs — no auth, 10K req/sec.

    Endpoint: GET https://internetdb.shodan.io/{ip}
    Auth: none
    Rate: 10,000 req/sec (generous)
    ToS: free for non-commercial use
    """

    BASE_URL = "https://internetdb.shodan.io"
    SOURCE_ID = "src_shodan_idb"

    def __init__(self) -> None:
        self._client = LiveHTTPClient("shodan_idb")

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Look up ports, hostnames, CVEs for an IP address."""
        async with self._client:
            response = await self._client.get(f"{self.BASE_URL}/{ip}")
            return response.json()

    async def lookup_ips_and_publish(
        self, ips: list[str]
    ) -> dict[str, int]:
        """
        Look up multiple IPs and publish results to event bus.

        Args:
            ips: List of IP addresses (from Tor relay data, IOC feeds, etc.)
        """
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0

        try:
            for ip in ips:
                try:
                    data = await self.lookup_ip(ip)

                    # InternetDB returns 404 for unknown IPs
                    if not data or "ip" not in data:
                        continue

                    content = json.dumps(data, ensure_ascii=False)
                    content_hash = compute_content_hash(content.encode("utf-8"))

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.CLEARNET_INTEL,
                        mode=CollectionMode.LIVE,
                        observed_at=datetime.now(UTC),
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/shodan_idb/{ip.replace('.', '_')}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "ip_intelligence",
                            "ip": data.get("ip", ip),
                            "ports": data.get("ports", []),
                            "hostnames": data.get("hostnames", []),
                            "cpes": data.get("cpes", []),
                            "tags": data.get("tags", []),
                            "vulns": data.get("vulns", []),
                            "text": content,
                        },
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to look up IP %s: %s", ip, exc)
                    errors += 1

        finally:
            await bus.stop()

        return {"source": self.SOURCE_ID, "published": published, "errors": errors}


# ── Orchestrator ────────────────────────────────────────────

async def collect_infra_intel(
    domains: list[str] | None = None,
    ips: list[str] | None = None,
) -> dict[str, Any]:
    """
    Run infrastructure correlation adapters.

    Args:
        domains: Domains to search in crt.sh
        ips: IPs to look up in Shodan InternetDB
    """
    results: dict[str, Any] = {"started_at": datetime.now(UTC).isoformat()}

    # crt.sh
    try:
        adapter = CrtShAdapter()
        results["crt_sh"] = await adapter.collect_and_publish(domains=domains)
    except Exception as exc:
        logger.error("crt.sh collection failed: %s", exc, exc_info=True)
        results["crt_sh"] = {"error": str(exc)}

    # Shodan InternetDB
    if ips:
        try:
            adapter = ShodanInternetDBAdapter()
            results["shodan_idb"] = await adapter.lookup_ips_and_publish(ips)
        except Exception as exc:
            logger.error("Shodan InternetDB lookup failed: %s", exc, exc_info=True)
            results["shodan_idb"] = {"error": str(exc)}

    results["completed_at"] = datetime.now(UTC).isoformat()
    return results
