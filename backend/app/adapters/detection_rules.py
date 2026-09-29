"""
NETRA — Sigma/YARA rule repository adapter (Phase 3).

Pulls detection rule metadata from open-source repositories to map
threat actors to TTPs, malware families, and campaigns.

  1. SigmaHQ  — YAML detection rules with MITRE ATT&CK tags + actor references
  2. YARA-Rules — community YARA rules with malware family/actor metadata

Source provenance:
  - SigmaHQ: https://github.com/SigmaHQ/sigma (verified, MIT license, no auth for raw)
    Endpoint: GitHub raw content or GitHub API
    Rule format: YAML with title, tags, description, author fields
    Actor data: ATT&CK tags (attack.gXXXX = group), rule titles, descriptions
  - YARA-Rules: https://github.com/Yara-Rules/rules (verified, GPL-2.0, no auth)
    Rule format: YARA with meta fields (author, description, threat_actor, family)

Key insight: detection rule metadata is a structured, free, actor-association
signal. Rules frequently name the threat actor, malware family, or campaign
they target — this is exactly the kind of association data NETRA needs.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

import yaml

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


# ── ATT&CK tag parsing ─────────────────────────────────────

# Sigma tags follow the pattern: attack.tXXXX (technique) or attack.gXXXX (group)
ATTACK_TECHNIQUE_RE = re.compile(r"attack\.t(\d{4}(?:\.\d{3})?)", re.IGNORECASE)
ATTACK_GROUP_RE = re.compile(r"attack\.g(\d{4})", re.IGNORECASE)

# Known MITRE ATT&CK group IDs → names (subset of most relevant)
MITRE_GROUPS: dict[str, str] = {
    "g0016": "apt29",
    "g0022": "apt3",
    "g0026": "apt18",
    "g0032": "lazarus",
    "g0034": "sandworm",
    "g0035": "dragonfly",
    "g0045": "menupass",
    "g0049": "oilrig",
    "g0050": "apt32",
    "g0059": "magic_hound",
    "g0064": "apt33",
    "g0074": "wizard_spider",
    "g0078": "gorgon_group",
    "g0080": "cobalt_group",
    "g0092": "ta505",
    "g0096": "apt41",
    "g0102": "fin7",
    "g0108": "blue_mockingbird",
    "g0114": "chimera",
    "g0119": "indrik_spider",
    "g0125": "hafnium",
    "g0129": "mustang_panda",
}


def extract_actor_refs_from_tags(tags: list[str]) -> list[str]:
    """Extract actor references from Sigma-style ATT&CK tags."""
    actors: list[str] = []
    for tag in tags:
        tag_lower = tag.lower()
        group_match = ATTACK_GROUP_RE.search(tag_lower)
        if group_match:
            gid = f"g{group_match.group(1)}"
            name = MITRE_GROUPS.get(gid, gid)
            actors.append(name)
    return actors


# ── SigmaHQ adapter ────────────────────────────────────────

class SigmaHQAdapter:
    """
    Pulls Sigma rule metadata from the SigmaHQ GitHub repository.

    Uses the GitHub API to list rule files and parse YAML metadata
    for actor/technique associations.

    We DON'T download all 3000+ rules — we fetch the rule index and
    parse metadata from recently updated rules.
    """

    # GitHub API for SigmaHQ repo tree
    GITHUB_API = "https://api.github.com"
    REPO = "SigmaHQ/sigma"
    SOURCE_ID = "src_sigmahq"

    # Ransomware-related rule directories
    RULE_PATHS = [
        "rules/windows/process_creation",
        "rules/windows/registry",
        "rules/windows/file",
        "rules/linux/process_creation",
    ]

    def __init__(self) -> None:
        self._client = LiveHTTPClient("default")

    async def fetch_rule_index(self, path: str, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch file listing from a SigmaHQ rule directory."""
        async with self._client:
            response = await self._client.get(
                f"{self.GITHUB_API}/repos/{self.REPO}/contents/{path}",
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            files = response.json()

        if not isinstance(files, list):
            return []

        # Filter to .yml files only
        yml_files = [
            f for f in files
            if isinstance(f, dict) and f.get("name", "").endswith(".yml")
        ]
        return yml_files[:limit]

    async def fetch_and_parse_rule(self, raw_url: str) -> dict[str, Any] | None:
        """Download and parse a single Sigma YAML rule."""
        try:
            async with self._client:
                response = await self._client.get(raw_url)
                text = response.text

            rule = yaml.safe_load(text)
            if not isinstance(rule, dict):
                return None

            return {
                "title": rule.get("title", ""),
                "id": rule.get("id", ""),
                "status": rule.get("status", ""),
                "description": rule.get("description", ""),
                "author": rule.get("author", ""),
                "date": rule.get("date", ""),
                "tags": rule.get("tags", []),
                "level": rule.get("level", ""),
                "logsource": rule.get("logsource", {}),
                "references": rule.get("references", []),
            }
        except Exception as exc:
            logger.debug("Failed to parse Sigma rule %s: %s", raw_url[:60], exc)
            return None

    async def collect_and_publish(self) -> dict[str, int]:
        """
        Fetch Sigma rules and publish actor/technique associations.
        """
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0
        actor_associations = 0

        try:
            for path in self.RULE_PATHS:
                try:
                    files = await self.fetch_rule_index(path, limit=30)

                    for file_info in files:
                        try:
                            download_url = file_info.get("download_url")
                            if not download_url:
                                continue

                            rule = await self.fetch_and_parse_rule(download_url)
                            if not rule or not rule.get("tags"):
                                continue

                            tags = rule.get("tags", [])
                            actors = extract_actor_refs_from_tags(tags)
                            techniques = [
                                f"T{m.group(1)}"
                                for t in tags
                                if (m := ATTACK_TECHNIQUE_RE.search(t.lower()))
                            ]

                            if actors:
                                actor_associations += 1

                            content = json.dumps(rule, ensure_ascii=False, default=str)
                            content_hash = compute_content_hash(content.encode("utf-8"))

                            event = RawEvent(
                                source_id=self.SOURCE_ID,
                                adapter_type=AdapterType.OSINT_FEED,
                                mode=CollectionMode.LIVE,
                                observed_at=datetime.now(UTC),
                                content_type=ContentType.JSON,
                                payload_ref=f"s3://netra-snapshots/sigma/{rule.get('id', uuid.uuid4().hex[:12])}.json",
                                content_hash=content_hash,
                                policy_decision_id="live-approved-feed",
                                language="en",
                                raw_metadata={
                                    "type": "sigma_rule",
                                    "rule_title": rule.get("title", ""),
                                    "rule_id": rule.get("id", ""),
                                    "status": rule.get("status", ""),
                                    "level": rule.get("level", ""),
                                    "tags": tags,
                                    "actors": actors,
                                    "techniques": techniques,
                                    "author": rule.get("author", ""),
                                    "references": rule.get("references", []),
                                    "description": rule.get("description", "")[:500],
                                    "text": content[:3000],
                                },
                            )

                            await bus.publish(Topics.RAW_EVENTS.value, event)
                            published += 1

                        except Exception as exc:
                            logger.error("Sigma rule processing failed: %s", exc)
                            errors += 1

                except Exception as exc:
                    logger.error("Sigma path %s failed: %s", path, exc)
                    errors += 1

        finally:
            await bus.stop()

        return {
            "source": self.SOURCE_ID,
            "published": published,
            "actor_associations": actor_associations,
            "errors": errors,
        }


# ── CertStream adapter (real-time WebSocket) ───────────────

class CertStreamAdapter:
    """
    Real-time certificate transparency feed via WebSocket.

    Catches cert issuance as it happens — much faster than polling crt.sh.
    Filters for .onion domains and known ransomware group domain patterns.

    Endpoint: wss://certstream.calidog.io/
    Auth: none
    Rate: unlimited (streaming)

    Source provenance:
      - CertStream: https://certstream.calidog.io/ (verified, open source)
      - GitHub: https://github.com/CaliDog/certstream-python (verified)
      - License: MIT
    """

    WS_URL = "wss://certstream.calidog.io/"
    SOURCE_ID = "src_certstream"

    def __init__(self) -> None:
        self._interesting_patterns: list[str] = []

    def set_watch_patterns(self, patterns: list[str]) -> None:
        """
        Set domain patterns to watch for in the cert stream.

        Args:
            patterns: List of strings to match against SAN domains
                      (e.g., ['lockbit', 'blackcat', '.onion'])
        """
        self._interesting_patterns = [p.lower() for p in patterns]

    async def stream_and_publish(
        self,
        duration_seconds: int = 300,
        max_events: int = 100,
    ) -> dict[str, int]:
        """
        Connect to CertStream WebSocket and publish interesting certs.

        Args:
            duration_seconds: How long to listen (default 5 minutes)
            max_events: Max events to publish before stopping
        """
        import asyncio
        import time

        try:
            import websockets
        except ImportError:
            logger.warning("websockets not installed — CertStream adapter unavailable")
            return {"source": self.SOURCE_ID, "error": "websockets not installed"}

        bus = create_event_bus()
        await bus.start()
        published = 0
        scanned = 0
        start_time = time.monotonic()

        default_patterns = [".onion", "lockbit", "blackcat", "alphv", "ransom", "leak"]
        patterns = self._interesting_patterns or default_patterns

        try:
            async with websockets.connect(self.WS_URL) as ws:
                while (
                    time.monotonic() - start_time < duration_seconds
                    and published < max_events
                ):
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=10)
                        msg = json.loads(raw)
                        scanned += 1

                        if msg.get("message_type") != "certificate_update":
                            continue

                        cert_data = msg.get("data", {}).get("leaf_cert", {})
                        all_domains = cert_data.get("all_domains", [])

                        # Check if any domain matches our watch patterns
                        matched = False
                        matched_pattern = ""
                        for domain in all_domains:
                            domain_lower = domain.lower()
                            for pattern in patterns:
                                if pattern in domain_lower:
                                    matched = True
                                    matched_pattern = pattern
                                    break
                            if matched:
                                break

                        if not matched:
                            continue

                        # Found an interesting cert
                        has_onion = any(".onion" in d for d in all_domains)
                        has_clearnet = any(
                            not d.endswith(".onion") and "." in d
                            for d in all_domains
                        )

                        content = json.dumps(msg["data"], ensure_ascii=False)
                        content_hash = compute_content_hash(content.encode("utf-8"))

                        event = RawEvent(
                            source_id=self.SOURCE_ID,
                            adapter_type=AdapterType.CLEARNET_INTEL,
                            mode=CollectionMode.LIVE,
                            observed_at=datetime.now(UTC),
                            content_type=ContentType.JSON,
                            payload_ref=f"s3://netra-snapshots/certstream/{uuid.uuid4().hex[:12]}.json",
                            content_hash=content_hash,
                            policy_decision_id="live-approved-feed",
                            language="en",
                            raw_metadata={
                                "type": "realtime_certificate",
                                "all_domains": all_domains[:20],
                                "matched_pattern": matched_pattern,
                                "has_onion": has_onion,
                                "has_clearnet": has_clearnet,
                                "is_san_leak": has_onion and has_clearnet,
                                "issuer": cert_data.get("issuer", {}),
                                "serial_number": cert_data.get("serial_number", ""),
                                "not_before": cert_data.get("not_before", ""),
                                "not_after": cert_data.get("not_after", ""),
                                "text": content[:3000],
                            },
                        )

                        await bus.publish(Topics.RAW_EVENTS.value, event)
                        published += 1
                        logger.info(
                            "CertStream: matched cert for '%s' (domains: %s)",
                            matched_pattern, ", ".join(all_domains[:3]),
                        )

                    except asyncio.TimeoutError:
                        continue
                    except Exception as exc:
                        logger.debug("CertStream message error: %s", exc)
                        continue

        except Exception as exc:
            logger.error("CertStream connection failed: %s", exc)
        finally:
            await bus.stop()

        return {
            "source": self.SOURCE_ID,
            "certs_scanned": scanned,
            "published": published,
            "duration_seconds": round(time.monotonic() - start_time),
        }


# ── Orchestrator ────────────────────────────────────────────

async def collect_phase3_intel() -> dict[str, Any]:
    """Run all Phase 3 adapters."""
    results: dict[str, Any] = {"started_at": datetime.now(UTC).isoformat()}

    # SigmaHQ rules
    try:
        results["sigma"] = await SigmaHQAdapter().collect_and_publish()
    except Exception as exc:
        logger.error("SigmaHQ failed: %s", exc, exc_info=True)
        results["sigma"] = {"error": str(exc)}

    # CertStream (5-minute window)
    try:
        results["certstream"] = await CertStreamAdapter().stream_and_publish(
            duration_seconds=300, max_events=50,
        )
    except Exception as exc:
        logger.error("CertStream failed: %s", exc, exc_info=True)
        results["certstream"] = {"error": str(exc)}

    results["completed_at"] = datetime.now(UTC).isoformat()
    return results
