"""
NETRA — Ransomware tracker adapter (Phase 1).

Pulls real-time ransomware intelligence from three sources:
  1. ransomware.live API PRO — groups, victims, onion URLs, PGP keys, timelines
  2. ransomlook.io API — posts, group details, crypto addresses, actor profiles
  3. Ransomwatch (GitHub) — daily-scraped leak-site posts (backup feed)

All data flows through the standard pipeline:
  collect → policy gate → safety gate → redact → hash → extract → resolve → score

Sources:
  - ransomware.live: https://api-pro.ransomware.live/ (free API key, X-API-KEY header)
  - ransomlook.io: GET /api/posts, /api/group/{name}, /api/crypto/{name}
  - ransomwatch: GitHub raw JSON (no key needed)
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
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


# ── Actor normalizer (cross-adapter dedup) ───────────────────

# Known aliases — ransomware.live and ransomlook report the same group differently
KNOWN_GROUP_ALIASES: dict[str, list[str]] = {
    "lockbit": ["lockbit3", "lockbit 3.0", "lockbit3.0", "lockbit 3", "lockbit2"],
    "alphv": ["blackcat", "alphv/blackcat", "alphv blackcat", "noberus"],
    "clop": ["cl0p", "clop ransomware", "ta505"],
    "blackbasta": ["black basta"],
    "royallocker": ["royal", "royal ransomware", "blacksuit"],
    "bianlian": ["bian lian"],
    "play": ["play ransomware", "playcrypt"],
    "medusa": ["medusa ransomware", "medusa locker", "medusalocker"],
    "akira": ["akira ransomware"],
    "rhysida": ["rhysida ransomware"],
    "hunters": ["hunters international", "hunters intl"],
    "8base": ["8base ransomware"],
    "noescape": ["no escape"],
    "ransomhub": ["ransom hub"],
}

# Build reverse lookup
_ALIAS_TO_CANONICAL: dict[str, str] = {}
for canonical, aliases in KNOWN_GROUP_ALIASES.items():
    _ALIAS_TO_CANONICAL[canonical] = canonical
    for alias in aliases:
        _ALIAS_TO_CANONICAL[alias.lower()] = canonical


def normalize_group_name(name: str) -> str:
    """Normalize a ransomware group name to a canonical form."""
    cleaned = name.strip().lower().replace("_", " ").replace("-", " ")
    return _ALIAS_TO_CANONICAL.get(cleaned, cleaned)


# ── ransomware.live adapter ─────────────────────────────────

class RansomwareLiveAdapter:
    """
    Pulls data from ransomware.live API PRO.

    Endpoints:
      GET /api/groups     → all ransomware groups + onion URLs
      GET /api/victims    → recent victims with timestamps
      GET /api/group/{n}  → single group detail with PGP, wallets
    """

    BASE_URL = "https://api-pro.ransomware.live"
    SOURCE_ID = "src_ransomware_live"

    def __init__(self) -> None:
        self._settings = get_settings()
        self._client = LiveHTTPClient("ransomware_live")

    async def _headers(self) -> dict[str, str]:
        api_key = self._settings.ransomware_live_api_key
        if not api_key:
            raise ValueError("RANSOMWARE_LIVE_API_KEY not set in .env")
        return {"X-API-KEY": api_key}

    async def collect_groups(self) -> list[dict[str, Any]]:
        """Fetch all ransomware groups with onion URLs and metadata."""
        async with self._client:
            headers = await self._headers()
            response = await self._client.get(
                f"{self.BASE_URL}/api/groups",
                headers=headers,
            )
            groups = response.json()

        logger.info("ransomware.live: fetched %d groups", len(groups))
        return groups

    async def collect_recent_victims(self, days: int = 7) -> list[dict[str, Any]]:
        """Fetch recent victims (last N days)."""
        async with self._client:
            headers = await self._headers()
            response = await self._client.get(
                f"{self.BASE_URL}/api/victims",
                headers=headers,
                params={"days": days},
            )
            victims = response.json()

        logger.info("ransomware.live: fetched %d recent victims", len(victims))
        return victims

    async def collect_group_detail(self, group_name: str) -> dict[str, Any]:
        """Fetch detailed info for a single group (PGP keys, wallets, etc.)."""
        async with self._client:
            headers = await self._headers()
            response = await self._client.get(
                f"{self.BASE_URL}/api/group/{group_name}",
                headers=headers,
            )
            return response.json()

    async def collect_and_publish(self) -> dict[str, int]:
        """
        Full collection cycle: fetch groups + victims, publish to event bus.

        Returns summary with counts.
        """
        bus = create_event_bus()
        await bus.start()

        published = 0
        errors = 0

        try:
            # Fetch groups
            groups = await self.collect_groups()

            for group in groups:
                try:
                    group_name = normalize_group_name(group.get("name", "unknown"))
                    content = json.dumps(group, ensure_ascii=False)
                    redaction = redact_pii(content)
                    content_bytes = redaction.redacted_text.encode("utf-8")
                    content_hash = compute_content_hash(content_bytes)

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.OSINT_FEED,
                        mode=CollectionMode.LIVE,
                        observed_at=datetime.now(UTC),
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/ransomware_live/group/{group_name}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "ransomware_group",
                            "group_name": group_name,
                            "original_name": group.get("name"),
                            "onion_urls": group.get("locations", []),
                            "description": group.get("description", ""),
                            "profile_url": group.get("url", ""),
                            "text": content,  # For extraction pipeline
                        },
                        redactions=redaction.redactions,
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to publish group %s: %s", group.get("name"), exc)
                    errors += 1

            # Fetch recent victims
            victims = await self.collect_recent_victims(days=7)

            for victim in victims:
                try:
                    group_name = normalize_group_name(victim.get("group_name", "unknown"))
                    content = json.dumps(victim, ensure_ascii=False)
                    redaction = redact_pii(content)
                    content_bytes = redaction.redacted_text.encode("utf-8")
                    content_hash = compute_content_hash(content_bytes)

                    # Parse victim date
                    observed_at = datetime.now(UTC)
                    if victim.get("discovered"):
                        try:
                            observed_at = datetime.fromisoformat(
                                victim["discovered"].replace("Z", "+00:00")
                            )
                        except (ValueError, AttributeError):
                            pass

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.OSINT_FEED,
                        mode=CollectionMode.LIVE,
                        observed_at=observed_at,
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/ransomware_live/victim/{uuid.uuid4().hex[:12]}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "ransomware_victim",
                            "group_name": group_name,
                            "victim_name": victim.get("victim", ""),
                            "website": victim.get("website", ""),
                            "discovered": victim.get("discovered", ""),
                            "text": content,
                        },
                        redactions=redaction.redactions,
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to publish victim: %s", exc)
                    errors += 1

        finally:
            await bus.stop()

        summary = {
            "source": self.SOURCE_ID,
            "groups_fetched": len(groups) if 'groups' in dir() else 0,
            "victims_fetched": len(victims) if 'victims' in dir() else 0,
            "published": published,
            "errors": errors,
        }
        logger.info("ransomware.live collection complete: %s", summary)
        return summary


# ── ransomlook.io adapter ───────────────────────────────────

class RansomLookAdapter:
    """
    Pulls data from ransomlook.io API.

    Endpoints:
      GET /api/posts?days=N      → recent posts from all groups
      GET /api/group/{name}      → group details + leak site URLs
      GET /api/crypto/{name}     → BTC/ETH/XMR addresses per group
      GET /api/actor/{name}      → threat actor profiles
    """

    BASE_URL = "https://www.ransomlook.io"
    SOURCE_ID = "src_ransomlook"

    def __init__(self) -> None:
        self._client = LiveHTTPClient("ransomlook")

    async def collect_recent_posts(self, days: int = 7) -> list[dict[str, Any]]:
        """Fetch recent posts from all groups."""
        async with self._client:
            response = await self._client.get(
                f"{self.BASE_URL}/api/recent",
                params={"days": days},
            )
            posts = response.json()

        logger.info("ransomlook: fetched %d recent posts", len(posts) if isinstance(posts, list) else 0)
        return posts if isinstance(posts, list) else []

    async def collect_group_detail(self, group_name: str) -> dict[str, Any]:
        """Fetch group details including leak site URLs."""
        async with self._client:
            response = await self._client.get(
                f"{self.BASE_URL}/api/group/{group_name}",
            )
            return response.json()

    async def collect_group_crypto(self, group_name: str) -> dict[str, Any]:
        """Fetch cryptocurrency addresses for a group."""
        async with self._client:
            response = await self._client.get(
                f"{self.BASE_URL}/api/crypto/{group_name}",
            )
            return response.json()

    async def collect_and_publish(self) -> dict[str, int]:
        """
        Full collection cycle: fetch posts + crypto, publish to event bus.
        """
        bus = create_event_bus()
        await bus.start()

        published = 0
        errors = 0
        posts: list = []

        try:
            # Fetch recent posts
            posts = await self.collect_recent_posts(days=7)

            for post in posts:
                try:
                    group_name = normalize_group_name(
                        post.get("group_name", post.get("group", "unknown"))
                    )
                    content = json.dumps(post, ensure_ascii=False)
                    redaction = redact_pii(content)
                    content_bytes = redaction.redacted_text.encode("utf-8")
                    content_hash = compute_content_hash(content_bytes)

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.OSINT_FEED,
                        mode=CollectionMode.LIVE,
                        observed_at=datetime.now(UTC),
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/ransomlook/post/{uuid.uuid4().hex[:12]}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "ransomware_post",
                            "group_name": group_name,
                            "post_title": post.get("post_title", ""),
                            "post_url": post.get("post_url", ""),
                            "discovered": post.get("discovered", ""),
                            "text": content,
                        },
                        redactions=redaction.redactions,
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to publish ransomlook post: %s", exc)
                    errors += 1

        finally:
            await bus.stop()

        summary = {
            "source": self.SOURCE_ID,
            "posts_fetched": len(posts),
            "published": published,
            "errors": errors,
        }
        logger.info("ransomlook collection complete: %s", summary)
        return summary


# ── Ransomwatch adapter (GitHub backup) ─────────────────────

class RansomwatchAdapter:
    """
    Pulls from Ransomwatch GitHub raw JSON — daily-scraped ransomware
    leak-site posts. No API key needed. Good backup if ransomware.live
    rate-limits you.

    Sources:
      - https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json
      - https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json
    """

    POSTS_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
    GROUPS_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"
    SOURCE_ID = "src_ransomwatch"

    def __init__(self) -> None:
        self._client = LiveHTTPClient("ransomwatch")

    async def collect_posts(self) -> list[dict[str, Any]]:
        """Fetch all ransomwatch posts."""
        async with self._client:
            response = await self._client.get(self.POSTS_URL)
            posts = response.json()
        logger.info("ransomwatch: fetched %d posts", len(posts))
        return posts

    async def collect_groups(self) -> list[dict[str, Any]]:
        """Fetch all ransomwatch group definitions."""
        async with self._client:
            response = await self._client.get(self.GROUPS_URL)
            groups = response.json()
        logger.info("ransomwatch: fetched %d groups", len(groups))
        return groups

    async def collect_and_publish(self) -> dict[str, int]:
        """Fetch posts from Ransomwatch and publish to event bus."""
        bus = create_event_bus()
        await bus.start()

        published = 0
        errors = 0
        posts: list = []

        try:
            posts = await self.collect_posts()

            # Only publish posts from the last 7 days to avoid flooding
            cutoff = datetime.now(UTC) - timedelta(days=7)

            for post in posts:
                try:
                    # Parse timestamp
                    post_date_str = post.get("discovered", post.get("date", ""))
                    if not post_date_str:
                        continue

                    try:
                        post_date = datetime.fromisoformat(
                            post_date_str.replace("Z", "+00:00")
                        )
                        if post_date.tzinfo is None:
                            post_date = post_date.replace(tzinfo=UTC)
                    except (ValueError, AttributeError):
                        continue

                    if post_date < cutoff:
                        continue

                    group_name = normalize_group_name(
                        post.get("group_name", post.get("group", "unknown"))
                    )
                    content = json.dumps(post, ensure_ascii=False)
                    content_hash = compute_content_hash(content.encode("utf-8"))

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.OSINT_FEED,
                        mode=CollectionMode.LIVE,
                        observed_at=post_date,
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/ransomwatch/post/{uuid.uuid4().hex[:12]}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "ransomware_post",
                            "group_name": group_name,
                            "post_title": post.get("post_title", ""),
                            "post_url": post.get("post_url", ""),
                            "discovered": post_date_str,
                            "text": content,
                        },
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to publish ransomwatch post: %s", exc)
                    errors += 1

        finally:
            await bus.stop()

        summary = {
            "source": self.SOURCE_ID,
            "total_posts": len(posts),
            "recent_published": published,
            "errors": errors,
        }
        logger.info("ransomwatch collection complete: %s", summary)
        return summary


# ── Orchestrator: run all ransomware adapters ───────────────

async def collect_ransomware_intel() -> dict[str, Any]:
    """
    Run all ransomware adapters and return combined results.

    Called by the Celery task 'collect_ransomware_intel'.
    """
    results: dict[str, Any] = {"started_at": datetime.now(UTC).isoformat()}

    # 1. ransomware.live (primary)
    settings = get_settings()
    if settings.ransomware_live_api_key:
        try:
            adapter = RansomwareLiveAdapter()
            results["ransomware_live"] = await adapter.collect_and_publish()
        except Exception as exc:
            logger.error("ransomware.live collection failed: %s", exc, exc_info=True)
            results["ransomware_live"] = {"error": str(exc)}
    else:
        results["ransomware_live"] = {"skipped": "no API key configured"}

    # 2. ransomlook.io
    try:
        adapter = RansomLookAdapter()
        results["ransomlook"] = await adapter.collect_and_publish()
    except Exception as exc:
        logger.error("ransomlook collection failed: %s", exc, exc_info=True)
        results["ransomlook"] = {"error": str(exc)}

    # 3. Ransomwatch (backup)
    try:
        adapter = RansomwatchAdapter()
        results["ransomwatch"] = await adapter.collect_and_publish()
    except Exception as exc:
        logger.error("ransomwatch collection failed: %s", exc, exc_info=True)
        results["ransomwatch"] = {"error": str(exc)}

    results["completed_at"] = datetime.now(UTC).isoformat()
    logger.info("Ransomware intel collection complete: %s", results)
    return results
