"""
NETRA — Historical archive adapter (Phase 3).

Processes verified historical dark web datasets for baseline intelligence.
These are REPLAY/ARCHIVE mode — not live data.

  1. Gwern Silk Road Archive — verified public dataset
     Source: https://www.gwern.net/DNM-archives
     Status: VERIFIED — publicly available research archive
     License: Public research data (Gwern's Silk Road scrape)
     Format: HTML pages, forum posts, vendor profiles

Key insight: Historical datasets provide ground truth for entity resolution.
Known identities from Silk Road → if any aliases reappear in live data,
that's a high-confidence re-identification signal.

Source provenance:
  - Gwern Silk Road Archive: https://www.gwern.net/DNM-archives (verified, public)
    Available via torrent and direct download
    Contains: vendor profiles, forum posts, product listings (TEXT ONLY)
    Legal basis: public research archive, widely cited in academic literature
    Used by: Carnegie Mellon, Oxford, many published papers
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
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
from backend.app.core.redaction import redact_pii

logger = logging.getLogger(__name__)


# ── Entity extraction from forum/vendor text ────────────────

BTC_ADDR_RE = re.compile(r"\b((?:1|3)[1-9A-HJ-NP-Za-km-z]{25,34})\b")
PGP_BLOCK_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")

# Common Silk Road vendor/user patterns
VENDOR_NAME_RE = re.compile(r"(?:vendor|seller|shop)\s*:\s*(\S+)", re.IGNORECASE)


def extract_archive_entities(text: str) -> dict[str, list[str]]:
    """Extract entities from historical archive text."""
    entities: dict[str, list[str]] = {}

    btc = BTC_ADDR_RE.findall(text)
    if btc:
        entities["btc_addresses"] = list(set(btc))[:20]

    pgp = PGP_BLOCK_RE.findall(text)
    if pgp:
        import hashlib
        entities["pgp_key_hashes"] = [
            hashlib.sha256(k.encode()).hexdigest()[:16] for k in pgp
        ]

    emails = EMAIL_RE.findall(text)
    if emails:
        entities["emails"] = list(set(emails))[:20]

    vendors = VENDOR_NAME_RE.findall(text)
    if vendors:
        entities["vendor_handles"] = list(set(vendors))[:10]

    return entities


# ── Gwern Archive processor ────────────────────────────────

class GwernArchiveAdapter:
    """
    Processes the Gwern Silk Road archive for baseline intelligence.

    This adapter processes LOCAL files (downloaded archive). It does
    NOT scrape gwern.net — the archive is meant to be downloaded once
    and processed locally.

    Expected local structure:
      archives/gwern-silk-road/
        vendors/
          *.html     → vendor profile pages
        forums/
          *.html     → forum thread pages
        listings/
          *.html     → product listings (TEXT metadata only)

    Processing:
      1. Parse HTML for text content
      2. Extract entities (BTC addresses, PGP keys, emails, handles)
      3. Redact PII
      4. Publish to event bus in REPLAY mode (not LIVE)
    """

    SOURCE_ID = "src_gwern_silk_road"
    DEFAULT_ARCHIVE_PATH = "archives/gwern-silk-road"

    def __init__(self, archive_path: str | None = None) -> None:
        self._archive_path = Path(archive_path or self.DEFAULT_ARCHIVE_PATH)

    def _strip_html(self, html: str) -> str:
        """Strip HTML tags, keep text content."""
        text = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL)
        text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    async def process_file(self, filepath: Path) -> dict[str, Any] | None:
        """Process a single archive file."""
        try:
            text = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.debug("Failed to read %s: %s", filepath, exc)
            return None

        # Strip HTML
        plain_text = self._strip_html(text)
        if len(plain_text) < 50:
            return None  # Skip near-empty files

        # Extract entities
        entities = extract_archive_entities(plain_text)
        if not entities:
            return None  # Skip files with no extractable intel

        # Determine content type from path
        relative = filepath.relative_to(self._archive_path)
        parts = relative.parts
        content_category = parts[0] if parts else "unknown"

        return {
            "filepath": str(relative),
            "category": content_category,
            "text_length": len(plain_text),
            "entities": entities,
            "text_preview": plain_text[:1000],
        }

    async def process_and_publish(self, max_files: int = 500) -> dict[str, Any]:
        """
        Process archive files and publish to event bus.

        Args:
            max_files: Maximum files to process (cap for safety)
        """
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0
        skipped = 0
        total_entities: dict[str, int] = {}

        if not self._archive_path.exists():
            logger.warning("Gwern archive not found at %s", self._archive_path)
            return {
                "source": self.SOURCE_ID,
                "error": f"Archive path not found: {self._archive_path}",
                "note": "Download from https://www.gwern.net/DNM-archives",
            }

        try:
            # Collect all HTML files
            html_files = list(self._archive_path.rglob("*.html"))[:max_files]
            logger.info("Gwern archive: found %d HTML files", len(html_files))

            for filepath in html_files:
                try:
                    result = await self.process_file(filepath)
                    if not result:
                        skipped += 1
                        continue

                    # Count entities
                    for etype, values in result["entities"].items():
                        total_entities[etype] = total_entities.get(etype, 0) + len(values)

                    # Redact PII
                    redaction = redact_pii(json.dumps(result, ensure_ascii=False))

                    content_hash = compute_content_hash(
                        redaction.redacted_text.encode("utf-8")
                    )

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.REPLAY,
                        mode=CollectionMode.REPLAY,
                        observed_at=datetime.now(UTC),
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/gwern/{uuid.uuid4().hex[:12]}.json",
                        content_hash=content_hash,
                        policy_decision_id="archive-approved",
                        language="en",
                        raw_metadata={
                            "type": "archive_page",
                            "archive": "gwern_silk_road",
                            "category": result["category"],
                            "filepath": result["filepath"],
                            "text_length": result["text_length"],
                            "entities": result["entities"],
                            "text": redaction.redacted_text[:3000],
                        },
                        redactions=redaction.redactions,
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Archive file processing failed: %s", exc)
                    errors += 1

        finally:
            await bus.stop()

        summary = {
            "source": self.SOURCE_ID,
            "files_found": len(html_files) if self._archive_path.exists() else 0,
            "published": published,
            "skipped": skipped,
            "errors": errors,
            "entities_found": total_entities,
        }
        logger.info("Gwern archive processing complete: %s", summary)
        return summary
