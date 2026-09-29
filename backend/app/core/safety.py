"""
NETRA — Content safety gate (§7).

Runs in two phases:
  1. pre_fetch()  — metadata/content-type decision (no download)
  2. post_fetch() — text-only keyword + pattern check (discard on block)

Images, video, and archives are NEVER collected in the MVP.
Prohibited content categories are never downloaded.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import StrEnum

logger = logging.getLogger(__name__)


class SafetyDecision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass(frozen=True)
class SafetyResult:
    """Result of a safety gate check."""
    decision: SafetyDecision
    reason: str | None = None


# ── Blocked MIME types (MVP: text/json only) ─────────────────

BLOCKED_MIME_PREFIXES = frozenset({
    "image/",
    "video/",
    "audio/",
    "application/zip",
    "application/x-rar",
    "application/x-tar",
    "application/gzip",
    "application/x-7z",
    "application/octet-stream",
    "application/pdf",           # PDFs can contain malicious content
    "application/x-executable",
    "application/x-msdownload",
})

# ── Content patterns that indicate prohibited material ───────
# These are broad-category patterns, not targeting specific content.
# Real deployment would use a classifier, not keyword matching.

_PROHIBITED_PATTERNS: list[re.Pattern[str]] = [
    # CSAM-related keywords (broad categories only)
    re.compile(r"\b(child\s+(?:abuse|exploitation|pornograph))\b", re.IGNORECASE),
    # Terrorism recruitment (broad category)
    re.compile(r"\b(recruit(?:ing|ment)\s+for\s+(?:jihad|terror))\b", re.IGNORECASE),
]

# Maximum text length to scan (performance guard)
MAX_SCAN_LENGTH = 500_000  # 500 KB of text


class SafetyGate:
    """
    Two-phase content safety gate.

    The gate is deliberately conservative: it blocks aggressively
    rather than allowing potentially harmful content through.
    """

    def pre_fetch(self, content_type: str, url: str = "") -> SafetyResult:
        """
        Phase 1: Decide based on metadata alone — NO content downloaded.

        Args:
            content_type: MIME type of the candidate.
            url: URL for logging context.

        Returns:
            SafetyResult indicating allow or block.
        """
        base_type = content_type.split(";")[0].strip().lower()

        # Block non-text content types
        for blocked_prefix in BLOCKED_MIME_PREFIXES:
            if base_type.startswith(blocked_prefix):
                logger.warning(
                    "SafetyGate PRE-FETCH BLOCK: %s (type: %s)",
                    url[:80], base_type,
                )
                return SafetyResult(
                    decision=SafetyDecision.BLOCK,
                    reason=f"Blocked MIME type: {base_type}",
                )

        return SafetyResult(decision=SafetyDecision.ALLOW)

    def post_fetch(self, text: str, url: str = "") -> SafetyResult:
        """
        Phase 2: Scan text content for prohibited patterns.

        Called AFTER fetch.  If blocked, the payload is discarded
        and only the decision record remains.

        Args:
            text: The fetched text content.
            url: URL for logging context.

        Returns:
            SafetyResult indicating allow or block.
        """
        # Truncate for performance
        scan_text = text[:MAX_SCAN_LENGTH]

        for pattern in _PROHIBITED_PATTERNS:
            match = pattern.search(scan_text)
            if match:
                logger.warning(
                    "SafetyGate POST-FETCH BLOCK: %s (pattern match: %s)",
                    url[:80], pattern.pattern[:40],
                )
                return SafetyResult(
                    decision=SafetyDecision.BLOCK,
                    reason=f"Prohibited content pattern detected",
                )

        return SafetyResult(decision=SafetyDecision.ALLOW)


# Singleton
safety_gate = SafetyGate()
