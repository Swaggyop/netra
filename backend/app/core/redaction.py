"""
NETRA — PII redaction (§7, hard rule 6).

Redacts Aadhaar numbers, PAN cards, phone numbers, and victim emails
BEFORE any data is persisted.  Redaction runs after fetch, before
hashing and storage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ── Redaction patterns ───────────────────────────────────────

@dataclass(frozen=True)
class RedactionRule:
    """A named regex pattern for PII detection."""
    name: str
    pattern: re.Pattern[str]
    replacement: str


REDACTION_RULES: list[RedactionRule] = [
    # Indian Aadhaar number: 12 digits, optionally grouped as 4-4-4
    RedactionRule(
        name="aadhaar",
        pattern=re.compile(
            r"\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b"
        ),
        replacement="[AADHAAR_REDACTED]",
    ),

    # Indian PAN: ABCDE1234F format
    RedactionRule(
        name="pan",
        pattern=re.compile(
            r"\b([A-Z]{5}\d{4}[A-Z])\b"
        ),
        replacement="[PAN_REDACTED]",
    ),

    # Phone numbers: Indian (+91, 10 digits) and international formats
    RedactionRule(
        name="phone",
        pattern=re.compile(
            r"(?:\+?\d{1,3}[\s\-]?)?\(?\d{3,5}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}\b"
        ),
        replacement="[PHONE_REDACTED]",
    ),

    # Email addresses that look like victim/personal emails
    # We redact ALL emails except those ending in common dark-web email providers
    RedactionRule(
        name="victim_email",
        pattern=re.compile(
            r"\b[a-zA-Z0-9._%+\-]+@(?!protonmail\.|tutanota\.|cock\.li|"
            r"dnmx\.|onionmail\.)[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
        ),
        replacement="[EMAIL_REDACTED]",
    ),
]


@dataclass
class RedactionResult:
    """Result of redacting text."""
    redacted_text: str
    redactions: list[str] = field(default_factory=list)


def redact_pii(text: str) -> RedactionResult:
    """
    Apply all PII redaction rules to text.

    Returns the redacted text and a summary of what was redacted
    (e.g., ["aadhaar:2", "phone:1"]).  The summary is stored with
    the event but never contains the original PII.
    """
    result_text = text
    redaction_summary: dict[str, int] = {}

    for rule in REDACTION_RULES:
        matches = rule.pattern.findall(result_text)
        if matches:
            count = len(matches)
            result_text = rule.pattern.sub(rule.replacement, result_text)
            redaction_summary[rule.name] = redaction_summary.get(rule.name, 0) + count

    redactions = [f"{name}:{count}" for name, count in redaction_summary.items()]

    return RedactionResult(
        redacted_text=result_text,
        redactions=redactions,
    )
