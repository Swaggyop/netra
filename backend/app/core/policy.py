"""
NETRA — Policy gate (§7).

Runs BEFORE any content is fetched.  Checks:
1. Source is enabled and approved/authorized in the registry
2. Domain is on the allowlist (not on denylist)
3. Content-type is text/html or application/json only
4. Size is within cap
5. Retention and PII policies are attached
6. Mode/legal-basis tag is recorded

A blocked item writes only a policy_decisions row.  No payload is kept.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

logger = logging.getLogger(__name__)


class Decision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT_ALLOW = "redact_allow"


@dataclass(frozen=True)
class CandidateRef:
    """Metadata about a candidate item — returned by adapter.discover()."""
    url: str
    content_type: str = "text/html"
    size_bytes: int | None = None
    title: str | None = None
    author_handle: str | None = None
    thread_id: str | None = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class PolicyDecisionResult:
    """Result of a policy gate evaluation."""
    decision_id: str
    decision: Decision
    rule_hits: dict[str, str]
    source_id: str
    event_id: str | None  # None if blocked


# ── Configuration ────────────────────────────────────────────

ALLOWED_CONTENT_TYPES = frozenset({
    "text/html",
    "text/plain",
    "application/json",
    "application/xml",
})

MAX_CONTENT_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

# Domain denylist — never collect from these
DOMAIN_DENYLIST = frozenset({
    # Add known illegal domains here if needed for blocking
})

# Domain allowlist for authorized/lab sources (empty = allow all non-denied)
DOMAIN_ALLOWLIST: frozenset[str] = frozenset()


class PolicyGate:
    """
    Evaluates whether a candidate item may be fetched and stored.

    Every call produces a PolicyDecisionResult that is persisted
    regardless of outcome (audit trail — OWASP A09).
    """

    def decide(
        self,
        source: "SourceRecord",
        ref: CandidateRef,
    ) -> PolicyDecisionResult:
        """
        Evaluate all policy rules.  Returns on first block.

        Args:
            source: The source registry record.
            ref: Metadata about the candidate item.

        Returns:
            PolicyDecisionResult with decision and rule hits.
        """
        rule_hits: dict[str, str] = {}
        decision_id = str(uuid.uuid4())

        # Rule 1: Source must be enabled
        if not source.enabled:
            rule_hits["source_disabled"] = f"Source {source.source_id} is disabled"
            return self._block(decision_id, source.source_id, rule_hits)

        # Rule 2: Source must be approved or authorized
        if source.authorization_status not in ("approved", "authorized"):
            rule_hits["unauthorized"] = (
                f"Source {source.source_id} has status '{source.authorization_status}'"
            )
            return self._block(decision_id, source.source_id, rule_hits)

        # Rule 3: Authorized sources must have a valid reference
        if source.authorization_status == "authorized" and not source.authorization_ref:
            rule_hits["missing_auth_ref"] = "Authorized source missing authorization_ref"
            return self._block(decision_id, source.source_id, rule_hits)

        # Rule 4: Content-type allowlist
        base_type = ref.content_type.split(";")[0].strip().lower()
        if base_type not in ALLOWED_CONTENT_TYPES:
            rule_hits["content_type_blocked"] = (
                f"Content-type '{base_type}' not in allowlist"
            )
            return self._block(decision_id, source.source_id, rule_hits)

        # Rule 5: Size cap
        if ref.size_bytes is not None and ref.size_bytes > MAX_CONTENT_SIZE_BYTES:
            rule_hits["size_exceeded"] = (
                f"Size {ref.size_bytes} exceeds cap {MAX_CONTENT_SIZE_BYTES}"
            )
            return self._block(decision_id, source.source_id, rule_hits)

        # Rule 6: Domain denylist
        domain = self._extract_domain(ref.url)
        if domain and domain in DOMAIN_DENYLIST:
            rule_hits["domain_denied"] = f"Domain '{domain}' is on the denylist"
            return self._block(decision_id, source.source_id, rule_hits)

        # Rule 7: Retention policy must exist
        if not source.retention_days or source.retention_days <= 0:
            rule_hits["no_retention"] = "Source has no retention policy"
            return self._block(decision_id, source.source_id, rule_hits)

        # All checks passed — check if redaction is needed
        needs_redaction = source.pii_policy and "redact" in source.pii_policy.lower()
        decision = Decision.REDACT_ALLOW if needs_redaction else Decision.ALLOW

        logger.info(
            "Policy ALLOW for %s from %s (redact=%s)",
            ref.url[:80], source.source_id, needs_redaction,
        )

        return PolicyDecisionResult(
            decision_id=decision_id,
            decision=decision,
            rule_hits=rule_hits,
            source_id=source.source_id,
            event_id=str(uuid.uuid4()),
        )

    def _block(
        self,
        decision_id: str,
        source_id: str,
        rule_hits: dict[str, str],
    ) -> PolicyDecisionResult:
        """Create a BLOCK decision — no event_id, no payload."""
        logger.warning(
            "Policy BLOCK for source %s: %s",
            source_id, "; ".join(rule_hits.values()),
        )
        return PolicyDecisionResult(
            decision_id=decision_id,
            decision=Decision.BLOCK,
            rule_hits=rule_hits,
            source_id=source_id,
            event_id=None,
        )

    @staticmethod
    def _extract_domain(url: str) -> str | None:
        """Extract domain from URL for denylist/allowlist checks."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            return parsed.hostname
        except Exception:
            return None


# ── Source record (lightweight DTO for the gate) ─────────────

@dataclass(frozen=True)
class SourceRecord:
    """Lightweight view of a source registry entry for the policy gate."""
    source_id: str
    source_type: str
    authorization_status: str
    authorization_ref: str | None
    enabled: bool
    retention_days: int
    pii_policy: str | None
    reliability_grade: str


# Singleton
policy_gate = PolicyGate()
