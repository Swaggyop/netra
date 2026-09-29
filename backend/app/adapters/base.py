"""
NETRA — Source adapter protocol (§7).

All adapters implement this protocol.  The pipeline calls:
  discover() → policy gate → safety gate (pre) → fetch() → safety gate (post)
                                                → redact → hash → store → extract

No adapter may access the network directly; .onion targets go through
the Tor SOCKS5 container.  SSRF validation is mandatory (OWASP A10).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Protocol

from backend.app.core.policy import CandidateRef


@dataclass(frozen=True)
class RawItem:
    """Content returned by adapter.fetch()."""
    content: bytes
    content_type: str
    metadata: dict[str, Any]


class SourceAdapter(Protocol):
    """Protocol that all source adapters must implement."""

    source_id: str

    def discover(self) -> Iterable[CandidateRef]:
        """
        Return metadata about candidate items (no content downloaded).

        Each CandidateRef passes through the policy gate before fetch().
        """
        ...

    def fetch(self, ref: CandidateRef) -> RawItem:
        """
        Fetch content for a policy-approved candidate.

        Only called AFTER PolicyGate.decide() returns ALLOW.
        .onion URLs must use the Tor SOCKS5 proxy.
        """
        ...


class NotAuthorizedError(Exception):
    """Raised by the authorized adapter stub when no authorization is configured."""
    pass
