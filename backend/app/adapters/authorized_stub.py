"""
NETRA — Authorized adapter stub (§0 hard rule 2).

This adapter exists ONLY as an interface plus a DISABLED stub.
It raises NotAuthorizedError unless a signed authorization reference
is configured and validated.

In production, an agency (e.g., NTRO) replaces this with their own
adapter implementation under their legal authority.
"""

from __future__ import annotations

import logging
from typing import Iterable

from backend.app.adapters.base import CandidateRef, NotAuthorizedError, RawItem, SourceAdapter

logger = logging.getLogger(__name__)


class AuthorizedAdapterStub:
    """
    DISABLED stub for authorized (operational) source adapters.

    This class demonstrates the interface that an agency would implement
    for accessing operational dark-web sources under legal authority.

    It is ALWAYS disabled in the prototype. Enabling it requires:
    1. A signed JWT authorization reference in the source registry
    2. Replacing this stub with an actual implementation
    3. Deploying within an agency's controlled infrastructure
    """

    source_id: str = "src_authorized_stub"

    def __init__(self) -> None:
        logger.warning(
            "AuthorizedAdapterStub initialised — this adapter is DISABLED. "
            "It exists only as an interface demonstration."
        )

    def discover(self) -> Iterable[CandidateRef]:
        """Always raises: this adapter is disabled."""
        raise NotAuthorizedError(
            "Authorized adapter is disabled in the prototype. "
            "This interface exists to demonstrate where an agency "
            "would plug in operational source collection under legal authority. "
            "See SYSTEM_DESIGN.md §7.5 for details."
        )

    def fetch(self, ref: CandidateRef) -> RawItem:
        """Always raises: this adapter is disabled."""
        raise NotAuthorizedError(
            "Authorized adapter is disabled. See discover() docstring."
        )
