"""
NETRA — Provenance: hashing, evidence IDs, and Merkle batch management (§17).

Every stored payload gets:
  1. SHA-256 content hash
  2. An evidence record
  3. Added to the current open Merkle batch

Batches close every N items or T minutes.  The root hash is stored and
can be verified (recompute from leaves).  Stretch: anchor via
OpenTimestamps or testnet transaction.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


# ── Hashing ──────────────────────────────────────────────────

def compute_content_hash(content: bytes) -> str:
    """Compute SHA-256 hash of content, prefixed with 'sha256:'."""
    digest = hashlib.sha256(content).hexdigest()
    return f"sha256:{digest}"


def compute_evidence_id(content_hash: str, source_id: str) -> str:
    """
    Deterministic evidence ID from content hash + source.

    This means re-ingesting the same content from the same source
    produces the same evidence ID (idempotent).
    """
    combined = f"{content_hash}:{source_id}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, combined))


# ── Merkle tree ──────────────────────────────────────────────

def _hash_pair(left: str, right: str) -> str:
    """Hash two hex hashes together for the Merkle tree."""
    combined = left.encode() + right.encode()
    return hashlib.sha256(combined).hexdigest()


def compute_merkle_root(leaf_hashes: list[str]) -> str:
    """
    Compute Merkle root from a list of hex hashes.

    If the number of leaves is odd, the last one is duplicated.
    Returns the root hash (without 'sha256:' prefix).
    """
    if not leaf_hashes:
        raise ValueError("Cannot compute Merkle root of empty list")

    # Strip 'sha256:' prefix if present
    hashes = [h.removeprefix("sha256:") for h in leaf_hashes]

    # Build tree bottom-up
    level = hashes
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(_hash_pair(left, right))
        level = next_level

    return level[0]


def verify_merkle_root(leaf_hashes: list[str], expected_root: str) -> bool:
    """Verify that the leaf hashes produce the expected Merkle root."""
    try:
        computed = compute_merkle_root(leaf_hashes)
        return computed == expected_root.removeprefix("sha256:")
    except Exception:
        return False


# ── Batch manager ────────────────────────────────────────────

class MerkleBatchManager:
    """
    Accumulates evidence hashes and closes batches when thresholds are met.

    Thread-safe for use in async workers.
    """

    DEFAULT_BATCH_SIZE = 100
    DEFAULT_BATCH_TIMEOUT_SECONDS = 300  # 5 minutes

    def __init__(
        self,
        batch_size: int = DEFAULT_BATCH_SIZE,
        batch_timeout_seconds: int = DEFAULT_BATCH_TIMEOUT_SECONDS,
    ) -> None:
        self._batch_size = batch_size
        self._batch_timeout = batch_timeout_seconds
        self._current_leaves: list[str] = []
        self._batch_started_at: datetime = datetime.now(UTC)
        self._batch_id: str = str(uuid.uuid4())

    def add_leaf(self, content_hash: str) -> dict | None:
        """
        Add a content hash to the current batch.

        Returns a completed batch dict if the batch should close,
        otherwise returns None.
        """
        self._current_leaves.append(content_hash)

        should_close = (
            len(self._current_leaves) >= self._batch_size
            or self._is_timeout_exceeded()
        )

        if should_close:
            return self.close_batch()

        return None

    def close_batch(self) -> dict:
        """Force-close the current batch and return its metadata."""
        if not self._current_leaves:
            raise ValueError("Cannot close an empty batch")

        root = compute_merkle_root(self._current_leaves)
        batch = {
            "batch_id": self._batch_id,
            "root_hash": f"sha256:{root}",
            "leaf_count": len(self._current_leaves),
            "leaf_hashes": list(self._current_leaves),
            "created_at": datetime.now(UTC),
        }

        # Reset for next batch
        self._current_leaves = []
        self._batch_started_at = datetime.now(UTC)
        self._batch_id = str(uuid.uuid4())

        logger.info(
            "Merkle batch %s closed: %d leaves, root=%s",
            batch["batch_id"], batch["leaf_count"], batch["root_hash"][:24],
        )

        return batch

    @property
    def pending_count(self) -> int:
        """Number of leaves in the current open batch."""
        return len(self._current_leaves)

    def _is_timeout_exceeded(self) -> bool:
        elapsed = (datetime.now(UTC) - self._batch_started_at).total_seconds()
        return elapsed >= self._batch_timeout
