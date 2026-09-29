"""
NETRA — Rebrand / persona migration detector (§12).

The centerpiece demo scenario.  Detects when a threat actor abandons
one identity and reappears under another.

Rule:
  1. Candidate A is dormant ≥ DORMANCY_DAYS (default 14)
  2. Candidate B first seen within [t0, t0 + WINDOW_DAYS] (default 45)
     and NOT co-active with A
  3. Pairwise evidence scored through the confidence engine
  4. If score ≥ ALERT_THRESHOLD (default 75): raise PERSONA_MIGRATION alert

The detector runs as a periodic Celery task after entity resolution.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.app.analytics.confidence.engine import (
    Band,
    ConfidenceEngine,
    EvidenceItem,
    LinkScore,
    score_to_band,
)

logger = logging.getLogger(__name__)


# ── Configuration ────────────────────────────────────────────

DORMANCY_DAYS = 14
WINDOW_DAYS = 45
ALERT_THRESHOLD = 75
CO_ACTIVITY_OVERLAP_DAYS = 3  # actors co-active within this window → NOT a rebrand


# ── Data classes ─────────────────────────────────────────────

@dataclass
class ActorProfile:
    """Lightweight actor profile for the rebrand detector."""
    actor_id: str
    handle: str
    first_seen: datetime
    last_seen: datetime
    status: str
    pgp_fingerprints: list[str]
    wallet_addresses: list[str]
    contact_ids: list[str]
    handles: list[str]
    style_vector: list[float] | None = None  # stylometry embedding


@dataclass
class RebrandCandidate:
    """A potential persona migration pair."""
    old_actor: ActorProfile
    new_actor: ActorProfile
    dormancy_days: int
    appearance_gap_days: int
    evidence: list[EvidenceItem]
    score: LinkScore | None = None


@dataclass
class MigrationAlert:
    """A PERSONA_MIGRATION alert ready for persistence."""
    alert_id: str
    alert_type: str = "persona_migration"
    old_actor_id: str = ""
    new_actor_id: str = ""
    old_handle: str = ""
    new_handle: str = ""
    score: float = 0
    band: str = ""
    evidence_summary: list[dict[str, Any]] = None  # type: ignore
    why: list[str] = None  # type: ignore


class RebrandDetector:
    """
    Detects persona migrations by correlating dormant and newly appeared actors.

    Algorithm:
    1. Find all dormant actors (last_seen < now - DORMANCY_DAYS)
    2. For each dormant actor, find new actors appearing within WINDOW_DAYS
    3. Exclude co-active pairs
    4. Compute pairwise evidence (shared keys, wallets, contacts, style)
    5. Score through the confidence engine
    6. If score ≥ threshold → emit alert
    """

    def __init__(
        self,
        dormancy_days: int = DORMANCY_DAYS,
        window_days: int = WINDOW_DAYS,
        alert_threshold: float = ALERT_THRESHOLD,
    ) -> None:
        self.dormancy_days = dormancy_days
        self.window_days = window_days
        self.alert_threshold = alert_threshold
        self.engine = ConfidenceEngine()

    def find_candidates(
        self,
        actors: list[ActorProfile],
        reference_time: datetime | None = None,
    ) -> list[RebrandCandidate]:
        """Find potential rebrand pairs from a list of actor profiles."""
        now = reference_time or datetime.now(UTC)
        dormancy_cutoff = now - timedelta(days=self.dormancy_days)

        # Partition actors
        dormant = [a for a in actors if a.last_seen < dormancy_cutoff]
        # Candidates are all OTHER actors (the pairwise window check filters timing)
        dormant_ids = {a.actor_id for a in dormant}
        recent = [a for a in actors if a.actor_id not in dormant_ids]

        candidates: list[RebrandCandidate] = []

        for old in dormant:
            t0 = old.last_seen
            window_end = t0 + timedelta(days=self.window_days)

            for new in recent:
                # Must appear within the window
                if not (t0 <= new.first_seen <= window_end):
                    continue

                # Must NOT be co-active
                if self._is_co_active(old, new):
                    continue

                # Compute pairwise evidence
                evidence = self._build_evidence(old, new)

                dormancy = (now - old.last_seen).days
                gap = (new.first_seen - old.last_seen).days

                candidates.append(RebrandCandidate(
                    old_actor=old,
                    new_actor=new,
                    dormancy_days=dormancy,
                    appearance_gap_days=gap,
                    evidence=evidence,
                ))

        return candidates

    def score_candidates(
        self,
        candidates: list[RebrandCandidate],
    ) -> list[RebrandCandidate]:
        """Score all candidates through the confidence engine."""
        for candidate in candidates:
            candidate.score = self.engine.compute(candidate.evidence)
        return candidates

    def generate_alerts(
        self,
        candidates: list[RebrandCandidate],
    ) -> list[MigrationAlert]:
        """Generate PERSONA_MIGRATION alerts for high-scoring candidates."""
        alerts: list[MigrationAlert] = []

        for candidate in candidates:
            if candidate.score is None:
                continue
            if candidate.score.score < self.alert_threshold:
                continue

            alert = MigrationAlert(
                alert_id=str(uuid.uuid4()),
                old_actor_id=candidate.old_actor.actor_id,
                new_actor_id=candidate.new_actor.actor_id,
                old_handle=candidate.old_actor.handle,
                new_handle=candidate.new_actor.handle,
                score=candidate.score.score,
                band=candidate.score.band.value,
                evidence_summary=[
                    {
                        "type": ev.evidence_type,
                        "lr": ev.effective_lr,
                        "reliability": ev.source_reliability,
                        "credibility": ev.credibility,
                    }
                    for ev in candidate.evidence
                ],
                why=candidate.score.why,
            )
            alerts.append(alert)

            logger.info(
                "PERSONA_MIGRATION detected: %s → %s (score=%s, band=%s)",
                candidate.old_actor.handle,
                candidate.new_actor.handle,
                candidate.score.score,
                candidate.score.band.value,
            )

        return alerts

    def detect(
        self,
        actors: list[ActorProfile],
        reference_time: datetime | None = None,
    ) -> list[MigrationAlert]:
        """
        Full detection pipeline: find → score → alert.

        This is the main entry point.
        """
        candidates = self.find_candidates(actors, reference_time)
        scored = self.score_candidates(candidates)
        return self.generate_alerts(scored)

    def _is_co_active(self, a: ActorProfile, b: ActorProfile) -> bool:
        """Check if two actors were active at the same time (= NOT a rebrand)."""
        overlap_start = max(a.first_seen, b.first_seen)
        overlap_end = min(a.last_seen, b.last_seen)
        overlap_days = (overlap_end - overlap_start).days
        return overlap_days > CO_ACTIVITY_OVERLAP_DAYS

    def _build_evidence(
        self,
        old: ActorProfile,
        new: ActorProfile,
    ) -> list[EvidenceItem]:
        """Build pairwise evidence between two actor profiles."""
        evidence: list[EvidenceItem] = []

        # PGP fingerprint match
        shared_pgp = set(old.pgp_fingerprints) & set(new.pgp_fingerprints)
        for fp in shared_pgp:
            evidence.append(EvidenceItem(
                evidence_type="pgp_fingerprint",
                source_reliability="A",
                credibility=1,
                raw_value={"fingerprint": fp},
            ))

        # Contact ID match
        shared_contacts = set(old.contact_ids) & set(new.contact_ids)
        for cid in shared_contacts:
            evidence.append(EvidenceItem(
                evidence_type="contact_id",
                source_reliability="B",
                credibility=2,
                raw_value={"contact_id": cid},
            ))

        # Wallet overlap
        shared_wallets = set(old.wallet_addresses) & set(new.wallet_addresses)
        if shared_wallets:
            evidence.append(EvidenceItem(
                evidence_type="wallet_cluster",
                source_reliability="B",
                credibility=2,
                raw_value={"shared_addresses": list(shared_wallets)},
            ))

        # Handle similarity
        from difflib import SequenceMatcher
        for old_h in old.handles:
            for new_h in new.handles:
                if old_h.lower() == new_h.lower():
                    evidence.append(EvidenceItem(
                        evidence_type="handle_exact",
                        source_reliability="C",
                        credibility=3,
                        raw_value={"old": old_h, "new": new_h},
                    ))
                else:
                    ratio = SequenceMatcher(None, old_h.lower(), new_h.lower()).ratio()
                    if ratio >= 0.7:
                        evidence.append(EvidenceItem(
                            evidence_type="handle_similar",
                            lr=5 * ratio,  # scale LR by similarity
                            source_reliability="C",
                            credibility=3,
                            raw_value={"old": old_h, "new": new_h, "similarity": ratio},
                        ))

        # Stylometry (if vectors available)
        if old.style_vector and new.style_vector:
            similarity = self._cosine_similarity(old.style_vector, new.style_vector)
            if similarity > 0.6:
                evidence.append(EvidenceItem(
                    evidence_type="stylometry",
                    lr=2 + similarity * 20,  # calibrated range: 2–22
                    source_reliability="C",
                    credibility=3,
                    raw_value={"cosine_similarity": round(similarity, 4)},
                ))

        # Temporal overlap evidence (as corroboration)
        gap_days = (new.first_seen - old.last_seen).days
        if gap_days <= 45:
            evidence.append(EvidenceItem(
                evidence_type="temporal_overlap",
                lr=max(1.5, 5 - gap_days * 0.1),  # closer gap → higher LR
                source_reliability="B",
                credibility=3,
                raw_value={"gap_days": gap_days},
            ))

        return evidence

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        """Compute cosine similarity between two vectors."""
        import math
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)
