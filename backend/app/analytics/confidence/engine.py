"""
NETRA — Confidence engine: explainable attribution scoring (§8).

Uses log-likelihood-ratio (LLR) fusion with Admiralty grading
to produce a scored, evidence-backed link between two actors.

Every link shows:
  1. The evidence chain (each item with type, LLR, source grade)
  2. The overall score (0–100) and band
  3. A human-readable "why" list
  4. An analyst_status = "pending" requiring human confirmation

The formula:
  adj_llr(e)     = ln(LR) × reliability_factor × credibility_factor
  family_llr(f)  = max(adj_llr in family) + 0.5 × sum(others in family)
  posterior_odds = prior_odds × exp(Σ family_llr)
  score          = round(100 × posterior_odds / (1 + posterior_odds))
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


# ── Evidence types and default likelihood ratios (§8.1) ──────

class EvidenceFamily(StrEnum):
    KEY = "key"
    INFRA = "infra"
    CONTACT = "contact"
    FINANCIAL = "financial"
    HANDLE = "handle"
    LINGUISTIC = "linguistic"
    TEMPORAL = "temporal"


@dataclass(frozen=True)
class EvidenceType:
    """Definition of an evidence type with its default LR and family."""
    name: str
    default_lr: float
    family: EvidenceFamily
    description: str


# Registry of all evidence types (§8.1 table)
EVIDENCE_TYPES: dict[str, EvidenceType] = {
    "pgp_fingerprint": EvidenceType("pgp_fingerprint", 1000, EvidenceFamily.KEY, "Same PGP fingerprint"),
    "ssh_key": EvidenceType("ssh_key", 1000, EvidenceFamily.INFRA, "Same SSH host key"),
    "contact_id": EvidenceType("contact_id", 500, EvidenceFamily.CONTACT, "Same contact identifier"),
    "cert_san": EvidenceType("cert_san", 300, EvidenceFamily.INFRA, "TLS cert names clearnet domain"),
    "wallet_cluster": EvidenceType("wallet_cluster", 200, EvidenceFamily.FINANCIAL, "Same wallet cluster"),
    "wallet_transfer": EvidenceType("wallet_transfer", 50, EvidenceFamily.FINANCIAL, "Direct wallet-to-wallet transfer"),
    "favicon": EvidenceType("favicon", 30, EvidenceFamily.INFRA, "Same favicon hash"),
    "handle_exact": EvidenceType("handle_exact", 30, EvidenceFamily.HANDLE, "Exact handle match"),
    "avatar_hash": EvidenceType("avatar_hash", 20, EvidenceFamily.HANDLE, "Same avatar hash"),
    "handle_similar": EvidenceType("handle_similar", 5, EvidenceFamily.HANDLE, "Similar handle (Jaro-Winkler ≥ 0.90)"),
    "stylometry": EvidenceType("stylometry", 10, EvidenceFamily.LINGUISTIC, "Similar writing profile"),
    "code_switch": EvidenceType("code_switch", 8, EvidenceFamily.LINGUISTIC, "Similar code-switch pattern"),
    "banner": EvidenceType("banner", 3, EvidenceFamily.INFRA, "Same server banner"),
    "temporal_overlap": EvidenceType("temporal_overlap", 2.5, EvidenceFamily.TEMPORAL, "Overlapping activity window"),
    "tx_timing": EvidenceType("tx_timing", 3, EvidenceFamily.TEMPORAL, "Correlated transaction timing"),
}


# ── Admiralty grading (§8.2) ─────────────────────────────────

RELIABILITY_FACTORS: dict[str, float] = {
    "A": 1.0,   # completely reliable
    "B": 0.85,  # usually reliable
    "C": 0.70,  # fairly reliable
    "D": 0.50,  # not usually reliable
    "E": 0.30,  # unreliable
    "F": 0.0,   # cannot be judged (ignored)
}

CREDIBILITY_FACTORS: dict[int, float] = {
    1: 1.0,   # confirmed
    2: 0.90,  # probably true
    3: 0.75,  # possibly true
    4: 0.55,  # doubtful
    5: 0.35,  # improbable
    6: 0.15,  # cannot be judged
}


# ── Scoring bands ────────────────────────────────────────────

class Band(StrEnum):
    VERY_HIGH = "VERY_HIGH"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    WEAK = "WEAK"


def score_to_band(score: float) -> Band:
    """Map a 0–100 score to a confidence band."""
    if score >= 90:
        return Band.VERY_HIGH
    elif score >= 75:
        return Band.HIGH
    elif score >= 50:
        return Band.MODERATE
    elif score >= 25:
        return Band.LOW
    else:
        return Band.WEAK


# ── Evidence item ────────────────────────────────────────────

@dataclass
class EvidenceItem:
    """A single piece of evidence contributing to a link score."""
    evidence_type: str
    lr: float | None = None          # override default LR (e.g., from calibration)
    source_reliability: str = "C"    # Admiralty A–F
    credibility: int = 3             # Admiralty 1–6
    source_id: str | None = None
    raw_value: dict[str, Any] = field(default_factory=dict)
    note: str | None = None

    @property
    def effective_lr(self) -> float:
        """LR to use: override or default from registry."""
        if self.lr is not None:
            return self.lr
        et = EVIDENCE_TYPES.get(self.evidence_type)
        return et.default_lr if et else 1.0

    @property
    def family(self) -> EvidenceFamily:
        et = EVIDENCE_TYPES.get(self.evidence_type)
        return et.family if et else EvidenceFamily.HANDLE

    @property
    def description(self) -> str:
        et = EVIDENCE_TYPES.get(self.evidence_type)
        return et.description if et else self.evidence_type


# ── Link score result ────────────────────────────────────────

@dataclass
class LinkScore:
    """Complete scoring result for a persona link."""
    score: float                     # 0–100
    band: Band
    posterior: float                  # raw posterior probability
    evidence_items: list[EvidenceItem]
    family_contributions: dict[str, float]  # family → contribution
    why: list[str]
    warnings: list[str] = field(default_factory=list)


# ── Confidence engine ────────────────────────────────────────

class ConfidenceEngine:
    """
    Computes explainable attribution scores using LLR fusion.

    Scores are always accompanied by evidence chains and
    human-readable explanations.  The engine enforces the
    "never show a bare percentage" rule — every score has a band
    and a why list.
    """

    DEFAULT_PRIOR_ODDS = 1 / 1000

    # Maximum contribution from weak evidence families
    # (addresses cross-family correlation inflation)
    FAMILY_CAPS: dict[EvidenceFamily, float] = {
        EvidenceFamily.TEMPORAL: 0.5,    # cap temporal at ln(1.65) equiv
        EvidenceFamily.HANDLE: 3.0,      # moderate cap on handles
    }

    def __init__(self, prior_odds: float = DEFAULT_PRIOR_ODDS) -> None:
        self.prior_odds = prior_odds

    def compute(self, evidence: list[EvidenceItem]) -> LinkScore:
        """
        Compute the attribution score from a list of evidence items.

        Returns a LinkScore with the full evidence chain and explanation.
        """
        if not evidence:
            return LinkScore(
                score=0,
                band=Band.WEAK,
                posterior=0,
                evidence_items=[],
                family_contributions={},
                why=["No evidence provided"],
            )

        warnings: list[str] = []

        # Group evidence by family
        families: dict[EvidenceFamily, list[float]] = {}
        for item in evidence:
            adj = self._adjusted_llr(item)
            family = item.family
            if family not in families:
                families[family] = []
            families[family].append(adj)

        # Compute family LLRs with correlation damping
        family_llrs: dict[str, float] = {}
        for family, llrs in families.items():
            llrs_sorted = sorted(llrs, reverse=True)
            # max + 0.5 × sum(others) — damps correlated evidence within family
            family_llr = llrs_sorted[0] + 0.5 * sum(llrs_sorted[1:])

            # Apply family cap if set
            cap = self.FAMILY_CAPS.get(family)
            if cap is not None and family_llr > cap:
                warnings.append(
                    f"{family.value} evidence capped at {cap:.2f} "
                    f"(was {family_llr:.2f}) to prevent inflation"
                )
                family_llr = cap

            family_llrs[family.value] = family_llr

        # Compute posterior
        total_llr = sum(family_llrs.values())
        posterior_odds = self.prior_odds * math.exp(total_llr)
        posterior = posterior_odds / (1 + posterior_odds)
        score = round(posterior * 100, 1)
        score = max(0, min(100, score))  # clamp

        band = score_to_band(score)

        # Build why list (sorted by strength)
        why = self._build_why(evidence)

        return LinkScore(
            score=score,
            band=band,
            posterior=posterior,
            evidence_items=evidence,
            family_contributions=family_llrs,
            why=why,
            warnings=warnings,
        )

    def _adjusted_llr(self, item: EvidenceItem) -> float:
        """Compute adjusted LLR for a single evidence item."""
        lr = item.effective_lr
        if lr <= 0:
            return 0

        raw_llr = math.log(lr)

        # Admiralty discount
        reliability = RELIABILITY_FACTORS.get(item.source_reliability, 0.5)
        credibility = CREDIBILITY_FACTORS.get(item.credibility, 0.5)

        return raw_llr * reliability * credibility

    def _build_why(self, evidence: list[EvidenceItem]) -> list[str]:
        """Build human-readable explanation list sorted by LLR strength."""
        items_with_llr = [
            (item, self._adjusted_llr(item))
            for item in evidence
        ]
        items_with_llr.sort(key=lambda x: x[1], reverse=True)
        return [item.description for item, _ in items_with_llr]


# Singleton
confidence_engine = ConfidenceEngine()
