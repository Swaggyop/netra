"""
NETRA — Evaluation harness.

Runs the extraction → resolution → rebrand detection pipeline
against synthetic data and compares results to ground truth.

Computes:
  - Extractor recall and precision per entity type
  - Rebrand detection precision/recall/F1 at each difficulty level
  - Confidence score distribution analysis
  - False positive analysis on decoy pairs

Usage:
    python -m backend.app.analytics.evaluate --data datagen/output
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from backend.app.extraction.extractors import extract_all
from backend.app.analytics.rebrand.detector import ActorProfile, RebrandDetector
from backend.app.analytics.confidence.engine import ConfidenceEngine, EvidenceItem

logger = logging.getLogger(__name__)


# ── Metrics ──────────────────────────────────────────────────

@dataclass
class ExtractorMetrics:
    """Precision/recall metrics for an entity extractor."""
    kind: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def recall(self) -> float:
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


@dataclass
class RebrandMetrics:
    """Precision/recall for rebrand detection."""
    difficulty: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    scores: list[float] = field(default_factory=list)

    @property
    def precision(self) -> float:
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def recall(self) -> float:
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def avg_score(self) -> float:
        return sum(self.scores) / len(self.scores) if self.scores else 0.0


# ── Extractor evaluation ─────────────────────────────────────

def evaluate_extractors(data_dir: str) -> dict[str, ExtractorMetrics]:
    """
    Evaluate extractor recall against generated actor identifiers.

    For each actor, checks if their known identifiers
    (PGP, wallets, contacts, emails) appear in their posts.
    """
    data_path = Path(data_dir)

    with open(data_path / "actors.json") as f:
        actors = json.load(f)
    with open(data_path / "posts.json") as f:
        posts = json.load(f)

    # Index posts by actor_id
    posts_by_actor: dict[str, list[str]] = {}
    for post in posts:
        actor_id = post["actor_id"]
        if actor_id not in posts_by_actor:
            posts_by_actor[actor_id] = []
        posts_by_actor[actor_id].append(post["text"])

    metrics: dict[str, ExtractorMetrics] = {
        "pgp": ExtractorMetrics("pgp"),
        "wallet": ExtractorMetrics("wallet"),
        "contact_id": ExtractorMetrics("contact_id"),
        "email": ExtractorMetrics("email"),
        "handle": ExtractorMetrics("handle"),
    }

    for actor in actors:
        actor_id = actor["actor_id"]
        actor_texts = posts_by_actor.get(actor_id, [])
        if not actor_texts:
            continue

        # Concatenate all posts for extraction
        combined = "\n\n".join(actor_texts)
        hits = extract_all(combined, {"handle": actor["handle"]})
        extracted_normalized = {(h.kind, h.normalized) for h in hits}

        # Check PGP
        pgp = actor.get("pgp_fingerprint", "")
        if pgp:
            pgp_norm = pgp.upper()
            if ("pgp", pgp_norm) in extracted_normalized:
                metrics["pgp"].true_positives += 1
            else:
                # Check if any post contains the PGP — if so, it's a false negative
                if pgp in combined or pgp.lower() in combined:
                    metrics["pgp"].false_negatives += 1

        # Check wallets
        for currency, addrs in actor.get("wallets", {}).items():
            for addr in addrs:
                norm = addr.lower() if currency == "ETH" else addr
                if ("wallet", norm) in extracted_normalized:
                    metrics["wallet"].true_positives += 1
                elif addr in combined:
                    metrics["wallet"].false_negatives += 1

        # Check contacts
        for cid in actor.get("contact_ids", []):
            norm = cid.lower()
            if ("contact_id", norm) in extracted_normalized:
                metrics["contact_id"].true_positives += 1
            elif cid in combined:
                metrics["contact_id"].false_negatives += 1

        # Check handle
        handle_norm = actor["handle"].lower().strip()
        if ("handle", handle_norm) in extracted_normalized:
            metrics["handle"].true_positives += 1
        else:
            metrics["handle"].false_negatives += 1

    return metrics


# ── Rebrand detection evaluation ─────────────────────────────

def evaluate_rebrands(data_dir: str) -> dict[str, RebrandMetrics]:
    """
    Evaluate rebrand detection against ground truth.
    """
    data_path = Path(data_dir)

    with open(data_path / "actors.json") as f:
        actors_data = json.load(f)
    with open(data_path / "truth.json") as f:
        truth = json.load(f)

    # Build actor profiles
    profiles: list[ActorProfile] = []
    for a in actors_data:
        btc_addrs = a.get("wallets", {}).get("BTC", [])
        profiles.append(ActorProfile(
            actor_id=a["actor_id"],
            handle=a["handle"],
            first_seen=datetime.fromisoformat(a["first_seen"]),
            last_seen=datetime.fromisoformat(a["last_seen"]),
            status="dormant" if a.get("is_dormant") else "active",
            pgp_fingerprints=[a.get("pgp_fingerprint", "")],
            wallet_addresses=btc_addrs,
            contact_ids=a.get("contact_ids", []),
            handles=[a["handle"]] + a.get("alt_handles", []),
        ))

    # Run detector
    detector = RebrandDetector(dormancy_days=7, window_days=60, alert_threshold=0)  # low threshold to see all scores
    ref_time = max(p.last_seen for p in profiles) + timedelta(days=30)
    candidates = detector.find_candidates(profiles, reference_time=ref_time)
    scored = detector.score_candidates(candidates)

    # Build ground truth lookup
    gt_pairs = {
        (p["old_actor_id"], p["new_actor_id"]): p
        for p in truth.get("rebrand_pairs", [])
    }
    decoy_pairs = {
        (p["actor_a_id"], p["actor_b_id"])
        for p in truth.get("decoy_pairs", [])
    }

    # Evaluate per difficulty
    metrics: dict[str, RebrandMetrics] = {
        "easy": RebrandMetrics("easy"),
        "medium": RebrandMetrics("medium"),
        "hard": RebrandMetrics("hard"),
        "decoy": RebrandMetrics("decoy"),
    }

    detected_pairs: set[tuple[str, str]] = set()

    for candidate in scored:
        if candidate.score is None:
            continue

        pair_key = (candidate.old_actor.actor_id, candidate.new_actor.actor_id)

        if pair_key in gt_pairs:
            difficulty = gt_pairs[pair_key]["difficulty"]
            metrics[difficulty].scores.append(candidate.score.score)
            if candidate.score.score >= 50:
                metrics[difficulty].true_positives += 1
                detected_pairs.add(pair_key)
        elif pair_key in decoy_pairs or (pair_key[1], pair_key[0]) in decoy_pairs:
            if candidate.score.score >= 50:
                metrics["decoy"].false_positives += 1
            metrics["decoy"].scores.append(candidate.score.score)

    # Count false negatives (ground truth pairs not detected)
    for pair_key, gt in gt_pairs.items():
        if pair_key not in detected_pairs:
            metrics[gt["difficulty"]].false_negatives += 1

    return metrics


# ── Report generation ────────────────────────────────────────

def run_evaluation(data_dir: str = "datagen/output") -> dict[str, Any]:
    """Run the full evaluation and return a summary report."""
    print(f"\n{'='*60}")
    print("NETRA — Evaluation Report")
    print(f"{'='*60}\n")

    # Extractor evaluation
    extractor_metrics = evaluate_extractors(data_dir)
    print("Extractor Performance:")
    print(f"  {'Kind':<15} {'Precision':>10} {'Recall':>10} {'F1':>10} {'TP':>5} {'FP':>5} {'FN':>5}")
    print(f"  {'-'*60}")
    for kind, m in extractor_metrics.items():
        print(f"  {kind:<15} {m.precision:>10.2%} {m.recall:>10.2%} {m.f1:>10.2%} {m.true_positives:>5} {m.false_positives:>5} {m.false_negatives:>5}")

    # Rebrand evaluation
    print(f"\nRebrand Detection Performance:")
    rebrand_metrics = evaluate_rebrands(data_dir)
    print(f"  {'Difficulty':<15} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Avg Score':>10}")
    print(f"  {'-'*55}")
    for diff, m in rebrand_metrics.items():
        print(f"  {diff:<15} {m.precision:>10.2%} {m.recall:>10.2%} {m.f1:>10.2%} {m.avg_score:>10.1f}")

    summary = {
        "extractors": {k: {"precision": m.precision, "recall": m.recall, "f1": m.f1} for k, m in extractor_metrics.items()},
        "rebrands": {k: {"precision": m.precision, "recall": m.recall, "f1": m.f1, "avg_score": m.avg_score} for k, m in rebrand_metrics.items()},
    }

    print(f"\n{'='*60}\n")
    return summary


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="NETRA evaluation harness")
    parser.add_argument("--data", default="datagen/output", help="Data directory")
    args = parser.parse_args()
    run_evaluation(args.data)


if __name__ == "__main__":
    main()
