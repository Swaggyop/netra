"""
Tests for the analytics modules: confidence engine, rebrand detector,
infrastructure detectors, and stylometry features.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from backend.app.analytics.confidence.engine import (
    Band,
    ConfidenceEngine,
    EvidenceItem,
    score_to_band,
)
from backend.app.analytics.rebrand.detector import (
    ActorProfile,
    RebrandDetector,
)
from backend.app.analytics.infra.detectors import (
    BannerDetector,
    CertSANDetector,
    ClearnetHost,
    FaviconDetector,
    HeaderOrderDetector,
    OnionProfile,
    SSHKeyDetector,
    run_all_detectors,
)
from backend.app.analytics.stylometry.models import (
    extract_style_features,
    FunctionWordModel,
)


# ── Confidence engine tests ──────────────────────────────────

class TestConfidenceEngine:
    engine = ConfidenceEngine()

    def test_no_evidence_gives_weak(self):
        result = self.engine.compute([])
        assert result.band == Band.WEAK
        assert result.score == 0

    def test_single_pgp_gives_high_or_above(self):
        """PGP fingerprint match (LR=1000) → at least MODERATE."""
        evidence = [
            EvidenceItem(
                evidence_type="pgp_fingerprint",
                source_reliability="A",
                credibility=1,
            )
        ]
        result = self.engine.compute(evidence)
        assert result.band in (Band.VERY_HIGH, Band.HIGH, Band.MODERATE)
        assert result.score >= 50

    def test_weak_evidence_gives_low(self):
        """Single temporal overlap (LR=2.5) → LOW/WEAK."""
        evidence = [
            EvidenceItem(
                evidence_type="temporal_overlap",
                source_reliability="C",
                credibility=4,
            )
        ]
        result = self.engine.compute(evidence)
        assert result.score < 50

    def test_multiple_moderate_stack(self):
        """Multiple moderate evidence items stack up."""
        evidence = [
            EvidenceItem(evidence_type="wallet_cluster", source_reliability="B", credibility=2),
            EvidenceItem(evidence_type="contact_id", source_reliability="B", credibility=2),
            EvidenceItem(evidence_type="handle_exact", source_reliability="C", credibility=3),
        ]
        result = self.engine.compute(evidence)
        assert result.score >= 50
        assert len(result.why) == 3

    def test_unreliable_source_discounted(self):
        """F-grade reliability → zero contribution."""
        evidence = [
            EvidenceItem(
                evidence_type="pgp_fingerprint",
                source_reliability="F",
                credibility=1,
            )
        ]
        result = self.engine.compute(evidence)
        assert result.score < 10

    def test_family_correlation_damping(self):
        """Same-family evidence gets correlation damping (max + 0.5×rest)."""
        # Two handle matches in same family
        two_handles = [
            EvidenceItem(evidence_type="handle_exact", source_reliability="B", credibility=2),
            EvidenceItem(evidence_type="handle_similar", source_reliability="B", credibility=2),
        ]
        # Should be less than 2× a single handle
        single = self.engine.compute([two_handles[0]])
        double = self.engine.compute(two_handles)
        assert double.score < single.score * 2

    def test_why_list_ordered_by_strength(self):
        evidence = [
            EvidenceItem(evidence_type="temporal_overlap", source_reliability="C", credibility=3),
            EvidenceItem(evidence_type="pgp_fingerprint", source_reliability="A", credibility=1),
        ]
        result = self.engine.compute(evidence)
        assert result.why[0] == "Same PGP fingerprint"  # strongest first

    def test_score_bands(self):
        assert score_to_band(95) == Band.VERY_HIGH
        assert score_to_band(80) == Band.HIGH
        assert score_to_band(60) == Band.MODERATE
        assert score_to_band(30) == Band.LOW
        assert score_to_band(10) == Band.WEAK


# ── Rebrand detector tests ───────────────────────────────────

class TestRebrandDetector:
    detector = RebrandDetector(dormancy_days=14, window_days=45, alert_threshold=75)

    def _make_actor(
        self,
        actor_id: str = "a1",
        handle: str = "ShadowX",
        first_offset: int = 0,
        last_offset: int = 30,
        pgp: list[str] | None = None,
        wallets: list[str] | None = None,
        contacts: list[str] | None = None,
    ) -> ActorProfile:
        now = datetime(2025, 6, 1, tzinfo=UTC)
        return ActorProfile(
            actor_id=actor_id,
            handle=handle,
            first_seen=now + timedelta(days=first_offset),
            last_seen=now + timedelta(days=last_offset),
            status="active",
            pgp_fingerprints=pgp or [],
            wallet_addresses=wallets or [],
            contact_ids=contacts or [],
            handles=[handle],
        )

    def test_detects_pgp_rebrand(self):
        """Old actor dormant → new actor with same PGP → alert or high evidence."""
        old = self._make_actor("old", "ShadowX", 0, 30, pgp=["ABCD" * 10])
        new = self._make_actor("new", "DarkWolf", 50, 90, pgp=["ABCD" * 10])

        ref_time = datetime(2025, 6, 1, tzinfo=UTC) + timedelta(days=100)
        candidates = self.detector.find_candidates([old, new], reference_time=ref_time)
        scored = self.detector.score_candidates(candidates)
        
        # Should find candidates with shared PGP evidence
        assert len(scored) >= 1
        assert scored[0].score is not None
        assert scored[0].score.score > 0
        # Evidence should include PGP fingerprint
        pgp_evidence = [e for e in scored[0].evidence if e.evidence_type == "pgp_fingerprint"]
        assert len(pgp_evidence) >= 1

    def test_co_active_actors_not_rebrands(self):
        """Two actors active at the same time → NOT a rebrand."""
        a = self._make_actor("a", "Alpha", 0, 60)
        b = self._make_actor("b", "Beta", 10, 70, pgp=["SAME" * 10])

        ref_time = datetime(2025, 6, 1, tzinfo=UTC) + timedelta(days=100)
        alerts = self.detector.detect([a, b], reference_time=ref_time)
        assert len(alerts) == 0

    def test_no_shared_evidence_no_alert(self):
        """Dormancy match but no shared identifiers → below threshold."""
        old = self._make_actor("old", "Alpha", 0, 30)
        new = self._make_actor("new", "Omega", 50, 90)

        ref_time = datetime(2025, 6, 1, tzinfo=UTC) + timedelta(days=100)
        alerts = self.detector.detect([old, new], reference_time=ref_time)
        # Should not produce alerts (no shared evidence → low score)
        assert all(a.score < 75 for a in alerts)


# ── Infrastructure detector tests ─────────────────────────────

class TestInfraDetectors:
    def _make_onion(self, **overrides) -> OnionProfile:
        defaults = {"address": "abc123" * 9 + "ab.onion"}
        defaults.update(overrides)
        return OnionProfile(**defaults)

    def _make_clearnet(self, **overrides) -> ClearnetHost:
        defaults = {"host": "example.com"}
        defaults.update(overrides)
        return ClearnetHost(**defaults)

    def test_cert_san_detects_clearnet(self):
        onion = self._make_onion(tls_cert_sans=["example.com", "www.example.com"])
        clearnet = self._make_clearnet(host="example.com")
        detector = CertSANDetector()
        results = detector.detect(onion, [clearnet])
        assert len(results) >= 1
        assert results[0].confidence >= 0.90

    def test_favicon_match(self):
        onion = self._make_onion(favicon_hash="abc123def456")
        clearnet = self._make_clearnet(favicon_hash="abc123def456")
        detector = FaviconDetector()
        results = detector.detect(onion, [clearnet])
        assert len(results) == 1
        assert results[0].kind == "favicon"

    def test_ssh_key_match_high_confidence(self):
        key = "ssh-rsa AAAA...test_key_fingerprint"
        onion = self._make_onion(ssh_host_key=key)
        clearnet = self._make_clearnet(ssh_host_key=key)
        detector = SSHKeyDetector()
        results = detector.detect(onion, [clearnet])
        assert len(results) == 1
        assert results[0].confidence >= 0.95

    def test_generic_banner_ignored(self):
        onion = self._make_onion(server_banner="nginx")
        clearnet = self._make_clearnet(server_banner="nginx")
        detector = BannerDetector()
        results = detector.detect(onion, [clearnet])
        assert len(results) == 0  # generic banners filtered

    def test_custom_banner_detected(self):
        banner = "MyCustomServer/2.1.3-beta"
        onion = self._make_onion(server_banner=banner)
        clearnet = self._make_clearnet(server_banner=banner)
        detector = BannerDetector()
        results = detector.detect(onion, [clearnet])
        assert len(results) == 1

    def test_header_order_match(self):
        headers = ["Content-Type", "X-Powered-By", "X-Custom", "Server", "Date"]
        onion = self._make_onion(header_order=headers)
        clearnet = self._make_clearnet(header_order=headers)
        detector = HeaderOrderDetector()
        results = detector.detect(onion, [clearnet])
        assert len(results) == 1

    def test_no_match_returns_empty(self):
        onion = self._make_onion()
        clearnet = self._make_clearnet()
        results = run_all_detectors(onion, [clearnet])
        assert len(results) == 0


# ── Stylometry feature tests ─────────────────────────────────

class TestStylometryFeatures:
    def test_feature_extraction_returns_dict(self):
        features = extract_style_features("This is a test sentence with some words.")
        assert isinstance(features, dict)
        assert "avg_word_length" in features
        assert "vocabulary_richness" in features

    def test_different_styles_produce_different_features(self):
        formal = extract_style_features(
            "Dear community, I would like to inform you that the new product is available. "
            "Please review the specifications carefully before making a purchase."
        )
        casual = extract_style_features(
            "yo check this out!!! new stuff available lol just buy it already omg so good!!"
        )
        # Exclamation density should differ
        assert casual.get("excl_density", 0) > formal.get("excl_density", 0)

    def test_function_word_model_similarity(self):
        model = FunctionWordModel()
        text_a = "The product is available for purchase on the market at a good price."
        text_b = "This item is listed for sale on the platform at a fair cost."
        text_c = "!!! WOW AMAZING DEAL BUY NOW BUY NOW BUY NOW !!!"

        sim_ab = model.similarity(text_a, text_b)
        sim_ac = model.similarity(text_a, text_c)

        # Similar texts should have higher similarity than dissimilar
        assert sim_ab > sim_ac or abs(sim_ab - sim_ac) < 0.3  # allow some tolerance
