"""
Tests for the policy gate, safety gate, redaction, and provenance modules.

These are the compliance-critical modules — they MUST have thorough tests.
"""

from __future__ import annotations

from backend.app.core.policy import (
    CandidateRef,
    Decision,
    PolicyGate,
    SourceRecord,
)
from backend.app.core.safety import SafetyDecision, SafetyGate
from backend.app.core.redaction import redact_pii
from backend.app.core.provenance import (
    compute_content_hash,
    compute_evidence_id,
    compute_merkle_root,
    verify_merkle_root,
    MerkleBatchManager,
)


# ── Policy gate tests ────────────────────────────────────────

class TestPolicyGate:
    gate = PolicyGate()

    def _make_source(self, **overrides) -> SourceRecord:
        defaults = {
            "source_id": "test_src",
            "source_type": "synthetic",
            "authorization_status": "approved",
            "authorization_ref": None,
            "enabled": True,
            "retention_days": 365,
            "pii_policy": None,
            "reliability_grade": "B",
        }
        defaults.update(overrides)
        return SourceRecord(**defaults)

    def _make_ref(self, **overrides) -> CandidateRef:
        defaults = {
            "url": "http://example.com/post/123",
            "content_type": "text/html",
        }
        defaults.update(overrides)
        return CandidateRef(**defaults)

    def test_approved_source_allows(self):
        result = self.gate.decide(self._make_source(), self._make_ref())
        assert result.decision == Decision.ALLOW

    def test_disabled_source_blocks(self):
        result = self.gate.decide(
            self._make_source(enabled=False),
            self._make_ref(),
        )
        assert result.decision == Decision.BLOCK
        assert "source_disabled" in result.rule_hits

    def test_unauthorized_source_blocks(self):
        result = self.gate.decide(
            self._make_source(authorization_status="disabled"),
            self._make_ref(),
        )
        assert result.decision == Decision.BLOCK
        assert "unauthorized" in result.rule_hits

    def test_authorized_without_ref_blocks(self):
        result = self.gate.decide(
            self._make_source(
                authorization_status="authorized",
                authorization_ref=None,
            ),
            self._make_ref(),
        )
        assert result.decision == Decision.BLOCK
        assert "missing_auth_ref" in result.rule_hits

    def test_authorized_with_ref_allows(self):
        result = self.gate.decide(
            self._make_source(
                authorization_status="authorized",
                authorization_ref="JWT_TOKEN_HERE",
            ),
            self._make_ref(),
        )
        assert result.decision == Decision.ALLOW

    def test_image_content_type_blocks(self):
        result = self.gate.decide(
            self._make_source(),
            self._make_ref(content_type="image/jpeg"),
        )
        assert result.decision == Decision.BLOCK
        assert "content_type_blocked" in result.rule_hits

    def test_oversized_content_blocks(self):
        result = self.gate.decide(
            self._make_source(),
            self._make_ref(size_bytes=100 * 1024 * 1024),
        )
        assert result.decision == Decision.BLOCK
        assert "size_exceeded" in result.rule_hits

    def test_redact_policy_returns_redact_allow(self):
        result = self.gate.decide(
            self._make_source(pii_policy="redact_all"),
            self._make_ref(),
        )
        assert result.decision == Decision.REDACT_ALLOW

    def test_no_retention_blocks(self):
        result = self.gate.decide(
            self._make_source(retention_days=0),
            self._make_ref(),
        )
        assert result.decision == Decision.BLOCK
        assert "no_retention" in result.rule_hits

    def test_block_produces_no_event_id(self):
        result = self.gate.decide(
            self._make_source(enabled=False),
            self._make_ref(),
        )
        assert result.event_id is None

    def test_allow_produces_event_id(self):
        result = self.gate.decide(self._make_source(), self._make_ref())
        assert result.event_id is not None


# ── Safety gate tests ────────────────────────────────────────

class TestSafetyGate:
    gate = SafetyGate()

    def test_text_html_allowed(self):
        result = self.gate.pre_fetch("text/html")
        assert result.decision == SafetyDecision.ALLOW

    def test_image_blocked(self):
        result = self.gate.pre_fetch("image/png")
        assert result.decision == SafetyDecision.BLOCK

    def test_video_blocked(self):
        result = self.gate.pre_fetch("video/mp4")
        assert result.decision == SafetyDecision.BLOCK

    def test_zip_blocked(self):
        result = self.gate.pre_fetch("application/zip")
        assert result.decision == SafetyDecision.BLOCK

    def test_clean_text_allowed(self):
        result = self.gate.post_fetch("This is a normal marketplace listing for electronics.")
        assert result.decision == SafetyDecision.ALLOW


# ── Redaction tests ──────────────────────────────────────────

class TestRedaction:
    def test_aadhaar_redacted(self):
        text = "My aadhaar is 1234 5678 9012"
        result = redact_pii(text)
        assert "1234 5678 9012" not in result.redacted_text
        assert "[AADHAAR_REDACTED]" in result.redacted_text
        assert "aadhaar:1" in result.redactions

    def test_pan_redacted(self):
        text = "PAN: ABCDE1234F"
        result = redact_pii(text)
        assert "ABCDE1234F" not in result.redacted_text
        assert "[PAN_REDACTED]" in result.redacted_text

    def test_phone_redacted(self):
        text = "Call 9876543210 now"
        result = redact_pii(text)
        assert "9876543210" not in result.redacted_text

    def test_victim_email_redacted(self):
        text = "Contact victim@gmail.com for more"
        result = redact_pii(text)
        assert "victim@gmail.com" not in result.redacted_text

    def test_protonmail_preserved(self):
        text = "Reach me at dealer@protonmail.com"
        result = redact_pii(text)
        assert "dealer@protonmail.com" in result.redacted_text

    def test_no_pii_unchanged(self):
        text = "Normal text with no PII at all."
        result = redact_pii(text)
        assert result.redacted_text == text
        assert result.redactions == []


# ── Provenance tests ─────────────────────────────────────────

class TestProvenance:
    def test_content_hash_deterministic(self):
        content = b"test content"
        h1 = compute_content_hash(content)
        h2 = compute_content_hash(content)
        assert h1 == h2
        assert h1.startswith("sha256:")

    def test_different_content_different_hash(self):
        h1 = compute_content_hash(b"content A")
        h2 = compute_content_hash(b"content B")
        assert h1 != h2

    def test_evidence_id_deterministic(self):
        eid1 = compute_evidence_id("sha256:abc123", "src_1")
        eid2 = compute_evidence_id("sha256:abc123", "src_1")
        assert eid1 == eid2

    def test_merkle_root_single_leaf(self):
        test_hash = "a" * 64  # valid hex SHA-256
        root = compute_merkle_root([f"sha256:{test_hash}"])
        assert isinstance(root, str)
        assert len(root) == 64  # hex SHA-256

    def test_merkle_root_multiple_leaves(self):
        leaves = ["sha256:aaa", "sha256:bbb", "sha256:ccc"]
        root = compute_merkle_root(leaves)
        assert isinstance(root, str)

    def test_merkle_verification(self):
        leaves = ["sha256:aaa", "sha256:bbb", "sha256:ccc", "sha256:ddd"]
        root = compute_merkle_root(leaves)
        assert verify_merkle_root(leaves, root)

    def test_merkle_verification_fails_on_tamper(self):
        leaves = ["sha256:aaa", "sha256:bbb"]
        root = compute_merkle_root(leaves)
        tampered = ["sha256:aaa", "sha256:TAMPERED"]
        assert not verify_merkle_root(tampered, root)


class TestMerkleBatchManager:
    def test_batch_closes_at_size(self):
        mgr = MerkleBatchManager(batch_size=3, batch_timeout_seconds=9999)
        assert mgr.add_leaf("sha256:a") is None
        assert mgr.add_leaf("sha256:b") is None
        result = mgr.add_leaf("sha256:c")
        assert result is not None
        assert result["leaf_count"] == 3
        assert result["root_hash"].startswith("sha256:")

    def test_pending_count(self):
        mgr = MerkleBatchManager(batch_size=100)
        mgr.add_leaf("sha256:x")
        mgr.add_leaf("sha256:y")
        assert mgr.pending_count == 2
