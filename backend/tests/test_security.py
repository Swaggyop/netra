"""
Tests for OWASP security utilities.
"""

from __future__ import annotations

from backend.app.core.security import (
    Role,
    build_audit_entry,
    generate_csrf_token,
    has_permission,
    hash_password,
    sanitize_html,
    validate_csrf_token,
    validate_url_no_ssrf,
    verify_password,
    AuditAction,
)


class TestPasswordHashing:
    def test_hash_and_verify(self):
        plain = "SecureP@ssw0rd!"
        hashed = hash_password(plain)
        assert hashed != plain
        assert verify_password(plain, hashed)

    def test_wrong_password_fails(self):
        hashed = hash_password("correct_password")
        assert not verify_password("wrong_password", hashed)

    def test_different_hashes_for_same_password(self):
        """bcrypt uses random salt — hashes differ."""
        h1 = hash_password("same_password")
        h2 = hash_password("same_password")
        assert h1 != h2  # different salts


class TestRBAC:
    def test_admin_has_all_permissions(self):
        assert has_permission("admin", Role.VIEWER)
        assert has_permission("admin", Role.ANALYST)
        assert has_permission("admin", Role.ADMIN)

    def test_analyst_has_viewer_and_analyst(self):
        assert has_permission("analyst", Role.VIEWER)
        assert has_permission("analyst", Role.ANALYST)
        assert not has_permission("analyst", Role.ADMIN)

    def test_viewer_has_only_viewer(self):
        assert has_permission("viewer", Role.VIEWER)
        assert not has_permission("viewer", Role.ANALYST)


class TestCSRF:
    def test_token_generation(self):
        token = generate_csrf_token()
        assert len(token) > 20

    def test_valid_token_matches(self):
        token = generate_csrf_token()
        assert validate_csrf_token(token, token)

    def test_different_tokens_dont_match(self):
        t1 = generate_csrf_token()
        t2 = generate_csrf_token()
        assert not validate_csrf_token(t1, t2)


class TestHTMLSanitisation:
    def test_strips_all_tags(self):
        result = sanitize_html("<script>alert('xss')</script>Hello")
        assert "<script>" not in result
        assert "Hello" in result

    def test_strips_nested_tags(self):
        result = sanitize_html("<div><b>bold</b></div>")
        assert "bold" in result
        assert "<" not in result


class TestSSRFValidation:
    def test_public_url_allowed(self):
        assert validate_url_no_ssrf("https://example.com/path")

    def test_onion_url_allowed(self):
        assert validate_url_no_ssrf("http://abc123.onion/path")

    def test_localhost_blocked(self):
        assert not validate_url_no_ssrf("http://localhost:8080")

    def test_private_ip_blocked(self):
        assert not validate_url_no_ssrf("http://192.168.1.1")
        assert not validate_url_no_ssrf("http://10.0.0.1")

    def test_loopback_blocked(self):
        assert not validate_url_no_ssrf("http://127.0.0.1")

    def test_cloud_metadata_blocked(self):
        assert not validate_url_no_ssrf("http://metadata.google.internal")
        assert not validate_url_no_ssrf("http://metadata.aws.internal")

    def test_empty_url_blocked(self):
        assert not validate_url_no_ssrf("")


class TestAuditEntry:
    def test_builds_valid_entry(self):
        entry = build_audit_entry(
            actor="user_123",
            action=AuditAction.VIEW_ACTOR,
            target="actor_456",
            detail={"depth": 2},
        )
        assert entry["actor"] == "user_123"
        assert entry["action"] == "view_actor"
        assert entry["target"] == "actor_456"
        assert entry["detail"]["depth"] == 2
        assert entry["at"] is not None
