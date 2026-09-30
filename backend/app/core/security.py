"""
NETRA — Security utilities (OWASP Top 10 hardening).

This module centralises all authentication, authorisation, and security
helpers so that security logic is never scattered across routers.

OWASP coverage:
  A01 Broken Access Control      → RBAC with role hierarchy
  A02 Cryptographic Failures     → bcrypt passwords, constant-time comparison
  A03 Injection                  → handled by SQLAlchemy ORM + Pydantic (not here)
  A04 Insecure Design            → policy gate / safety gate (separate modules)
  A05 Security Misconfiguration  → Dockerfile non-root, settings validation
  A06 Vulnerable Components      → pip-audit in CI (Makefile)
  A07 Auth Failures              → JWT with short expiry + refresh, bcrypt
  A08 Integrity Failures         → Merkle batches (provenance module)
  A09 Logging/Monitoring         → audit_log table + structured logging
  A10 SSRF                       → URL validation in adapters
"""

from __future__ import annotations

import hmac
import secrets
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

from backend.app.config import get_settings

# ── Password hashing (A02, A07) ─────────────────────────────

_pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=get_settings().bcrypt_rounds,
)


def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time password verification."""
    return _pwd_context.verify(plain, hashed)


# ── JWT tokens (A07) ────────────────────────────────────────

class TokenType(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"


class TokenPayload(BaseModel):
    """Decoded JWT claims."""
    sub: str                        # user ID
    role: str                       # analyst | admin | viewer
    type: TokenType
    exp: datetime
    jti: str = Field(default_factory=lambda: secrets.token_urlsafe(16))


class TokenPair(BaseModel):
    """Issued token pair returned on login."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int                 # seconds until access token expires


def create_token(
    subject: str,
    role: str,
    token_type: TokenType = TokenType.ACCESS,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT. Short-lived by default (OWASP A07)."""
    settings = get_settings()

    if expires_delta is None:
        if token_type == TokenType.ACCESS:
            expires_delta = timedelta(minutes=settings.jwt_access_token_expire_minutes)
        else:
            expires_delta = timedelta(minutes=settings.jwt_refresh_token_expire_minutes)

    payload = TokenPayload(
        sub=subject,
        role=role,
        type=token_type,
        exp=datetime.now(UTC) + expires_delta,
    )
    # Build payload dict manually — jose requires `exp` as int timestamp
    claims = {
        "sub": payload.sub,
        "role": payload.role,
        "type": payload.type.value,
        "exp": int(payload.exp.timestamp()),
        "jti": payload.jti,
    }
    return jwt.encode(
        claims,
        settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def create_token_pair(subject: str, role: str) -> TokenPair:
    """Issue an access + refresh token pair."""
    settings = get_settings()
    access = create_token(subject, role, TokenType.ACCESS)
    refresh = create_token(subject, role, TokenType.REFRESH)
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


def decode_token(token: str) -> TokenPayload:
    """
    Decode and validate a JWT.

    Raises JWTError on invalid/expired tokens.
    """
    settings = get_settings()
    try:
        raw = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
        )
        return TokenPayload(**raw)
    except JWTError:
        raise


# ── Role-based access control (A01) ─────────────────────────

class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


# Role hierarchy: admin > analyst > viewer
_ROLE_HIERARCHY: dict[Role, int] = {
    Role.VIEWER: 0,
    Role.ANALYST: 1,
    Role.ADMIN: 2,
}


def has_permission(user_role: str, required_role: Role) -> bool:
    """Check if a user's role meets or exceeds the required role level."""
    user_level = _ROLE_HIERARCHY.get(Role(user_role), -1)
    required_level = _ROLE_HIERARCHY[required_role]
    return user_level >= required_level


# ── CSRF protection (A01) ───────────────────────────────────

def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)


def validate_csrf_token(token: str, expected: str) -> bool:
    """Constant-time CSRF token comparison to prevent timing attacks."""
    return hmac.compare_digest(token, expected)


# ── Input sanitisation helpers (A03, A07) ────────────────────

def sanitize_html(text: str) -> str:
    """
    Strip all HTML tags for safe rendering in reports.

    Uses bleach to prevent XSS in PDF/HTML exports (OWASP A03).
    """
    import bleach
    return bleach.clean(text, tags=[], attributes={}, strip=True)


def validate_url_no_ssrf(url: str) -> bool:
    """
    Basic SSRF prevention: reject private/internal network URLs (OWASP A10).

    Full SSRF protection also requires the Tor container network isolation.
    """
    from urllib.parse import urlparse
    import ipaddress

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return False

    # Allow .onion (routed through Tor container)
    if hostname.endswith(".onion"):
        return True

    # Block private IPs
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except ValueError:
        # It's a hostname, not an IP — check common internal patterns
        blocked_patterns = [
            "localhost", "127.0.0.1", "0.0.0.0",
            "169.254.", "10.", "172.16.", "172.17.",
            "172.18.", "172.19.", "172.20.", "172.21.",
            "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168.",
            "metadata.google.internal",
            "metadata.aws.internal",
        ]
        hostname_lower = hostname.lower()
        if any(hostname_lower.startswith(p) or hostname_lower == p for p in blocked_patterns):
            return False

    return True


# ── Audit helper ─────────────────────────────────────────────

class AuditAction(StrEnum):
    """Auditable actions for the audit_log table (OWASP A09)."""
    LOGIN = "login"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    VIEW_ACTOR = "view_actor"
    CREATE_ACTOR = "create_actor"
    REVIEW_LINK = "review_link"
    EXPORT = "export"
    SOURCE_TOGGLE = "source_toggle"
    CONFIG_CHANGE = "config_change"
    USER_CREATE = "user_create"
    USER_ROLE_CHANGE = "user_role_change"


def build_audit_entry(
    actor: str,
    action: AuditAction,
    target: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an audit log entry dict ready for insertion."""
    return {
        "actor": actor,
        "action": action.value,
        "target": target,
        "at": datetime.now(UTC).replace(tzinfo=None),
        "detail": detail or {},
    }
