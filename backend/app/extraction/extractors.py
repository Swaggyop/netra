"""
NETRA — Entity extraction pipeline (§7, §250–257).

Regex-first, spaCy-second approach for extracting identifiers
from text content.  All extractors are unit-testable and deterministic
for the same input.

Extracted entity kinds:
  - pgp          PGP fingerprint (40 hex, spaced variants)
  - wallet       BTC (legacy, P2SH, bech32), ETH, TRON, XMR
  - email        Email addresses
  - domain       Domain names
  - onion        Onion v3 addresses (56 chars + .onion)
  - contact_id   Telegram @handles, Jabber/XMPP JIDs, Session IDs
  - handle       Usernames from post metadata and signature patterns
  - ip           IPv4 addresses
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EntityHit:
    """A single extracted entity."""
    kind: str
    value: str
    normalized: str
    start: int = -1    # character offset in source text
    end: int = -1
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


# ── PGP Fingerprint Extractor ────────────────────────────────

_PGP_FINGERPRINT_PATTERN = re.compile(
    r"""
    (?:PGP|GPG|fingerprint|fpr|fp)[:\s]*    # optional label
    ([0-9A-Fa-f]{4}[\s\-]?){9}             # 9 groups of 4 hex
    [0-9A-Fa-f]{4}                          # last group
    |                                        # OR
    \b([0-9A-Fa-f]{40})\b                   # 40 contiguous hex
    """,
    re.VERBOSE | re.IGNORECASE,
)

_PGP_BLOCK_PATTERN = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)


def extract_pgp(text: str) -> list[EntityHit]:
    """Extract PGP fingerprints from text."""
    hits: list[EntityHit] = []

    for match in _PGP_FINGERPRINT_PATTERN.finditer(text):
        raw = match.group(0)
        # Extract just the hex characters
        hex_only = re.sub(r"[^0-9A-Fa-f]", "", raw)
        if len(hex_only) == 40:
            normalized = hex_only.upper()
            hits.append(EntityHit(
                kind="pgp",
                value=raw.strip(),
                normalized=normalized,
                start=match.start(),
                end=match.end(),
            ))

    # Also detect armored key blocks (extract fingerprint if present)
    for match in _PGP_BLOCK_PATTERN.finditer(text):
        hits.append(EntityHit(
            kind="pgp",
            value="[PGP_KEY_BLOCK]",
            normalized="KEY_BLOCK_DETECTED",
            start=match.start(),
            end=match.end(),
            confidence=0.8,
            metadata={"type": "armored_block"},
        ))

    return hits


# ── Cryptocurrency Wallet Extractors ─────────────────────────

# Bitcoin: legacy (1...), P2SH (3...), bech32 (bc1...)
_BTC_LEGACY = re.compile(r"\b(1[1-9A-HJ-NP-Za-km-z]{25,34})\b")
_BTC_P2SH = re.compile(r"\b(3[1-9A-HJ-NP-Za-km-z]{25,34})\b")
_BTC_BECH32 = re.compile(r"\b(bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,62})\b", re.IGNORECASE)

# Ethereum: 0x + 40 hex
_ETH = re.compile(r"\b(0x[0-9a-fA-F]{40})\b")

# TRON: T + 33 base58
_TRON = re.compile(r"\b(T[1-9A-HJ-NP-Za-km-z]{33})\b")

# Monero: starts with 4, 95 characters
_XMR = re.compile(r"\b(4[0-9A-Za-z]{94})\b")


def extract_wallets(text: str) -> list[EntityHit]:
    """Extract cryptocurrency wallet addresses."""
    hits: list[EntityHit] = []

    for pattern, currency in [
        (_BTC_BECH32, "BTC"),
        (_BTC_LEGACY, "BTC"),
        (_BTC_P2SH, "BTC"),
        (_ETH, "ETH"),
        (_TRON, "TRON"),
        (_XMR, "XMR"),
    ]:
        for match in pattern.finditer(text):
            addr = match.group(1)
            # XMR is untraceable — tag it
            meta = {"currency": currency}
            if currency == "XMR":
                meta["traceable"] = False

            hits.append(EntityHit(
                kind="wallet",
                value=addr,
                normalized=addr.lower() if currency == "ETH" else addr,
                start=match.start(),
                end=match.end(),
                metadata=meta,
            ))

    return hits


# ── Email Extractor ──────────────────────────────────────────

_EMAIL = re.compile(
    r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"
)


def extract_emails(text: str) -> list[EntityHit]:
    """Extract email addresses."""
    hits: list[EntityHit] = []
    for match in _EMAIL.finditer(text):
        email = match.group(1)
        hits.append(EntityHit(
            kind="email",
            value=email,
            normalized=email.lower(),
            start=match.start(),
            end=match.end(),
        ))
    return hits


# ── Domain Extractor ─────────────────────────────────────────

_DOMAIN = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\."
    r"(?:[a-zA-Z]{2,}))\b"
)

# TLDs to exclude (too common, not useful as identifiers)
_NOISE_TLDS = {"com", "org", "net", "edu", "gov", "io", "co"}


def extract_domains(text: str) -> list[EntityHit]:
    """Extract domain names (excluding very common TLDs unless specific)."""
    hits: list[EntityHit] = []
    for match in _DOMAIN.finditer(text):
        domain = match.group(1)
        # Skip email domains (already caught by email extractor)
        if f"@{domain}" in text:
            continue
        # Skip noise domains
        tld = domain.split(".")[-1].lower()
        if len(domain.split(".")) <= 2 and tld in _NOISE_TLDS:
            continue
        hits.append(EntityHit(
            kind="domain",
            value=domain,
            normalized=domain.lower(),
            start=match.start(),
            end=match.end(),
        ))
    return hits


# ── Onion v3 Extractor ───────────────────────────────────────

_ONION_V3 = re.compile(
    r"\b([a-z2-7]{56}\.onion)\b",
    re.IGNORECASE,
)


def extract_onions(text: str) -> list[EntityHit]:
    """Extract Tor .onion v3 addresses."""
    hits: list[EntityHit] = []
    for match in _ONION_V3.finditer(text):
        addr = match.group(1)
        hits.append(EntityHit(
            kind="onion",
            value=addr,
            normalized=addr.lower(),
            start=match.start(),
            end=match.end(),
        ))
    return hits


# ── Contact ID Extractor ─────────────────────────────────────

# Telegram handles
_TELEGRAM = re.compile(r"(?<!\w)(@[a-zA-Z][a-zA-Z0-9_]{4,31})\b")

# Jabber/XMPP JIDs
_JABBER = re.compile(
    r"\b([a-zA-Z0-9._%+\-]+@(?:jabber|xmpp|conversations)\.[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b",
    re.IGNORECASE,
)

# Session IDs (05 + 64 hex)
_SESSION = re.compile(r"\b(05[0-9a-fA-F]{64})\b")

# Wickr IDs (me/ prefix or just flagged by context)
_WICKR = re.compile(r"(?:wickr|wickr\.me)[:\s]+([a-zA-Z0-9_]{3,20})", re.IGNORECASE)


def extract_contact_ids(text: str) -> list[EntityHit]:
    """Extract contact identifiers (Telegram, Jabber, Session, Wickr)."""
    hits: list[EntityHit] = []

    for match in _TELEGRAM.finditer(text):
        handle = match.group(1)
        hits.append(EntityHit(
            kind="contact_id",
            value=handle,
            normalized=handle.lower(),
            start=match.start(),
            end=match.end(),
            metadata={"platform": "telegram"},
        ))

    for match in _JABBER.finditer(text):
        jid = match.group(1)
        hits.append(EntityHit(
            kind="contact_id",
            value=jid,
            normalized=jid.lower(),
            start=match.start(),
            end=match.end(),
            metadata={"platform": "xmpp"},
        ))

    for match in _SESSION.finditer(text):
        sid = match.group(1)
        hits.append(EntityHit(
            kind="contact_id",
            value=sid,
            normalized=sid.lower(),
            start=match.start(),
            end=match.end(),
            metadata={"platform": "session"},
        ))

    for match in _WICKR.finditer(text):
        wid = match.group(1)
        hits.append(EntityHit(
            kind="contact_id",
            value=f"wickr:{wid}",
            normalized=f"wickr:{wid.lower()}",
            start=match.start(),
            end=match.end(),
            metadata={"platform": "wickr"},
        ))

    return hits


# ── IPv4 Extractor ───────────────────────────────────────────

_IPV4 = re.compile(
    r"\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def extract_ipv4(text: str) -> list[EntityHit]:
    """Extract IPv4 addresses."""
    hits: list[EntityHit] = []
    for match in _IPV4.finditer(text):
        ip = match.group(0)
        hits.append(EntityHit(
            kind="ip",
            value=ip,
            normalized=ip,
            start=match.start(),
            end=match.end(),
        ))
    return hits


# ── Handle Extractor (from metadata + signatures) ────────────

_SIGNATURE_PATTERNS = [
    re.compile(r"^--\s*(.+)$", re.MULTILINE),                      # -- Handle
    re.compile(r"^Regards,\s*(.+)$", re.MULTILINE),                 # Regards, Handle
    re.compile(r"^Cheers,\s*(.+)$", re.MULTILINE),                  # Cheers, Handle
    re.compile(r"^\-\s*(.+)$", re.MULTILINE),                       # - Handle
]


def extract_handles(text: str, metadata: dict[str, Any] | None = None) -> list[EntityHit]:
    """
    Extract handles from post metadata and text signatures.

    The metadata handle (from post author field) is the primary source.
    Text signatures are secondary.
    """
    hits: list[EntityHit] = []

    # From metadata
    if metadata:
        handle = metadata.get("author_handle") or metadata.get("handle")
        if handle and isinstance(handle, str) and len(handle) >= 2:
            hits.append(EntityHit(
                kind="handle",
                value=handle,
                normalized=handle.lower().strip(),
                confidence=1.0,
                metadata={"source": "metadata"},
            ))

    # From text signatures
    for pattern in _SIGNATURE_PATTERNS:
        for match in pattern.finditer(text):
            sig_handle = match.group(1).strip()
            # Filter out PGP fingerprints and other non-handle content
            if len(sig_handle) < 2 or len(sig_handle) > 64:
                continue
            if re.match(r"^[0-9A-Fa-f]{16,}$", sig_handle):
                continue  # PGP fingerprint
            hits.append(EntityHit(
                kind="handle",
                value=sig_handle,
                normalized=sig_handle.lower().strip(),
                confidence=0.7,
                metadata={"source": "signature"},
            ))

    return hits


# ── Master extraction pipeline ───────────────────────────────

ALL_EXTRACTORS = [
    extract_pgp,
    extract_wallets,
    extract_emails,
    extract_onions,
    extract_contact_ids,
    extract_ipv4,
    extract_domains,
]


def extract_all(
    text: str,
    metadata: dict[str, Any] | None = None,
) -> list[EntityHit]:
    """
    Run all extractors on text content.

    Returns a deduplicated list of EntityHit objects.
    """
    hits: list[EntityHit] = []

    # Run all regex extractors
    for extractor in ALL_EXTRACTORS:
        hits.extend(extractor(text))

    # Handle extraction (needs metadata)
    hits.extend(extract_handles(text, metadata))

    # Deduplicate by (kind, normalized)
    seen: set[tuple[str, str]] = set()
    unique: list[EntityHit] = []
    for hit in hits:
        key = (hit.kind, hit.normalized)
        if key not in seen:
            seen.add(key)
            unique.append(hit)

    return unique
