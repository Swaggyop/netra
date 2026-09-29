"""
NETRA — Infrastructure correlation detectors (§10).

De-anonymisation via onion service misconfiguration detection.
Compares observable properties of .onion services against clearnet
hosts to find misconfigurations that leak operator identity.

Detector categories:
  D1  TLS certificate Subject Alternative Names
  D2  Favicon hash (MD5 of favicon.ico)
  D3  Server banner / HTTP headers fingerprint
  D4  Server status page pattern matching
  D5  SSH host key fingerprint
  D6  HTTP header ordering
  D7  Custom error page hash

All detectors implement the DetectorProtocol and return
InfraCorrelation results with a confidence score.
"""

from __future__ import annotations

import hashlib
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── Result types ─────────────────────────────────────────────

@dataclass(frozen=True)
class InfraCorrelation:
    """A single infrastructure correlation finding."""
    detector_id: str
    onion_address: str
    clearnet_match: str          # domain / IP
    kind: str                    # cert_san | favicon | banner | ...
    confidence: float            # 0.0 – 1.0
    raw_evidence: dict[str, Any] = field(default_factory=dict)
    description: str = ""


@dataclass(frozen=True)
class OnionProfile:
    """Observable properties collected from an onion service."""
    address: str                           # .onion address
    tls_cert_sans: list[str] = field(default_factory=list)
    tls_cert_fingerprint: str | None = None
    favicon_hash: str | None = None        # md5 of favicon.ico
    server_banner: str | None = None       # Server header value
    http_headers: dict[str, str] = field(default_factory=dict)
    header_order: list[str] = field(default_factory=list)
    ssh_host_key: str | None = None
    error_page_hash: str | None = None     # md5 of 404 page
    status_page_text: str | None = None


@dataclass(frozen=True)
class ClearnetHost:
    """Known properties of a clearnet host for comparison."""
    host: str                              # domain or IP
    tls_cert_sans: list[str] = field(default_factory=list)
    tls_cert_fingerprint: str | None = None
    favicon_hash: str | None = None
    server_banner: str | None = None
    http_headers: dict[str, str] = field(default_factory=dict)
    header_order: list[str] = field(default_factory=list)
    ssh_host_key: str | None = None
    error_page_hash: str | None = None


# ── Detector protocol ────────────────────────────────────────

class Detector(ABC):
    """Base class for infrastructure correlation detectors."""

    detector_id: str
    kind: str
    description: str

    @abstractmethod
    def detect(
        self,
        onion: OnionProfile,
        clearnet_hosts: list[ClearnetHost],
    ) -> list[InfraCorrelation]:
        """Run detection against all clearnet hosts."""
        ...


# ── D1: TLS Certificate SAN Detector ────────────────────────

class CertSANDetector(Detector):
    """
    D1: Checks if a .onion site's TLS certificate contains a clearnet
    domain in its Subject Alternative Names.

    This is a HIGH confidence finding — it's a direct misconfiguration
    that reveals the operator's clearnet domain.
    """

    detector_id = "D1"
    kind = "cert_san"
    description = "TLS certificate names a clearnet domain in SAN"

    def detect(
        self,
        onion: OnionProfile,
        clearnet_hosts: list[ClearnetHost],
    ) -> list[InfraCorrelation]:
        results: list[InfraCorrelation] = []

        if not onion.tls_cert_sans:
            return results

        clearnet_domains = {h.host.lower() for h in clearnet_hosts}

        for san in onion.tls_cert_sans:
            san_lower = san.lower()
            # Direct domain match
            if san_lower in clearnet_domains:
                results.append(InfraCorrelation(
                    detector_id=self.detector_id,
                    onion_address=onion.address,
                    clearnet_match=san_lower,
                    kind=self.kind,
                    confidence=0.95,
                    raw_evidence={"san": san, "cert_fp": onion.tls_cert_fingerprint},
                    description=f"Onion TLS cert includes clearnet domain '{san}' in SAN",
                ))

            # Wildcard match
            if san_lower.startswith("*."):
                base = san_lower[2:]
                for domain in clearnet_domains:
                    if domain.endswith(base):
                        results.append(InfraCorrelation(
                            detector_id=self.detector_id,
                            onion_address=onion.address,
                            clearnet_match=domain,
                            kind=self.kind,
                            confidence=0.90,
                            raw_evidence={"san_wildcard": san, "matched": domain},
                            description=f"Wildcard SAN '*.{base}' matches '{domain}'",
                        ))

        return results


# ── D2: Favicon Hash Detector ────────────────────────────────

class FaviconDetector(Detector):
    """
    D2: Compares favicon.ico hashes between onion and clearnet hosts.

    Operators often forget to change/remove the favicon, which
    provides a fingerprint linkable to their clearnet presence.
    """

    detector_id = "D2"
    kind = "favicon"
    description = "Same favicon hash on onion and clearnet"

    def detect(
        self,
        onion: OnionProfile,
        clearnet_hosts: list[ClearnetHost],
    ) -> list[InfraCorrelation]:
        results: list[InfraCorrelation] = []

        if not onion.favicon_hash:
            return results

        for host in clearnet_hosts:
            if host.favicon_hash and host.favicon_hash == onion.favicon_hash:
                results.append(InfraCorrelation(
                    detector_id=self.detector_id,
                    onion_address=onion.address,
                    clearnet_match=host.host,
                    kind=self.kind,
                    confidence=0.70,
                    raw_evidence={"hash": onion.favicon_hash},
                    description=f"Favicon hash {onion.favicon_hash[:12]}... matches {host.host}",
                ))

        return results


# ── D3: Server Banner Detector ───────────────────────────────

class BannerDetector(Detector):
    """
    D3: Compares Server header and HTTP banner fingerprints.

    Custom or unusual server banners can identify specific installations.
    """

    detector_id = "D3"
    kind = "banner"
    description = "Same server banner on onion and clearnet"

    # Common banners that are too generic to be useful
    NOISE_BANNERS = frozenset({
        "nginx", "apache", "cloudflare", "microsoft-iis",
        "nginx/1.18.0", "apache/2.4.41",
    })

    def detect(
        self,
        onion: OnionProfile,
        clearnet_hosts: list[ClearnetHost],
    ) -> list[InfraCorrelation]:
        results: list[InfraCorrelation] = []

        if not onion.server_banner:
            return results

        banner_lower = onion.server_banner.lower().strip()
        if banner_lower in self.NOISE_BANNERS:
            return results

        for host in clearnet_hosts:
            if host.server_banner and host.server_banner.lower().strip() == banner_lower:
                results.append(InfraCorrelation(
                    detector_id=self.detector_id,
                    onion_address=onion.address,
                    clearnet_match=host.host,
                    kind=self.kind,
                    confidence=0.45,
                    raw_evidence={"banner": onion.server_banner},
                    description=f"Same server banner: '{onion.server_banner}'",
                ))

        return results


# ── D4: Server Status Page Detector ──────────────────────────

class StatusPageDetector(Detector):
    """
    D4: Checks for default status pages that reveal server identity.

    Some servers expose /server-status, /status, or custom health
    endpoints that contain identifying information.
    """

    detector_id = "D4"
    kind = "server_status"
    description = "Status page reveals clearnet identity"

    # Patterns that indicate identity leakage
    IDENTITY_PATTERNS = [
        re.compile(r"ServerName:\s*(\S+)", re.IGNORECASE),
        re.compile(r"hostname[\"']?\s*[:=]\s*[\"']?(\S+)", re.IGNORECASE),
        re.compile(r"server_name\s+(\S+);"),  # nginx config leak
    ]

    def detect(
        self,
        onion: OnionProfile,
        clearnet_hosts: list[ClearnetHost],
    ) -> list[InfraCorrelation]:
        results: list[InfraCorrelation] = []

        if not onion.status_page_text:
            return results

        clearnet_domains = {h.host.lower() for h in clearnet_hosts}

        for pattern in self.IDENTITY_PATTERNS:
            for match in pattern.finditer(onion.status_page_text):
                leaked_host = match.group(1).lower()
                if leaked_host in clearnet_domains:
                    results.append(InfraCorrelation(
                        detector_id=self.detector_id,
                        onion_address=onion.address,
                        clearnet_match=leaked_host,
                        kind=self.kind,
                        confidence=0.85,
                        raw_evidence={"pattern": pattern.pattern, "leaked": leaked_host},
                        description=f"Status page leaks hostname '{leaked_host}'",
                    ))

        return results


# ── D5: SSH Host Key Detector ────────────────────────────────

class SSHKeyDetector(Detector):
    """
    D5: Compares SSH host key fingerprints.

    If the same SSH host key is used on both onion and clearnet,
    this is a VERY HIGH confidence match (keys are unique).
    """

    detector_id = "D5"
    kind = "ssh_key"
    description = "Same SSH host key on onion and clearnet"

    def detect(
        self,
        onion: OnionProfile,
        clearnet_hosts: list[ClearnetHost],
    ) -> list[InfraCorrelation]:
        results: list[InfraCorrelation] = []

        if not onion.ssh_host_key:
            return results

        for host in clearnet_hosts:
            if host.ssh_host_key and host.ssh_host_key == onion.ssh_host_key:
                results.append(InfraCorrelation(
                    detector_id=self.detector_id,
                    onion_address=onion.address,
                    clearnet_match=host.host,
                    kind=self.kind,
                    confidence=0.98,
                    raw_evidence={"key_fingerprint": onion.ssh_host_key[:32]},
                    description=f"SSH host key match with {host.host}",
                ))

        return results


# ── D6: HTTP Header Order Detector ───────────────────────────

class HeaderOrderDetector(Detector):
    """
    D6: Compares HTTP response header ordering.

    The order of HTTP headers is server-implementation-specific
    and can fingerprint specific software configurations.
    """

    detector_id = "D6"
    kind = "header_order"
    description = "Same HTTP header ordering on onion and clearnet"

    MIN_HEADERS = 4  # need enough headers to be meaningful

    def detect(
        self,
        onion: OnionProfile,
        clearnet_hosts: list[ClearnetHost],
    ) -> list[InfraCorrelation]:
        results: list[InfraCorrelation] = []

        if len(onion.header_order) < self.MIN_HEADERS:
            return results

        for host in clearnet_hosts:
            if len(host.header_order) < self.MIN_HEADERS:
                continue

            # Normalize header names
            onion_order = [h.lower() for h in onion.header_order]
            host_order = [h.lower() for h in host.header_order]

            if onion_order == host_order:
                results.append(InfraCorrelation(
                    detector_id=self.detector_id,
                    onion_address=onion.address,
                    clearnet_match=host.host,
                    kind=self.kind,
                    confidence=0.40,
                    raw_evidence={
                        "header_count": len(onion_order),
                        "headers": onion_order,
                    },
                    description=f"Identical header ordering ({len(onion_order)} headers)",
                ))

        return results


# ── D7: Custom Error Page Detector ───────────────────────────

class ErrorPageDetector(Detector):
    """
    D7: Compares hash of custom error pages (404, 403, etc.).

    Custom error pages are often unique to a specific deployment
    and serve as a fingerprint.
    """

    detector_id = "D7"
    kind = "error_page"
    description = "Same custom error page on onion and clearnet"

    def detect(
        self,
        onion: OnionProfile,
        clearnet_hosts: list[ClearnetHost],
    ) -> list[InfraCorrelation]:
        results: list[InfraCorrelation] = []

        if not onion.error_page_hash:
            return results

        for host in clearnet_hosts:
            if host.error_page_hash and host.error_page_hash == onion.error_page_hash:
                results.append(InfraCorrelation(
                    detector_id=self.detector_id,
                    onion_address=onion.address,
                    clearnet_match=host.host,
                    kind=self.kind,
                    confidence=0.55,
                    raw_evidence={"hash": onion.error_page_hash},
                    description=f"Error page hash matches {host.host}",
                ))

        return results


# ── Utility: hash content ────────────────────────────────────

def hash_content(content: bytes) -> str:
    """MD5 hash for favicon/error page fingerprinting."""
    return hashlib.md5(content).hexdigest()


# ── Detector registry ───────────────────────────────────────

ALL_DETECTORS: list[Detector] = [
    CertSANDetector(),
    FaviconDetector(),
    BannerDetector(),
    StatusPageDetector(),
    SSHKeyDetector(),
    HeaderOrderDetector(),
    ErrorPageDetector(),
]


def run_all_detectors(
    onion: OnionProfile,
    clearnet_hosts: list[ClearnetHost],
) -> list[InfraCorrelation]:
    """
    Run all infrastructure correlation detectors.

    Returns findings sorted by confidence (highest first).
    """
    results: list[InfraCorrelation] = []
    for detector in ALL_DETECTORS:
        try:
            findings = detector.detect(onion, clearnet_hosts)
            results.extend(findings)
        except Exception as exc:
            logger.error(
                "Detector %s failed: %s",
                detector.detector_id, exc,
            )

    # Sort by confidence descending
    results.sort(key=lambda r: r.confidence, reverse=True)

    if results:
        logger.info(
            "Infrastructure scan for %s: %d findings (top: %s @ %.2f)",
            onion.address[:16], len(results),
            results[0].kind, results[0].confidence,
        )

    return results
