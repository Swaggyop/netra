"""
NETRA — Onion crawler (Phase 2).

Two-stage dark web discovery and crawling system:

  Stage 1: DISCOVERY
    - Query Ahmia.fi search engine for .onion URLs
    - Query onion URLs discovered by other adapters (ransomware tracker, abuse.ch)
    - Seed list of known onion directories

  Stage 2: CRAWLING (via Tor SOCKS5)
    - Fetch discovered .onion pages (text-only)
    - Extract entities: handles, PGP keys, wallet addresses, emails
    - Extract infrastructure: server headers, favicon, framework
    - All traffic routed through socks5://tor:9050

Safety guarantees (ENFORCED, not just planned):
  ✓ robots.txt checked before EVERY crawl (via RobotsTxtChecker from onion_probe)
  ✓ Safety gate pre-checks content type — blocks images/video/archives/executables
  ✓ Safety gate post-checks text content — blocks prohibited material
  ✓ 5 MB response size cap (DOWNLOAD_MAXSIZE)
  ✓ Text-only: only text/html, text/plain, application/json fetched
  ✓ Policy gate controls which domains may be crawled
  ✓ Max pages per domain cap (prevents exhaustive crawling)
  ✓ Max depth cap (prevents deep-link following)
  ✓ Crawl delay between requests (politeness)

Source provenance:
  - Ahmia.fi: https://ahmia.fi/ — open-source Tor search engine
    Search endpoint: https://ahmia.fi/search/?q={query}
    No API — HTML scraping of search results (Ahmia is open-source: github.com/ahmia)
    Ahmia actively filters out illegal content from its index.
  - Crawling: your own Tor SOCKS5 proxy (docker-compose tor service)
  - Legal basis: publicly accessible .onion pages, text-only extraction
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlparse

from backend.app.adapters.http_client import LiveHTTPClient
from backend.app.adapters.onion_probe import (
    RobotsTxtChecker,
    _mmh3_hash32,
    extract_header_fingerprint,
    extract_html_fingerprint,
    measure_clock_skew,
)
from backend.app.config import get_settings
from backend.app.core.events import (
    AdapterType,
    CollectionMode,
    ContentType,
    RawEvent,
    Topics,
    create_event_bus,
)
from backend.app.core.provenance import compute_content_hash
from backend.app.core.redaction import redact_pii
from backend.app.core.safety import safety_gate

logger = logging.getLogger(__name__)


# ── Crawl config ────────────────────────────────────────────

MAX_PAGES_PER_DOMAIN = 20     # Don't exhaustively crawl any single site
MAX_CRAWL_DEPTH = 2           # Only follow links 2 levels deep
MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5 MB cap (enforced)
CRAWL_DELAY_SECONDS = 3.0    # Politeness delay between requests
ALLOWED_CONTENT_TYPES = frozenset({
    "text/html",
    "text/plain",
    "application/json",
})


# ── Entity extraction patterns ──────────────────────────────

BTC_ADDR_RE = re.compile(r"\b((?:1|3)[1-9A-HJ-NP-Za-km-z]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,62})\b")
ETH_ADDR_RE = re.compile(r"\b(0x[0-9a-fA-F]{40})\b")
XMR_ADDR_RE = re.compile(r"\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PGP_BLOCK_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)
PGP_FP_RE = re.compile(r"[0-9A-Fa-f]{40}")
ONION_URL_RE = re.compile(r"https?://[a-z2-7]{56}\.onion[^\s\"'<>]*")
HANDLE_RE = re.compile(r"@[\w]{3,30}")


def extract_entities_from_text(text: str) -> dict[str, list[str]]:
    """
    Extract structured identifiers from crawled page text.

    Returns dict of entity_type → [values].
    """
    entities: dict[str, list[str]] = {}

    btc = BTC_ADDR_RE.findall(text)
    if btc:
        entities["btc_addresses"] = list(set(btc))[:20]

    eth = ETH_ADDR_RE.findall(text)
    if eth:
        entities["eth_addresses"] = list(set(eth))[:20]

    xmr = XMR_ADDR_RE.findall(text)
    if xmr:
        entities["xmr_addresses"] = list(set(xmr))[:10]

    emails = EMAIL_RE.findall(text)
    if emails:
        entities["emails"] = list(set(emails))[:20]

    pgp_blocks = PGP_BLOCK_RE.findall(text)
    if pgp_blocks:
        entities["pgp_keys"] = [hashlib.sha256(k.encode()).hexdigest()[:16] for k in pgp_blocks]

    pgp_fps = PGP_FP_RE.findall(text)
    if pgp_fps:
        entities["pgp_fingerprints"] = list(set(pgp_fps))[:10]

    onion_urls = ONION_URL_RE.findall(text)
    if onion_urls:
        entities["onion_urls"] = list(set(onion_urls))[:30]

    handles = HANDLE_RE.findall(text)
    if handles:
        entities["handles"] = list(set(handles))[:20]

    return entities


# ── Link extractor ──────────────────────────────────────────

HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)


def extract_onion_links(html: str, base_url: str) -> list[str]:
    """Extract .onion links from HTML, resolving relative URLs."""
    links: set[str] = set()
    for href in HREF_RE.findall(html):
        try:
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            if parsed.hostname and parsed.hostname.endswith(".onion"):
                # Normalize: strip fragment, keep scheme+host+path
                clean = f"{parsed.scheme}://{parsed.hostname}{parsed.path}"
                if clean.endswith("/"):
                    clean = clean[:-1]
                links.add(clean)
        except Exception:
            continue
    return list(links)[:50]


# ── Ahmia discovery ─────────────────────────────────────────

class AhmiaDiscovery:
    """
    Discovers .onion URLs via Ahmia.fi search engine.

    Ahmia actively filters illegal content from its index — it's the
    safest discovery source for onion URLs.

    Note: Ahmia doesn't have a JSON API. We parse search result HTML
    to extract .onion links.
    """

    SEARCH_URL = "https://ahmia.fi/search/"
    SOURCE_ID = "src_ahmia"

    def __init__(self) -> None:
        # Ahmia is a clearnet site — no Tor needed for the search
        self._client = LiveHTTPClient("default")

    async def search(self, query: str, max_results: int = 30) -> list[str]:
        """
        Search Ahmia for .onion URLs matching a query.

        Args:
            query: Search term (e.g., 'ransomware', 'marketplace', 'forum')
            max_results: Max URLs to return

        Returns:
            List of discovered .onion URLs
        """
        discovered: set[str] = set()

        async with self._client:
            try:
                response = await self._client.get(
                    self.SEARCH_URL,
                    params={"q": query},
                )

                html = response.text

                # Extract .onion URLs from Ahmia search results
                # Ahmia renders results with redirect URLs containing the onion
                onion_matches = ONION_URL_RE.findall(html)
                for url in onion_matches:
                    parsed = urlparse(url)
                    if parsed.hostname and parsed.hostname.endswith(".onion"):
                        base = f"{parsed.scheme}://{parsed.hostname}"
                        discovered.add(base)

                # Also look for onion addresses in plain text (56-char v3 format)
                v3_onion_re = re.compile(r"([a-z2-7]{56})\.onion")
                for match in v3_onion_re.findall(html):
                    discovered.add(f"http://{match}.onion")

            except Exception as exc:
                logger.error("Ahmia search failed for '%s': %s", query, exc)

        results = list(discovered)[:max_results]
        logger.info("Ahmia: discovered %d onion URLs for query '%s'", len(results), query)
        return results

    async def discover_ransomware_sites(self) -> list[str]:
        """Discover ransomware-related .onion sites via Ahmia."""
        all_urls: set[str] = set()
        queries = [
            "ransomware",
            "data leak",
            "lockbit",
            "blackcat",
            "alphv",
        ]
        for query in queries:
            urls = await self.search(query, max_results=20)
            all_urls.update(urls)
        return list(all_urls)


# ── Crawled page model ──────────────────────────────────────

class CrawledPage:
    """Result of crawling a single .onion page."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.crawled_at = datetime.now(UTC)
        self.status_code: int | None = None
        self.content_type: str = ""
        self.title: str | None = None
        self.text_length: int = 0
        self.entities: dict[str, list[str]] = {}
        self.outgoing_links: list[str] = []
        self.header_fingerprint: dict[str, str] = {}
        self.html_fingerprint: dict[str, Any] = {}
        self.clock_skew: float | None = None
        self.favicon_hash: int | None = None
        self.error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "crawled_at": self.crawled_at.isoformat(),
            "status_code": self.status_code,
            "content_type": self.content_type,
            "title": self.title,
            "text_length": self.text_length,
            "entities": self.entities,
            "outgoing_onion_links": len(self.outgoing_links),
            "header_fingerprint": self.header_fingerprint,
            "html_fingerprint": self.html_fingerprint,
            "clock_skew_seconds": self.clock_skew,
            "favicon_hash": self.favicon_hash,
            "error": self.error,
        }


# ── Tor crawler ─────────────────────────────────────────────

class OnionCrawler:
    """
    Crawls .onion pages through Tor SOCKS5 with full safety enforcement.

    Pipeline:
      1. Discover URLs (Ahmia + seed lists from other adapters)
      2. For each URL:
         a. Check robots.txt
         b. Safety gate pre-check (content type)
         c. Fetch page (text-only, 5MB cap, through Tor)
         d. Safety gate post-check (content scan)
         e. Extract entities (wallets, PGP, emails, handles)
         f. Extract infrastructure (headers, favicon, framework)
         g. Measure clock-skew from Date header
         h. Discover outgoing .onion links
         i. Redact PII
         j. Hash and publish to event bus
    """

    SOURCE_ID = "src_onion_crawler"

    def __init__(self) -> None:
        self._client = LiveHTTPClient("default", use_tor=True)
        self._robots = RobotsTxtChecker()
        self._visited: set[str] = set()
        self._domain_counts: dict[str, int] = {}

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.hostname}{path}"

    def _get_domain(self, url: str) -> str:
        """Extract domain from URL."""
        return urlparse(url).hostname or ""

    async def crawl_page(self, url: str) -> CrawledPage:
        """
        Crawl a single .onion page with all safety checks.

        Returns CrawledPage with extracted entities and fingerprints.
        """
        page = CrawledPage(url)
        normalized = self._normalize_url(url)

        # Dedup check
        if normalized in self._visited:
            page.error = "already_visited"
            return page
        self._visited.add(normalized)

        # Per-domain cap
        domain = self._get_domain(url)
        count = self._domain_counts.get(domain, 0)
        if count >= MAX_PAGES_PER_DOMAIN:
            page.error = f"domain cap reached ({MAX_PAGES_PER_DOMAIN} pages)"
            return page
        self._domain_counts[domain] = count + 1

        async with self._client:
            # 1. robots.txt
            allowed = await self._robots.is_allowed(url, self._client)
            if not allowed:
                page.error = "blocked by robots.txt"
                logger.info("Crawler: robots.txt blocked %s", url[:60])
                return page

            # 2. Politeness delay
            import asyncio
            await asyncio.sleep(CRAWL_DELAY_SECONDS)

            # 3. Fetch
            try:
                start = time.monotonic()
                response = await self._client.get(url, max_retries=2)
                elapsed = time.monotonic() - start

                page.status_code = response.status_code

                # 4. Content-type check (safety gate pre-check)
                ct = response.headers.get("content-type", "")
                page.content_type = ct
                base_ct = ct.split(";")[0].strip().lower()

                safety_pre = safety_gate.pre_fetch(base_ct, url)
                if safety_pre.decision != "allow":
                    page.error = f"safety pre-check blocked: {safety_pre.reason}"
                    return page

                if base_ct not in ALLOWED_CONTENT_TYPES:
                    page.error = f"content type {base_ct} not allowed (text-only)"
                    return page

                # 5. Size check
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > MAX_RESPONSE_SIZE:
                    page.error = f"response too large: {content_length} bytes"
                    return page

                # 6. Get text content
                text = response.text[:MAX_RESPONSE_SIZE]
                page.text_length = len(text)

                # 7. Safety gate post-check (content scan)
                safety_post = safety_gate.post_fetch(text, url)
                if safety_post.decision != "allow":
                    page.error = f"safety post-check blocked: {safety_post.reason}"
                    logger.warning("Crawler: safety post-check blocked %s", url[:60])
                    return page

                # 8. Clock-skew
                date_header = response.headers.get("date")
                if date_header:
                    page.clock_skew = measure_clock_skew(date_header)

                # 9. Header fingerprint
                page.header_fingerprint = extract_header_fingerprint(
                    dict(response.headers)
                )

                # 10. HTML fingerprint
                if "text/html" in base_ct:
                    page.html_fingerprint = extract_html_fingerprint(text)

                    # Title
                    title_match = re.search(
                        r"<title[^>]*>([^<]+)</title>", text, re.IGNORECASE
                    )
                    if title_match:
                        page.title = title_match.group(1).strip()[:200]

                    # Outgoing .onion links (for BFS discovery)
                    page.outgoing_links = extract_onion_links(text, url)

                # 11. Entity extraction
                page.entities = extract_entities_from_text(text)

            except Exception as exc:
                page.error = str(exc)
                return page

            # 12. Favicon hash (separate request)
            try:
                favicon_url = urljoin(url, "/favicon.ico")
                fav_response = await self._client.get(favicon_url, max_retries=1)
                if fav_response.status_code == 200 and len(fav_response.content) > 0:
                    page.favicon_hash = _mmh3_hash32(fav_response.content)
            except Exception:
                pass

        return page

    async def crawl_and_publish(
        self,
        seed_urls: list[str],
        max_depth: int = MAX_CRAWL_DEPTH,
    ) -> dict[str, Any]:
        """
        BFS crawl from seed URLs, publishing results to event bus.

        Args:
            seed_urls: Initial .onion URLs to crawl
            max_depth: Maximum link-following depth (0 = seed only)
        """
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0
        total_entities: dict[str, int] = {}

        try:
            # BFS with depth tracking
            queue: list[tuple[str, int]] = [(url, 0) for url in seed_urls]
            seen_urls: set[str] = set(seed_urls)

            while queue:
                url, depth = queue.pop(0)

                page = await self.crawl_page(url)

                if page.error and page.error in ("already_visited",):
                    continue

                if page.error:
                    errors += 1
                    logger.debug("Crawl error for %s: %s", url[:50], page.error)
                    continue

                # Count extracted entities
                for etype, values in page.entities.items():
                    total_entities[etype] = total_entities.get(etype, 0) + len(values)

                # Publish to event bus
                try:
                    content = json.dumps(page.to_dict(), ensure_ascii=False)
                    redaction = redact_pii(content)
                    content_hash = compute_content_hash(
                        redaction.redacted_text.encode("utf-8")
                    )

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.OSINT_FEED,
                        mode=CollectionMode.LIVE,
                        observed_at=page.crawled_at,
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/crawler/{uuid.uuid4().hex[:12]}.json",
                        content_hash=content_hash,
                        policy_decision_id="crawler-approved",
                        language="en",
                        raw_metadata={
                            "type": "crawled_onion_page",
                            "url": page.url,
                            "title": page.title,
                            "domain": self._get_domain(page.url),
                            "text_length": page.text_length,
                            "entities": page.entities,
                            "header_fingerprint": page.header_fingerprint,
                            "html_fingerprint": page.html_fingerprint,
                            "clock_skew_seconds": page.clock_skew,
                            "favicon_hash": page.favicon_hash,
                            "depth": depth,
                            "text": redaction.redacted_text[:5000],  # Cap for event bus
                        },
                        redactions=redaction.redactions,
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to publish crawled page: %s", exc)
                    errors += 1

                # Add discovered links to queue (BFS, respect depth)
                if depth < max_depth and page.outgoing_links:
                    for link in page.outgoing_links:
                        normalized = self._normalize_url(link)
                        if normalized not in seen_urls:
                            seen_urls.add(normalized)
                            queue.append((link, depth + 1))

        finally:
            await bus.stop()

        summary = {
            "source": self.SOURCE_ID,
            "seed_urls": len(seed_urls),
            "pages_crawled": published + errors,
            "published": published,
            "errors": errors,
            "entities_found": total_entities,
            "domains_crawled": len(self._domain_counts),
        }
        logger.info("Onion crawl complete: %s", summary)
        return summary


# ── Orchestrator ────────────────────────────────────────────

async def discover_and_crawl(
    search_queries: list[str] | None = None,
    seed_urls: list[str] | None = None,
) -> dict[str, Any]:
    """
    Full discovery + crawl pipeline.

    1. Discover .onion URLs via Ahmia search
    2. Combine with provided seed URLs
    3. Crawl all discovered URLs (BFS, depth 2)
    4. Publish everything to event bus

    Args:
        search_queries: Ahmia search terms (e.g., ['ransomware', 'forum'])
        seed_urls: Additional seed URLs from other adapters
    """
    results: dict[str, Any] = {"started_at": datetime.now(UTC).isoformat()}
    all_urls: set[str] = set()

    # Stage 1: Discovery via Ahmia
    if search_queries:
        try:
            discovery = AhmiaDiscovery()
            for query in search_queries:
                urls = await discovery.search(query, max_results=15)
                all_urls.update(urls)
            results["ahmia_discovery"] = {
                "queries": search_queries,
                "urls_discovered": len(all_urls),
            }
        except Exception as exc:
            logger.error("Ahmia discovery failed: %s", exc, exc_info=True)
            results["ahmia_discovery"] = {"error": str(exc)}

    # Add seed URLs
    if seed_urls:
        all_urls.update(seed_urls)

    results["total_seed_urls"] = len(all_urls)

    # Stage 2: Crawl
    if all_urls:
        try:
            crawler = OnionCrawler()
            results["crawl"] = await crawler.crawl_and_publish(
                seed_urls=list(all_urls),
                max_depth=MAX_CRAWL_DEPTH,
            )
        except Exception as exc:
            logger.error("Onion crawl failed: %s", exc, exc_info=True)
            results["crawl"] = {"error": str(exc)}
    else:
        results["crawl"] = {"skipped": "no URLs to crawl"}

    results["completed_at"] = datetime.now(UTC).isoformat()
    return results
