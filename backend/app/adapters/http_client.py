"""
NETRA — Shared async HTTP client for live adapters.

Provides:
  - Rate-limit-aware request throttling (per-source)
  - Automatic retry with exponential backoff
  - Tor SOCKS5 proxy support for .onion requests
  - Source health tracking (last success/failure, rate-limit remaining)
  - Request size limits (OWASP A05)

All live adapters use this instead of raw httpx/aiohttp.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from backend.app.config import get_settings

logger = logging.getLogger(__name__)


# ── Source health tracking ───────────────────────────────────

@dataclass
class SourceHealth:
    """Tracks health metrics for a data source."""
    source_id: str
    last_success: datetime | None = None
    last_failure: datetime | None = None
    last_error: str | None = None
    consecutive_failures: int = 0
    consecutive_429s: int = 0
    total_requests: int = 0
    total_successes: int = 0
    total_failures: int = 0
    rate_limit_remaining: int | None = None
    rate_limit_reset: datetime | None = None

    def record_success(self) -> None:
        self.last_success = datetime.now(UTC)
        self.consecutive_failures = 0
        self.consecutive_429s = 0
        self.total_requests += 1
        self.total_successes += 1

    def record_failure(self, error: str, is_rate_limit: bool = False) -> None:
        self.last_failure = datetime.now(UTC)
        self.last_error = error
        self.consecutive_failures += 1
        self.total_requests += 1
        self.total_failures += 1
        if is_rate_limit:
            self.consecutive_429s += 1

    @property
    def is_healthy(self) -> bool:
        return self.consecutive_failures < 5

    @property
    def backoff_seconds(self) -> float:
        """Exponential backoff based on consecutive failures."""
        if self.consecutive_429s > 0:
            return min(2 ** self.consecutive_429s * 60, 3600)
        if self.consecutive_failures > 0:
            return min(2 ** self.consecutive_failures * 10, 600)
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "last_failure": self.last_failure.isoformat() if self.last_failure else None,
            "last_error": self.last_error,
            "consecutive_failures": self.consecutive_failures,
            "consecutive_429s": self.consecutive_429s,
            "total_requests": self.total_requests,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "rate_limit_remaining": self.rate_limit_remaining,
            "is_healthy": self.is_healthy,
        }


# ── Rate limiter (token bucket) ─────────────────────────────

class TokenBucketLimiter:
    """
    Simple token-bucket rate limiter.

    Each source gets its own limiter with a configured rate.
    Blocks (async) when the bucket is empty.
    """

    def __init__(self, rate: float, burst: int) -> None:
        """
        Args:
            rate: Tokens per second.
            burst: Maximum burst size.
        """
        self._rate = rate
        self._burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available, then consume one."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            self._last_refill = now

            if self._tokens < 1:
                wait_time = (1 - self._tokens) / self._rate
                await asyncio.sleep(wait_time)
                self._tokens = 0
            else:
                self._tokens -= 1


# ── Default rate limits per source ───────────────────────────

DEFAULT_RATE_LIMITS: dict[str, tuple[float, int]] = {
    # (tokens_per_second, burst)
    "ransomware_live":  (0.5, 2),     # ~30/min, cache is 30min anyway
    "ransomlook":       (1.0, 5),     # fair use
    "ransomwatch":      (0.1, 1),     # GitHub CDN, poll rarely
    "urlhaus":          (1.0, 5),     # fair use
    "threatfox":        (1.0, 5),     # fair use
    "malwarebazaar":    (1.0, 5),     # fair use
    "feodo":            (0.1, 1),     # static feed, poll rarely
    "mempool":          (2.0, 10),    # generous but avoid 429
    "etherscan":        (5.0, 5),     # 5/sec on free tier
    "blockchair":       (0.5, 2),     # free tier limited
    "crt_sh":           (0.2, 2),     # fair use, slow
    "certstream":       (100, 100),   # websocket, no limit
    "shodan_idb":       (100, 100),   # 10K/sec officially
    "onionoo":          (0.5, 3),     # fair use
    "greynoise":        (0.5, 2),     # community tier
    "otx":              (1.0, 5),     # fair use
    "default":          (1.0, 5),
}

# ── Shared HTTP client ──────────────────────────────────────

_health_registry: dict[str, SourceHealth] = {}
_rate_limiters: dict[str, TokenBucketLimiter] = {}


def get_health(source_id: str) -> SourceHealth:
    """Get or create health tracker for a source."""
    if source_id not in _health_registry:
        _health_registry[source_id] = SourceHealth(source_id=source_id)
    return _health_registry[source_id]


def get_all_health() -> dict[str, dict[str, Any]]:
    """Get health status for all tracked sources."""
    return {sid: h.to_dict() for sid, h in _health_registry.items()}


def _get_limiter(source_id: str) -> TokenBucketLimiter:
    """Get or create rate limiter for a source."""
    if source_id not in _rate_limiters:
        rate, burst = DEFAULT_RATE_LIMITS.get(source_id, DEFAULT_RATE_LIMITS["default"])
        _rate_limiters[source_id] = TokenBucketLimiter(rate, burst)
    return _rate_limiters[source_id]


class LiveHTTPClient:
    """
    Async HTTP client for live data adapters.

    Features:
      - Per-source rate limiting
      - Automatic retry with exponential backoff
      - Tor SOCKS5 proxy for .onion URLs
      - Response size limits
      - Source health tracking
    """

    MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB

    def __init__(self, source_id: str, *, use_tor: bool = False) -> None:
        self.source_id = source_id
        self._use_tor = use_tor
        self._health = get_health(source_id)
        self._limiter = _get_limiter(source_id)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> LiveHTTPClient:
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.stop()

    async def start(self) -> None:
        """Initialize the HTTP client."""
        settings = get_settings()
        transport_kwargs: dict[str, Any] = {
            "retries": 0,  # we handle retries ourselves
        }

        if self._use_tor:
            # Route through Tor SOCKS5 proxy
            proxy_url = settings.tor_socks_proxy
            transport = httpx.AsyncHTTPTransport(proxy=proxy_url, **transport_kwargs)
        else:
            transport = httpx.AsyncHTTPTransport(**transport_kwargs)

        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=True,
            limits=httpx.Limits(
                max_connections=10,
                max_keepalive_connections=5,
            ),
            headers={
                "User-Agent": "NETRA/0.1.0 (Threat Intelligence Research)",
                "Accept": "application/json",
                "Accept-Encoding": "gzip",
            },
        )

    async def stop(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        max_retries: int = 3,
    ) -> httpx.Response:
        """
        GET request with rate limiting, retries, and health tracking.

        Raises httpx.HTTPStatusError on non-retryable errors.
        """
        return await self._request("GET", url, headers=headers, params=params, max_retries=max_retries)

    async def post(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        max_retries: int = 3,
    ) -> httpx.Response:
        """
        POST request with rate limiting, retries, and health tracking.

        Raises httpx.HTTPStatusError on non-retryable errors.
        """
        return await self._request("POST", url, headers=headers, json=json, data=data, max_retries=max_retries)

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        max_retries: int = 3,
    ) -> httpx.Response:
        """Execute a request with rate limiting, retries, and health tracking."""
        if not self._client:
            raise RuntimeError(f"HTTP client for {self.source_id} not started. Call start() first.")

        # Check backoff
        if self._health.backoff_seconds > 0 and self._health.last_failure:
            elapsed = (datetime.now(UTC) - self._health.last_failure).total_seconds()
            remaining = self._health.backoff_seconds - elapsed
            if remaining > 0:
                logger.warning(
                    "Source %s in backoff, waiting %.1fs",
                    self.source_id, remaining,
                )
                await asyncio.sleep(min(remaining, 60))

        last_error: Exception | None = None
        for attempt in range(max_retries):
            # Rate limit
            await self._limiter.acquire()

            try:
                response = await self._client.request(
                    method, url,
                    headers=headers,
                    params=params,
                    json=json,
                    data=data,
                )

                # Parse rate-limit headers if present
                self._parse_rate_limit_headers(response)

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    self._health.record_failure("rate_limited", is_rate_limit=True)
                    logger.warning(
                        "Rate limited by %s, retry after %ds (attempt %d/%d)",
                        self.source_id, retry_after, attempt + 1, max_retries,
                    )
                    await asyncio.sleep(retry_after)
                    continue

                if response.status_code >= 500:
                    self._health.record_failure(f"server_error_{response.status_code}")
                    wait = min(2 ** attempt * 5, 60)
                    logger.warning(
                        "Server error %d from %s, retrying in %ds",
                        response.status_code, self.source_id, wait,
                    )
                    await asyncio.sleep(wait)
                    continue

                # Check response size
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > self.MAX_RESPONSE_SIZE:
                    self._health.record_failure("response_too_large")
                    raise ValueError(
                        f"Response from {self.source_id} exceeds {self.MAX_RESPONSE_SIZE} bytes"
                    )

                response.raise_for_status()
                self._health.record_success()
                return response

            except httpx.TimeoutException as e:
                last_error = e
                self._health.record_failure(f"timeout: {e}")
                wait = min(2 ** attempt * 5, 60)
                logger.warning(
                    "Timeout from %s (attempt %d/%d), retrying in %ds",
                    self.source_id, attempt + 1, max_retries, wait,
                )
                await asyncio.sleep(wait)

            except httpx.ConnectError as e:
                last_error = e
                self._health.record_failure(f"connect_error: {e}")
                wait = min(2 ** attempt * 10, 120)
                logger.warning(
                    "Connection error to %s (attempt %d/%d), retrying in %ds",
                    self.source_id, attempt + 1, max_retries, wait,
                )
                await asyncio.sleep(wait)

            except httpx.HTTPStatusError:
                # Non-retryable HTTP error (4xx except 429)
                raise

        # All retries exhausted
        if last_error:
            raise last_error
        raise httpx.ConnectError(f"All {max_retries} attempts failed for {self.source_id}")

    def _parse_rate_limit_headers(self, response: httpx.Response) -> None:
        """Extract rate-limit info from common header patterns."""
        for header in ("X-RateLimit-Remaining", "X-Rate-Limit-Remaining", "RateLimit-Remaining"):
            val = response.headers.get(header)
            if val is not None:
                try:
                    self._health.rate_limit_remaining = int(val)
                except ValueError:
                    pass
                break

        for header in ("X-RateLimit-Reset", "X-Rate-Limit-Reset", "RateLimit-Reset"):
            val = response.headers.get(header)
            if val is not None:
                try:
                    self._health.rate_limit_reset = datetime.fromtimestamp(int(val), tz=UTC)
                except (ValueError, OSError):
                    pass
                break

    @property
    def health(self) -> SourceHealth:
        return self._health
