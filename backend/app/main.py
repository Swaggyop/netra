"""
NETRA — FastAPI application entry point.

Security middleware stack (OWASP Top 10):
  A01 → RBAC via JWT (deps.py)
  A02 → TLS in production, SecretStr for all secrets
  A03 → Pydantic validation, parameterised queries, HTML sanitisation
  A04 → Policy gate + safety gate before collection
  A05 → Security headers, CORS, rate limiting
  A06 → pip-audit in CI
  A07 → JWT auth with refresh, bcrypt, account lockout
  A08 → Merkle batch provenance
  A09 → Audit log for all sensitive operations
  A10 → SSRF protection in URL validation, Tor isolation
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from backend.app.config import get_settings

# ── Structured logging ───────────────────────────────────────

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer() if not get_settings().is_production
        else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        logging.getLevelName(get_settings().log_level),
    ),
)

logger = structlog.get_logger()


# ── Rate limiter (OWASP A05) ────────────────────────────────

settings = get_settings()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{settings.rate_limit_per_minute}/minute"],
)


# ── Lifespan (startup / shutdown) ────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialise and tear down backing services."""
    logger.info("Starting NETRA", env=settings.app_env)

    # Postgres
    from backend.app.models.base import init_db
    init_db(settings.database_url)
    logger.info("PostgreSQL initialised")

    # Neo4j
    from backend.app.graph.schema import init_neo4j
    await init_neo4j()
    logger.info("Neo4j initialised")

    # Event bus
    from backend.app.api.deps import get_event_bus
    await get_event_bus()
    logger.info("Event bus initialised", bus=settings.event_bus)

    # MinIO — ensure bucket exists
    try:
        import urllib3
        from minio import Minio
        http_client = urllib3.PoolManager(
            timeout=urllib3.Timeout(connect=0.5, read=0.5),
            retries=False,
        )
        minio_client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key.get_secret_value(),
            secure=settings.minio_secure,
            http_client=http_client,
        )
        if not minio_client.bucket_exists(settings.minio_bucket):
            minio_client.make_bucket(settings.minio_bucket)
            logger.info("MinIO bucket created", bucket=settings.minio_bucket)
    except Exception as exc:
        logger.warning("MinIO init failed (non-fatal)", error=str(exc))

    logger.info("NETRA ready", env=settings.app_env)
    yield

    # Shutdown
    from backend.app.graph.schema import close_neo4j
    await close_neo4j()
    logger.info("NETRA shutdown complete")


# ── Application ──────────────────────────────────────────────

app = FastAPI(
    title="NETRA",
    description="Networked Evidence & Threat-actor Relationship Analyzer",
    version="0.1.0",
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    lifespan=lifespan,
)

# Attach rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── Security middleware stack ────────────────────────────────

# 1. Trusted hosts (OWASP A05)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.allowed_hosts,
)

# 2. CORS (OWASP A05)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
    max_age=600,
)


# 3. Security headers (OWASP A05)
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next) -> Response:
    """Add security headers to every response."""
    response: Response = await call_next(request)

    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # XSS protection (legacy but still useful)
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Prevent MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Referrer policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Content Security Policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    # HSTS (only in production behind TLS)
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    # Permissions policy
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=()"
    )
    # Remove server header
    if "server" in response.headers:
        del response.headers["server"]

    return response


# 4. Request size limiter (OWASP A05 — prevent large payload DoS)
@app.middleware("http")
async def request_size_limiter(request: Request, call_next) -> Response:
    """Reject requests exceeding the configured max size."""
    content_length = request.headers.get("content-length")
    max_bytes = settings.max_request_size_mb * 1024 * 1024

    if content_length and int(content_length) > max_bytes:
        return Response(
            content='{"detail": "Request too large"}',
            status_code=413,
            media_type="application/json",
        )

    return await call_next(request)


# 5. Request ID for tracing
@app.middleware("http")
async def request_id_middleware(request: Request, call_next) -> Response:
    """Attach a unique request ID for log correlation."""
    import uuid
    request_id = str(uuid.uuid4())
    structlog.contextvars.bind_contextvars(request_id=request_id)
    response: Response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    structlog.contextvars.unbind_contextvars("request_id")
    return response


# ── Register routers ────────────────────────────────────────

from backend.app.api.health import router as health_router
from backend.app.api.auth import router as auth_router
from backend.app.api.actors import router as actors_router
from backend.app.api.sources import router as sources_router
from backend.app.api.exports import export_router
from backend.app.api.routes import (
    search_router,
    alerts_router,
    provenance_router,
    timeline_router,
    infra_router,
    watchlist_router,
)
from backend.app.api.pipeline import pipeline_router
from backend.app.api.websocket import ws_router

# Health — no auth, root and api prefix
app.include_router(health_router)
app.include_router(health_router, prefix="/api/v1")

# All API routes under /api/v1
API_PREFIX = "/api/v1"
app.include_router(auth_router, prefix=API_PREFIX)
app.include_router(actors_router, prefix=API_PREFIX)
app.include_router(sources_router, prefix=API_PREFIX)
app.include_router(search_router, prefix=API_PREFIX)
app.include_router(alerts_router, prefix=API_PREFIX)
app.include_router(export_router, prefix=API_PREFIX)
app.include_router(provenance_router, prefix=API_PREFIX)
app.include_router(timeline_router, prefix=API_PREFIX)
app.include_router(infra_router, prefix=API_PREFIX)
app.include_router(watchlist_router, prefix=API_PREFIX)
app.include_router(pipeline_router, prefix=API_PREFIX)

# WebSocket — no API prefix (ws://host/ws/feed)
app.include_router(ws_router)

