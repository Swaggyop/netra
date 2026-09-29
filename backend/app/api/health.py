"""
NETRA — Health check endpoints.

Verifies connectivity to all backing services.
Unauthenticated so load balancers and monitoring can hit it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict[str, Any]:
    """
    Aggregate health check for all backing services.

    Returns 200 even if some services are degraded —
    the response body contains per-service status.
    """
    results: dict[str, str] = {}

    # PostgreSQL
    try:
        from sqlalchemy import text
        from backend.app.models.base import get_session_factory
        factory = get_session_factory()
        async with factory() as session:
            await session.execute(text("SELECT 1"))
        results["postgres"] = "healthy"
    except Exception as exc:
        results["postgres"] = f"unhealthy: {exc}"

    # Neo4j
    try:
        from backend.app.graph.schema import get_driver
        driver = get_driver()
        async with driver.session() as session:
            await session.run("RETURN 1")
        results["neo4j"] = "healthy"
    except Exception as exc:
        results["neo4j"] = f"unhealthy: {exc}"

    # Redis
    try:
        import redis.asyncio as aioredis
        from backend.app.config import get_settings
        r = aioredis.from_url(get_settings().redis_url)
        await r.ping()
        await r.aclose()
        results["redis"] = "healthy"
    except Exception as exc:
        results["redis"] = f"unhealthy: {exc}"

    # Redpanda
    try:
        from backend.app.config import get_settings
        settings = get_settings()
        if settings.event_bus == "redpanda":
            from aiokafka import AIOKafkaProducer
            producer = AIOKafkaProducer(bootstrap_servers=settings.redpanda_brokers)
            await producer.start()
            await producer.stop()
            results["redpanda"] = "healthy"
        else:
            results["redpanda"] = "skipped (using redis event bus)"
    except Exception as exc:
        results["redpanda"] = f"unhealthy: {exc}"

    # MinIO
    try:
        import urllib3
        from minio import Minio
        from backend.app.config import get_settings
        settings = get_settings()
        http_client = urllib3.PoolManager(
            timeout=urllib3.Timeout(connect=0.5, read=0.5),
            retries=False,
        )
        client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key.get_secret_value(),
            secure=settings.minio_secure,
            http_client=http_client,
        )
        client.list_buckets()
        results["minio"] = "healthy"
    except Exception as exc:
        results["minio"] = f"unhealthy (optional): {exc}"

    overall = "healthy" if all(
        v == "healthy" or v.startswith("skipped") for v in results.values()
    ) else "degraded"

    return {
        "status": overall,
        "timestamp": datetime.now(UTC).isoformat(),
        "services": results,
    }


@router.get("/health/sources")
async def source_health() -> list[dict[str, Any]]:
    """
    Health status for all live data source adapters.

    Merges adapter HTTP health checks with actual collection run data
    stored in Redis by Celery workers.
    """
    import json
    import redis.asyncio as aioredis
    from backend.app.config import get_settings
    from backend.app.adapters.http_client import (
        DEFAULT_RATE_LIMITS,
        get_all_health,
        get_health,
    )

    for src in DEFAULT_RATE_LIMITS:
        if src != "default":
            get_health(src)

    source_statuses = get_all_health()

    # Read real collection run data from Redis
    collection_runs: dict[str, dict[str, Any]] = {}
    try:
        settings = get_settings()
        r = aioredis.from_url(settings.redis_url, socket_timeout=2)
        raw_runs = await r.hgetall("netra:collection_runs")
        await r.aclose()
        for key, val in raw_runs.items():
            source_name = key.decode() if isinstance(key, bytes) else key
            data = json.loads(val.decode() if isinstance(val, bytes) else val)
            collection_runs[source_name] = data
            # Also map sub-sources (e.g., ransomware → ransomware_live, ransomlook)
            for sub in data.get("sub_sources", []):
                # Strip 'src_' prefix if present
                clean = sub.replace("src_", "")
                collection_runs[clean] = data
    except Exception:
        pass

    # Build final source list — map collection data to each source
    # Source group mapping for sub-source lookup
    GROUP_MAP = {
        "ransomware_live": "ransomware", "ransomlook": "ransomware", "ransomwatch": "ransomware",
        "urlhaus": "abuse_ch", "threatfox": "abuse_ch", "malwarebazaar": "abuse_ch", "feodo": "abuse_ch",
        "onionoo": "tor_network",
        "crt_sh": "cert_transparency",
        "mempool": "blockchain", "etherscan": "blockchain", "blockchair": "blockchain",
        "greynoise": "osint_feeds", "shodan_idb": "osint_feeds",
    }

    results: list[dict[str, Any]] = []
    for sid, s in source_statuses.items():
        status = "online"
        if not s.get("is_healthy", True):
            status = "offline"
        elif s.get("consecutive_failures", 0) > 0:
            status = "degraded"

        # Look up collection run data — check direct name, then group
        run = collection_runs.get(sid) or collection_runs.get(GROUP_MAP.get(sid, ""))
        last_success = s.get("last_success")
        events_24h = s.get("total_successes", 0)

        if run:
            last_success = run.get("completed_at") or last_success
            events_24h = max(events_24h, run.get("total_items", 0))

        results.append({
            "name": sid,
            "status": status,
            "last_success": last_success,
            "error": s.get("last_error"),
            "events_24h": events_24h,
            "next_run": None,
        })

    return results

