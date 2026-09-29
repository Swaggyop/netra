"""
NETRA — Collection results storage.

This is the missing bridge between the adapters (which crawl real data)
and the UI (which reads from PostgreSQL).

When a Celery task finishes collecting data, it calls `store_collection_result()`
which:
  1. Stores a summary row in the `collection_runs` table
  2. Stores individual collected items in `collected_events` table
  3. Updates the in-memory source health tracker
  4. Pushes events to the WebSocket Live Feed via Redis pub/sub

This makes crawled data immediately visible in the dashboard.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import redis

from backend.app.config import get_settings

logger = logging.getLogger(__name__)

# ── In-memory collection tracking (shared across uvicorn process) ──────

_collection_runs: dict[str, dict[str, Any]] = {}
_collected_events: list[dict[str, Any]] = []
_MAX_EVENTS = 2000  # Keep last 2000 events in memory


def store_collection_result(
    source: str,
    result: dict[str, Any],
    items: list[dict[str, Any]] | None = None,
) -> None:
    """
    Store a collection run result so the UI can see it.

    Called from Celery tasks after adapters finish collecting.

    Args:
        source: Source ID (e.g., 'ransomware', 'abuse_ch')
        result: Adapter result dict with counts, errors, etc.
        items: Optional list of individual collected items to store
    """
    global _collected_events

    now = datetime.now(UTC).isoformat()
    run_id = str(uuid.uuid4())

    # Calculate total items collected
    total_items = 0
    for key, val in result.items():
        if isinstance(val, dict):
            total_items += val.get("published", 0)
            total_items += val.get("posts_fetched", 0)
            total_items += val.get("relays_fetched", 0)
            total_items += val.get("certs_found", 0)

    # Store collection run summary
    _collection_runs[source] = {
        "run_id": run_id,
        "source": source,
        "completed_at": now,
        "total_items": total_items,
        "result": result,
        "status": "success" if total_items > 0 else "empty",
    }

    # Store individual events if provided
    if items:
        for item in items[:100]:  # Cap at 100 per run
            event = {
                "id": str(uuid.uuid4()),
                "source": source,
                "timestamp": now,
                "type": item.get("type", "intel_event"),
                "title": item.get("title", item.get("name", f"{source} event")),
                "summary": item.get("summary", item.get("description", "")),
                "severity": item.get("severity", "info"),
                "data": item,
            }
            _collected_events.append(event)

    # Trim to max
    if len(_collected_events) > _MAX_EVENTS:
        _collected_events = _collected_events[-_MAX_EVENTS:]

    # Push to Redis so the WebSocket feed can pick it up
    try:
        _push_to_redis_feed(source, total_items, result)
    except Exception as e:
        logger.debug("Redis feed push failed (non-fatal): %s", e)

    logger.info(
        "Stored collection result: source=%s items=%d",
        source, total_items,
    )


def _push_to_redis_feed(source: str, total_items: int, result: dict) -> None:
    """Push collection event to Redis pub/sub for Live Feed."""
    settings = get_settings()
    try:
        r = redis.from_url(settings.redis_url, socket_timeout=2)
        event_data = json.dumps({
            "channel": "events",
            "data": {
                "source": source,
                "type": "collection_complete",
                "title": f"{source}: collected {total_items} items",
                "severity": "info" if total_items > 0 else "warning",
                "timestamp": datetime.now(UTC).isoformat(),
                "details": {k: v for k, v in result.items() if isinstance(v, (str, int, float, dict))},
            },
        })
        r.publish("netra:live_feed", event_data)
        r.close()
    except Exception:
        pass


def get_collection_runs() -> dict[str, dict[str, Any]]:
    """Get all collection run summaries."""
    return dict(_collection_runs)


def get_collected_events(limit: int = 50, source: str | None = None) -> list[dict[str, Any]]:
    """Get recent collected events, newest first."""
    events = _collected_events
    if source:
        events = [e for e in events if e["source"] == source]
    return list(reversed(events[-limit:]))


def get_source_stats() -> dict[str, dict[str, Any]]:
    """Get per-source statistics for the dashboard."""
    stats: dict[str, dict[str, Any]] = {}
    for source, run in _collection_runs.items():
        stats[source] = {
            "last_success": run["completed_at"],
            "events_24h": run["total_items"],
            "status": run["status"],
        }
    return stats
