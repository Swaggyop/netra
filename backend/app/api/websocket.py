"""
NETRA — WebSocket live feed.

Provides real-time event streaming to connected clients:
  1. New events as they're processed
  2. Alert notifications (rebrand detected, new ransomware group, etc.)
  3. Pipeline status updates
  4. Source health status changes

Uses FastAPI WebSocket with Redis pub/sub for horizontal scaling.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

ws_router = APIRouter(tags=["websocket"])


# ── Connection manager ──────────────────────────────────────

class ConnectionManager:
    """
    Manages active WebSocket connections.

    Supports:
      - Broadcasting to all connected clients
      - Channel-based subscriptions (events, alerts, status)
      - Connection lifecycle management
    """

    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = {
            "events": set(),
            "alerts": set(),
            "status": set(),
            "all": set(),
        }

    async def connect(self, websocket: WebSocket, channels: list[str]) -> None:
        """Accept a WebSocket and register it to specified channels."""
        await websocket.accept()
        for channel in channels:
            if channel in self._connections:
                self._connections[channel].add(websocket)
        self._connections["all"].add(websocket)
        logger.info("WebSocket connected: channels=%s", channels)

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket from all channels."""
        for channel_sockets in self._connections.values():
            channel_sockets.discard(websocket)
        logger.info("WebSocket disconnected")

    async def broadcast(self, channel: str, message: dict[str, Any]) -> None:
        """Send a message to all connections on a channel."""
        sockets = self._connections.get(channel, set()).copy()
        dead: list[WebSocket] = []

        payload = json.dumps(message, default=str)

        for ws in sockets:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        # Clean up dead connections
        for ws in dead:
            self.disconnect(ws)

    @property
    def connection_count(self) -> int:
        """Number of unique active connections."""
        return len(self._connections["all"])


# Global manager instance
manager = ConnectionManager()


_ticker_task: asyncio.Task | None = None
_redis_listener_task: asyncio.Task | None = None


async def _redis_feed_listener() -> None:
    """
    Listen to the Redis 'netra:live_feed' pub/sub channel and forward
    real collection events to all WebSocket clients.

    This replaces the old fake SAMPLE_EVENTS ticker with real data.
    """
    import redis.asyncio as aioredis
    from backend.app.config import get_settings

    settings = get_settings()
    while True:
        try:
            r = aioredis.from_url(settings.redis_url, socket_connect_timeout=5)
            pubsub = r.pubsub()
            await pubsub.subscribe("netra:live_feed")
            logger.info("Redis live feed listener started")

            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                try:
                    data = json.loads(message["data"])
                    if manager.connection_count > 0:
                        await manager.broadcast("events", data)
                except (json.JSONDecodeError, KeyError):
                    continue

        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning("Redis feed listener error: %s, retrying in 5s", exc)
            await asyncio.sleep(5)


async def _fallback_ticker() -> None:
    """
    Fallback: poll Redis recent_events list every 10s and push new items.
    Also sends a heartbeat so clients know the connection is alive.
    """
    import redis.asyncio as aioredis
    from backend.app.config import get_settings

    settings = get_settings()
    last_seen_count = 0

    while True:
        try:
            await asyncio.sleep(10)
            if manager.connection_count == 0:
                continue

            try:
                r = aioredis.from_url(settings.redis_url, socket_timeout=2)
                current_len = await r.llen("netra:recent_events")

                if current_len > last_seen_count and last_seen_count > 0:
                    # New events arrived — fetch the new ones
                    new_count = current_len - last_seen_count
                    raw_events = await r.lrange("netra:recent_events", 0, new_count - 1)
                    for raw in raw_events:
                        try:
                            data = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
                            await manager.broadcast("events", data)
                        except (json.JSONDecodeError, AttributeError):
                            continue

                last_seen_count = current_len
                await r.aclose()

            except Exception:
                # Send heartbeat so client knows connection is alive
                await manager.broadcast("all", {
                    "channel": "status",
                    "type": "heartbeat",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "connections": manager.connection_count,
                })

        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning("Fallback ticker error: %s", exc)
            await asyncio.sleep(10)


def ensure_ticker_started() -> None:
    global _ticker_task, _redis_listener_task
    if _redis_listener_task is None or _redis_listener_task.done():
        try:
            loop = asyncio.get_running_loop()
            _redis_listener_task = loop.create_task(_redis_feed_listener())
        except RuntimeError:
            pass
    if _ticker_task is None or _ticker_task.done():
        try:
            loop = asyncio.get_running_loop()
            _ticker_task = loop.create_task(_fallback_ticker())
        except RuntimeError:
            pass


# ── WebSocket endpoint ──────────────────────────────────────

@ws_router.websocket("/ws/feed")
async def live_feed(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for real-time event feed.

    Client can send subscription messages:
      {"subscribe": ["events", "alerts", "status"]} or {"action": "subscribe", "channel": "events"}

    Server sends:
      {"channel": "events", "type": "new_event", "data": {...}}
      {"channel": "alerts", "type": "rebrand_detected", "data": {...}}
      {"channel": "status", "type": "source_health", "data": {...}}
    """
    # Default to all channels
    channels = ["events", "alerts", "status"]

    await manager.connect(websocket, channels)
    ensure_ticker_started()

    try:
        # Send connection acknowledgment
        await websocket.send_json({
            "type": "connected",
            "channels": channels,
            "server_time": datetime.now(UTC).isoformat(),
        })

        # Send initial batch of recent events from Redis so dashboard immediately shows real data
        try:
            import redis.asyncio as aioredis
            from backend.app.config import get_settings
            settings = get_settings()
            r = aioredis.from_url(settings.redis_url, socket_timeout=2)
            raw_events = await r.lrange("netra:recent_events", 0, 9)
            await r.aclose()
            for raw in raw_events:
                try:
                    data = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
                    await websocket.send_json(data)
                except (json.JSONDecodeError, AttributeError):
                    continue
        except Exception:
            pass  # No cached events yet — that's fine

        while True:
            try:
                # Listen for client messages (subscription changes, heartbeat)
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0,  # Send heartbeat if no client message in 30s
                )

                msg = json.loads(data)

                # Handle subscription changes
                if "subscribe" in msg:
                    sub = msg["subscribe"]
                    new_channels = sub if isinstance(sub, list) else [sub]
                    manager.disconnect(websocket)
                    await manager.connect(websocket, new_channels)
                    await websocket.send_json({
                        "type": "subscribed",
                        "channels": new_channels,
                    })
                elif msg.get("action") == "subscribe" and "channel" in msg:
                    ch = msg["channel"]
                    if ch in manager._connections:
                        manager._connections[ch].add(websocket)
                    await websocket.send_json({
                        "type": "subscribed",
                        "channel": ch,
                    })

                # Handle heartbeat
                elif msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})

            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_json({
                    "type": "heartbeat",
                    "server_time": datetime.now(UTC).isoformat(),
                    "connections": manager.connection_count,
                })

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as exc:
        logger.error("WebSocket error: %s", exc)
        manager.disconnect(websocket)


# ── Broadcast helpers (called from pipeline/workers) ────────

async def broadcast_new_event(event_data: dict[str, Any]) -> None:
    """Broadcast a new processed event to all connected clients."""
    source_name = event_data.get("source") or event_data.get("source_id", "pipeline_collector")
    await manager.broadcast("events", {
        "channel": "events",
        "type": "new_event",
        "timestamp": datetime.now(UTC).isoformat(),
        "data": {
            "event_id": event_data.get("event_id", ""),
            "source": source_name,
            "source_id": source_name,
            "entities_found": event_data.get("entities_found", 1),
            "entity_kinds": event_data.get("entity_kinds", ["ioc"]),
            "timestamp": datetime.now(UTC).isoformat(),
        },
    })


async def broadcast_alert(
    alert_type: str,
    title: str,
    details: dict[str, Any],
    severity: str = "medium",
) -> None:
    """Broadcast an alert to all connected clients."""
    await manager.broadcast("alerts", {
        "channel": "alerts",
        "type": alert_type,
        "timestamp": datetime.now(UTC).isoformat(),
        "data": {
            "title": title,
            "severity": severity,
            "details": details,
        },
    })


async def broadcast_source_status(
    source_id: str,
    status: str,
    last_success: str | None = None,
    error: str | None = None,
) -> None:
    """Broadcast source health status change."""
    await manager.broadcast("status", {
        "channel": "status",
        "type": "source_health",
        "timestamp": datetime.now(UTC).isoformat(),
        "data": {
            "source_id": source_id,
            "status": status,
            "last_success": last_success,
            "error": error,
        },
    })
