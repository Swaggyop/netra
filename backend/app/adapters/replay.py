"""
NETRA — Replay engine (§13).

Reads generated (or approved archived) data and publishes events
to the event bus with original timestamps at configurable speed.

Usage:
    python -m backend.app.adapters.replay --speed 100 --data datagen/output
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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

logger = logging.getLogger(__name__)


async def replay(
    data_dir: str = "datagen/output",
    speed: float = 1.0,
    source_id: str = "src_synthetic",
) -> dict[str, int]:
    """
    Replay synthetic posts as events through the pipeline.

    Args:
        data_dir: Path to the datagen output directory.
        speed: Replay speed multiplier (1 = realtime, 100 = 100× faster).
        source_id: Source ID to tag events with.

    Returns:
        Summary dict with event counts.
    """
    data_path = Path(data_dir)

    # Load posts
    posts_file = data_path / "posts.json"
    if not posts_file.exists():
        raise FileNotFoundError(f"Posts file not found: {posts_file}")

    with open(posts_file) as f:
        posts: list[dict[str, Any]] = json.load(f)

    # Sort by posted_at for chronological replay
    posts.sort(key=lambda p: p["posted_at"])

    logger.info(
        "Replay starting: %d posts at %sx speed from %s",
        len(posts), speed, data_dir,
    )

    # Initialise event bus
    bus = create_event_bus()
    await bus.start()

    published = 0
    skipped = 0
    prev_ts: datetime | None = None

    try:
        for post in posts:
            posted_at = datetime.fromisoformat(post["posted_at"])

            # Simulate time gaps between events (scaled by speed)
            if prev_ts and speed < float("inf"):
                gap = (posted_at - prev_ts).total_seconds()
                if gap > 0:
                    await asyncio.sleep(gap / speed)
            prev_ts = posted_at

            # Redact PII
            redaction_result = redact_pii(post["text"])

            # Hash content
            content_bytes = redaction_result.redacted_text.encode("utf-8")
            content_hash = compute_content_hash(content_bytes)

            # Create event
            event = RawEvent(
                source_id=source_id,
                adapter_type=AdapterType.REPLAY,
                mode=CollectionMode.REPLAY,
                observed_at=posted_at,
                content_type=ContentType.TEXT,
                payload_ref=f"s3://netra-snapshots/replay/{post['post_id']}.txt",
                content_hash=content_hash,
                policy_decision_id="replay-auto-allow",
                language=post.get("language", "en"),
                raw_metadata={
                    "handle": post.get("handle"),
                    "market": post.get("market"),
                    "actor_id": post.get("actor_id"),
                    "post_id": post["post_id"],
                },
                redactions=redaction_result.redactions,
            )

            # Publish
            offset = await bus.publish(Topics.RAW_EVENTS.value, event)
            published += 1

            if published % 50 == 0:
                logger.info(
                    "Replay progress: %d/%d events published (offset: %s)",
                    published, len(posts), offset,
                )

    except KeyboardInterrupt:
        logger.info("Replay interrupted by user")
    finally:
        await bus.stop()

    summary = {
        "total_posts": len(posts),
        "published": published,
        "skipped": skipped,
        "speed": speed,
        "source_id": source_id,
    }
    logger.info("Replay complete: %s", summary)
    return summary


# ── CLI entry point ──────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="NETRA replay engine")
    parser.add_argument("--data", type=str, default="datagen/output", help="Data directory")
    parser.add_argument("--speed", type=float, default=100.0, help="Replay speed (1=realtime, 100=fast)")
    parser.add_argument("--source", type=str, default="src_synthetic", help="Source ID")
    args = parser.parse_args()

    asyncio.run(replay(data_dir=args.data, speed=args.speed, source_id=args.source))


if __name__ == "__main__":
    main()
