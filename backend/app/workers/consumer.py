"""
NETRA — Event bus consumer (§7 pipeline glue).

Listens to the event bus for new events from adapters and triggers
the full processing pipeline:
  1. Consume event from netra.events.raw topic
  2. Process through pipeline (safety → redact → extract → resolve → graph)
  3. Trigger downstream analytics (wallet clustering, clock-skew, etc.)
  4. Trigger on-demand lookups for newly discovered entities

This runs as a persistent Celery worker, NOT in the API request path.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


async def start_event_consumer() -> None:
    """
    Start the persistent event bus consumer.

    Listens to RAW_EVENTS topic and processes each event through
    the full pipeline.
    """
    from backend.app.core.events import Topics, create_event_bus

    bus = create_event_bus()
    await bus.start()

    logger.info("Event consumer started, listening on %s", Topics.RAW_EVENTS.value)

    try:
        async for event in bus.subscribe(
            Topics.RAW_EVENTS.value,
            group="pipeline-workers",
        ):
            try:
                await process_and_dispatch(event)
            except Exception as exc:
                logger.error(
                    "Consumer error for event %s: %s",
                    getattr(event, "event_id", "?")[:8],
                    exc,
                    exc_info=True,
                )
    finally:
        await bus.stop()


async def process_and_dispatch(event: Any) -> None:
    """
    Process a single event and dispatch downstream tasks.

    This is the central coordination point:
    1. Run the main pipeline (extract, resolve, graph write)
    2. Check extracted entities for on-demand lookups
    3. Trigger wallet clustering if new wallets found
    4. Trigger clock-skew correlation if new probe data
    """
    from backend.app.core.pipeline import process_raw_event

    event_data = event.model_dump(mode="json")
    event_id = event_data.get("event_id", "")
    source_id = event_data.get("source_id", "")
    metadata = event_data.get("raw_metadata", {})

    logger.info("Processing event %s from %s", event_id[:8], source_id)

    # Run main pipeline
    result = await process_raw_event(event_data)

    if result.get("status") != "completed":
        logger.debug(
            "Event %s pipeline result: %s",
            event_id[:8], result.get("status"),
        )
        return

    # Dispatch downstream tasks based on extracted entities
    entity_kinds = set(result.get("entity_kinds", []))

    # If we found wallet addresses, trigger blockchain lookup
    if "wallet" in entity_kinds:
        _dispatch_blockchain_lookup(metadata)

    # If we found onion URLs, trigger probe
    if "onion" in entity_kinds:
        _dispatch_onion_probe(metadata)

    # If we found IPs, trigger GreyNoise lookup
    if "ip" in entity_kinds:
        _dispatch_ip_reputation(metadata)

    # If this is a probe result with clock-skew data, update correlator
    event_type = metadata.get("type", "")
    if event_type == "onion_probe" and metadata.get("clock_skew_seconds") is not None:
        _dispatch_clock_skew_update(metadata)

    logger.info(
        "Event %s dispatched: %d entities, %s",
        event_id[:8],
        result.get("entities_found", 0),
        ", ".join(entity_kinds) if entity_kinds else "none",
    )


def _dispatch_blockchain_lookup(metadata: dict[str, Any]) -> None:
    """Queue blockchain lookups for newly discovered wallet addresses."""
    try:
        from backend.app.workers.celery_app import collect_blockchain_for_addresses

        # Extract wallet addresses from metadata
        entities = metadata.get("entities", {})
        addresses: dict[str, list[str]] = {}

        btc = entities.get("btc_addresses", [])
        if btc:
            addresses["btc"] = btc[:5]  # Cap to avoid rate limits

        eth = entities.get("eth_addresses", [])
        if eth:
            addresses["eth"] = eth[:5]

        if addresses:
            collect_blockchain_for_addresses.delay(addresses)
            logger.info("Dispatched blockchain lookup for %d chains", len(addresses))

    except Exception as exc:
        logger.error("Failed to dispatch blockchain lookup: %s", exc)


def _dispatch_onion_probe(metadata: dict[str, Any]) -> None:
    """Queue probes for newly discovered .onion URLs."""
    try:
        from backend.app.workers.celery_app import probe_specific_urls

        entities = metadata.get("entities", {})
        onion_urls = entities.get("onion_urls", [])

        if onion_urls:
            probe_specific_urls.delay(onion_urls[:10])
            logger.info("Dispatched probe for %d new onion URLs", min(len(onion_urls), 10))

    except Exception as exc:
        logger.error("Failed to dispatch onion probe: %s", exc)


def _dispatch_ip_reputation(metadata: dict[str, Any]) -> None:
    """Queue GreyNoise lookups for newly discovered IPs."""
    try:
        from backend.app.workers.celery_app import collect_greynoise_for_ips

        entities = metadata.get("entities", {})
        relay_ips = entities.get("relay_ips", [])

        # Also look for IPs in raw metadata
        ips = metadata.get("ips", []) or relay_ips
        if ips:
            collect_greynoise_for_ips.delay(ips[:20])
            logger.info("Dispatched GreyNoise lookup for %d IPs", min(len(ips), 20))

    except Exception as exc:
        logger.error("Failed to dispatch IP reputation: %s", exc)


def _dispatch_clock_skew_update(metadata: dict[str, Any]) -> None:
    """Update the clock-skew correlator with new probe measurements."""
    try:
        url = metadata.get("url", "")
        skew = metadata.get("clock_skew_seconds")
        if url and skew is not None:
            # In production, persist to Redis/DB for the correlator
            logger.info("Clock-skew measurement: %s → %.3fs", url[:40], skew)

    except Exception as exc:
        logger.error("Failed to update clock-skew: %s", exc)
