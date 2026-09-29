"""
NETRA — Celery application and task definitions.

All heavy work (collection, extraction, analysis, exports) runs here,
not in the FastAPI request path (hard rule 7).

Live adapter tasks:
  - collect_ransomware_intel   — ransomware.live + ransomlook.io + Ransomwatch
  - collect_abuse_ch_intel     — URLhaus + ThreatFox + MalwareBazaar + Feodo
  - collect_tor_intel          — Onionoo relay data + CISA advisories
  - collect_infra_intel        — crt.sh cert search + Shodan InternetDB
  - collect_blockchain_intel   — mempool.space + Etherscan (triggered by entity extraction)
"""

from __future__ import annotations

import asyncio
import logging

from celery import Celery
from celery.schedules import crontab

from backend.app.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

# ── Celery app ───────────────────────────────────────────────

celery_app = Celery(
    "netra",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    # Serialisation
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Security: limit task execution time (OWASP A05 — prevent resource exhaustion)
    task_time_limit=600,         # hard kill after 10 min
    task_soft_time_limit=540,    # soft timeout at 9 min (allows cleanup)

    # Worker stability
    worker_max_tasks_per_child=100,  # restart worker after 100 tasks (memory leak prevention)
    worker_prefetch_multiplier=1,    # don't over-prefetch

    # Result expiry
    result_expires=3600,  # 1 hour

    # Beat schedule — live adapter collection intervals
    beat_schedule={
        # ── Live data collection ─────────────────────────────

        # Ransomware intel: every 30 min (ransomware.live caches for 30min)
        "collect-ransomware-intel": {
            "task": "backend.app.workers.celery_app.collect_ransomware_intel_task",
            "schedule": crontab(minute="*/30"),
        },

        # abuse.ch feeds: every 15 min (high-velocity IOC feeds)
        "collect-abuse-ch-intel": {
            "task": "backend.app.workers.celery_app.collect_abuse_ch_intel_task",
            "schedule": crontab(minute="*/15"),
        },

        # Tor relay data: every 2 hours (relays don't change fast)
        "collect-tor-intel": {
            "task": "backend.app.workers.celery_app.collect_tor_intel_task",
            "schedule": crontab(minute=0, hour="*/2"),
        },

        # Cert transparency: every 6 hours (certs don't appear instantly)
        "collect-cert-intel": {
            "task": "backend.app.workers.celery_app.collect_cert_intel_task",
            "schedule": crontab(minute=0, hour="*/6"),
        },

        # CISA advisories: once daily at 8 AM UTC
        "collect-cisa-advisories": {
            "task": "backend.app.workers.celery_app.collect_cisa_task",
            "schedule": crontab(minute=0, hour=8),
        },

        # ── Phase 2: Onion probe + crawler ────────────────────

        # Onion probe: every 4 hours (check uptime, clock-skew, fingerprints)
        "probe-onion-services": {
            "task": "backend.app.workers.celery_app.probe_onion_services_task",
            "schedule": crontab(minute=30, hour="*/4"),
        },

        # Onion crawler: every 12 hours (Ahmia discovery + BFS crawl)
        "crawl-onion-sites": {
            "task": "backend.app.workers.celery_app.crawl_onion_sites_task",
            "schedule": crontab(minute=0, hour="*/12"),
        },

        # ── Phase 3: Additional sources ───────────────────────

        # OTX + SSLBL: every hour
        "collect-osint-feeds": {
            "task": "backend.app.workers.celery_app.collect_osint_feeds_task",
            "schedule": crontab(minute=15, hour="*/1"),
        },

        # SigmaHQ rules: daily at 6 AM (rules update infrequently)
        "collect-sigma-rules": {
            "task": "backend.app.workers.celery_app.collect_sigma_rules_task",
            "schedule": crontab(minute=0, hour=6),
        },

        # CertStream: every 4 hours (5-min listening window each time)
        "collect-certstream": {
            "task": "backend.app.workers.celery_app.collect_certstream_task",
            "schedule": crontab(minute=45, hour="*/4"),
        },

        # Tor exit node list: daily at 2 AM
        "collect-tor-exits": {
            "task": "backend.app.workers.celery_app.collect_tor_exits_task",
            "schedule": crontab(minute=0, hour=2),
        },

        # ── Pipeline maintenance ─────────────────────────────

        # Close any open Merkle batch
        "close-merkle-batch": {
            "task": "backend.app.workers.celery_app.close_merkle_batch",
            "schedule": crontab(minute="*/5"),
        },

        # Retention enforcement
        "enforce-retention": {
            "task": "backend.app.workers.celery_app.enforce_retention",
            "schedule": crontab(hour=3, minute=0),  # daily at 3 AM
        },
    },
)


# ── Helper to run async code in Celery (sync) tasks ─────────

def _run_async(coro):
    """Run an async coroutine in a sync Celery task context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Already in an event loop — create a new one
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def _store_result(source: str, result: dict) -> None:
    """
    Store collection result in Redis so the API server can read it.

    This bridges the gap between Celery workers (which collect data)
    and the FastAPI server (which serves the dashboard).

    Now tracks CUMULATIVE totals across multiple triggers.
    """
    import json
    from datetime import UTC, datetime

    try:
        import redis
        settings = get_settings()
        r = redis.from_url(settings.redis_url, socket_timeout=2)

        # Count total items collected in THIS run
        total_items = 0
        sub_sources = []
        for key, val in result.items():
            if isinstance(val, dict):
                total_items += val.get("published", 0)
                total_items += val.get("posts_fetched", 0)
                total_items += val.get("relays_fetched", 0)
                total_items += val.get("certs_found", 0)
                total_items += val.get("total_posts", 0)
                if val.get("source"):
                    sub_sources.append(val["source"])

        now = datetime.now(UTC).isoformat()

        # Read previous run count for this source
        prev_raw = r.hget("netra:collection_runs", source)
        prev_runs = 0
        prev_total = 0
        if prev_raw:
            try:
                prev = json.loads(prev_raw.decode() if isinstance(prev_raw, bytes) else prev_raw)
                prev_runs = prev.get("run_count", 0)
                prev_total = prev.get("cumulative_items", 0)
            except (json.JSONDecodeError, AttributeError):
                pass

        run_count = prev_runs + 1
        cumulative = prev_total + total_items

        # Store per-source run info with cumulative tracking
        run_data = json.dumps({
            "source": source,
            "completed_at": now,
            "total_items": total_items,
            "cumulative_items": cumulative,
            "run_count": run_count,
            "status": "success" if total_items > 0 else "empty",
            "sub_sources": sub_sources,
            "result_summary": {
                k: v for k, v in result.items()
                if isinstance(v, (str, int, float, dict))
            },
        })
        r.hset("netra:collection_runs", source, run_data)

        # Increment global events counter
        r.incrby("netra:total_events_collected", total_items)

        # Push to the live feed channel
        feed_event = json.dumps({
            "channel": "events",
            "data": {
                "source": source,
                "type": "collection_complete",
                "title": f"[OK] {source}: {total_items} items collected (run #{run_count})",
                "severity": "info",
                "timestamp": now,
                "entities_found": total_items,
            },
        })
        r.publish("netra:live_feed", feed_event)

        # Store in a Redis list for recent events (capped)
        r.lpush("netra:recent_events", feed_event)
        r.ltrim("netra:recent_events", 0, 499)  # Keep last 500

        # Store the actual result details so exports can access them
        detail_key = f"netra:collection_data:{source}"
        r.set(detail_key, json.dumps({
            "source": source,
            "collected_at": now,
            "run_count": run_count,
            "items_this_run": total_items,
            "result": {k: v for k, v in result.items() if isinstance(v, (str, int, float, dict, list))},
        }), ex=86400)  # TTL: 24 hours

        r.close()
        logger.info("Stored collection result for %s: %d items (run #%d, cumulative: %d)", source, total_items, run_count, cumulative)

    except Exception as e:
        logger.warning("Failed to store collection result in Redis: %s", e)


# ── Live adapter tasks ──────────────────────────────────────

@celery_app.task(bind=True, max_retries=2, default_retry_delay=120)
def collect_ransomware_intel_task(self) -> dict:
    """
    Collect from ransomware.live + ransomlook.io + Ransomwatch.

    Runs every 30 minutes via beat schedule.
    """
    logger.info("Starting ransomware intel collection")
    try:
        from backend.app.adapters.ransomware_tracker import collect_ransomware_intel
        result = _run_async(collect_ransomware_intel())
        _store_result("ransomware", result)
        logger.info("Ransomware intel collection complete: %s", result)
        return result
    except Exception as exc:
        logger.error("Ransomware intel collection failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=2, default_retry_delay=120)
def collect_abuse_ch_intel_task(self) -> dict:
    """
    Collect from abuse.ch (URLhaus + ThreatFox + MalwareBazaar + Feodo).

    Runs every 15 minutes via beat schedule.
    """
    logger.info("Starting abuse.ch intel collection")
    try:
        from backend.app.adapters.abuse_ch import collect_abuse_ch_intel
        result = _run_async(collect_abuse_ch_intel())
        _store_result("abuse_ch", result)
        logger.info("abuse.ch collection complete: %s", result)
        return result
    except Exception as exc:
        logger.error("abuse.ch collection failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=2, default_retry_delay=300)
def collect_tor_intel_task(self) -> dict:
    """
    Collect Tor relay data from Onionoo.

    Runs every 2 hours via beat schedule.
    """
    logger.info("Starting Tor network intel collection")
    try:
        from backend.app.adapters.tor_network import collect_tor_and_infra_intel
        result = _run_async(collect_tor_and_infra_intel())
        _store_result("tor_network", result)
        logger.info("Tor intel collection complete: %s", result)
        return result
    except Exception as exc:
        logger.error("Tor intel collection failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=1, default_retry_delay=600)
def collect_cert_intel_task(self) -> dict:
    """
    Search crt.sh for onion-related certificates.

    Runs every 6 hours via beat schedule.
    """
    logger.info("Starting cert transparency collection")
    try:
        from backend.app.adapters.cert_transparency import collect_infra_intel
        result = _run_async(collect_infra_intel())
        _store_result("cert_transparency", result)
        logger.info("Cert transparency collection complete: %s", result)
        return result
    except Exception as exc:
        logger.error("Cert transparency collection failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=1, default_retry_delay=3600)
def collect_cisa_task(self) -> dict:
    """
    Collect CISA KEV advisories (Admiralty grade A source).

    Runs once daily at 8 AM UTC.
    """
    logger.info("Starting CISA advisory collection")
    try:
        from backend.app.adapters.tor_network import CERTAdvisoryAdapter
        adapter = CERTAdvisoryAdapter()
        result = _run_async(adapter.collect_and_publish())
        logger.info("CISA advisory collection complete: %s", result)
        return result
    except Exception as exc:
        logger.error("CISA advisory collection failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=2)
def collect_blockchain_for_addresses(self, addresses: dict) -> dict:
    """
    Look up blockchain data for specific wallet addresses.

    Triggered on-demand when entity extraction finds new wallet addresses,
    NOT on a schedule.

    Args:
        addresses: {"btc": ["bc1q..."], "eth": ["0x..."]}
    """
    logger.info("Starting blockchain lookup for %d chains", len(addresses))
    try:
        from backend.app.adapters.blockchain import collect_blockchain_intel
        result = _run_async(collect_blockchain_intel(addresses))
        logger.info("Blockchain lookup complete: %s", result)
        return result
    except Exception as exc:
        logger.error("Blockchain lookup failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


# ── Phase 2: Onion probe + crawler tasks ────────────────────

@celery_app.task(bind=True, max_retries=1, default_retry_delay=600)
def probe_onion_services_task(self) -> dict:
    """
    Probe known .onion services for uptime, clock-skew, fingerprints.

    Runs every 4 hours via beat schedule.
    Gets target URLs from the entities table (onion URLs discovered by
    ransomware tracker, crawler, or abuse.ch feeds).
    """
    logger.info("Starting onion probe cycle")
    try:
        from backend.app.adapters.onion_probe import OnionProbeAdapter

        # In production, query DB for known onion URLs
        # For now, use onion URLs from ransomware tracker events
        # TODO: query entities table for onion_url type
        probe = OnionProbeAdapter()
        # Placeholder — real URLs come from entity extraction pipeline
        result = _run_async(probe.probe_and_publish([]))
        logger.info("Onion probe complete: %s", result)
        return result
    except Exception as exc:
        logger.error("Onion probe failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=1, default_retry_delay=1800,
                 time_limit=1800, soft_time_limit=1700)
def crawl_onion_sites_task(self) -> dict:
    """
    Discover + crawl .onion sites via Ahmia + Tor SOCKS5.

    Runs every 12 hours via beat schedule.
    Extended time limit (30 min) because crawling is slow through Tor.
    """
    logger.info("Starting onion discovery + crawl cycle")
    try:
        from backend.app.adapters.onion_crawler import discover_and_crawl

        result = _run_async(discover_and_crawl(
            search_queries=["ransomware", "data leak", "dark web forum"],
            seed_urls=None,  # In production, seed from entity extraction
        ))
        logger.info("Onion crawl complete: %s", result)
        return result
    except Exception as exc:
        logger.error("Onion crawl failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=1)
def probe_specific_urls(self, urls: list) -> dict:
    """
    Probe specific .onion URLs on-demand.

    Triggered when new onion URLs are discovered by the pipeline.
    """
    logger.info("Probing %d specific onion URLs", len(urls))
    try:
        from backend.app.adapters.onion_probe import OnionProbeAdapter
        probe = OnionProbeAdapter()
        result = _run_async(probe.probe_and_publish(urls))
        return result
    except Exception as exc:
        logger.error("Specific probe failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


# ── Phase 3: Additional source tasks ───────────────────────

@celery_app.task(bind=True, max_retries=2, default_retry_delay=300)
def collect_osint_feeds_task(self) -> dict:
    """
    Collect from OTX + SSLBL.

    Runs hourly via beat schedule.
    """
    logger.info("Starting OSINT feed collection")
    try:
        from backend.app.adapters.osint_feeds import collect_osint_feeds
        result = _run_async(collect_osint_feeds())
        _store_result("osint_feeds", result)
        logger.info("OSINT feed collection complete: %s", result)
        return result
    except Exception as exc:
        logger.error("OSINT feed collection failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=1, default_retry_delay=600)
def collect_sigma_rules_task(self) -> dict:
    """
    Fetch SigmaHQ detection rules for actor/technique associations.

    Runs daily at 6 AM UTC.
    """
    logger.info("Starting SigmaHQ rule collection")
    try:
        from backend.app.adapters.detection_rules import SigmaHQAdapter
        result = _run_async(SigmaHQAdapter().collect_and_publish())
        logger.info("SigmaHQ collection complete: %s", result)
        return result
    except Exception as exc:
        logger.error("SigmaHQ collection failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=1, default_retry_delay=600,
                 time_limit=600, soft_time_limit=540)
def collect_certstream_task(self) -> dict:
    """
    Listen to CertStream WebSocket for 5 min, filter for interesting certs.

    Runs every 4 hours. Extended time limit for WebSocket streaming.
    """
    logger.info("Starting CertStream listener")
    try:
        from backend.app.adapters.detection_rules import CertStreamAdapter
        result = _run_async(CertStreamAdapter().stream_and_publish(
            duration_seconds=300, max_events=50,
        ))
        logger.info("CertStream listener complete: %s", result)
        return result
    except Exception as exc:
        logger.error("CertStream listener failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=1)
def collect_tor_exits_task(self) -> dict:
    """
    Download current Tor exit node list for noise filtering.

    Runs daily at 2 AM UTC.
    """
    logger.info("Downloading Tor exit node list")
    try:
        from backend.app.adapters.supplementary import TorExitNodeAdapter
        result = _run_async(TorExitNodeAdapter().collect_and_publish())
        logger.info("Tor exit list download complete: %s", result)
        return result
    except Exception as exc:
        logger.error("Tor exit list download failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=1)
def collect_greynoise_for_ips(self, ips: list) -> dict:
    """
    Look up IPs against GreyNoise (on-demand, not scheduled).

    Triggered when entity extraction finds IPs that need reputation check.
    """
    logger.info("GreyNoise lookup for %d IPs", len(ips))
    try:
        from backend.app.adapters.osint_feeds import GreyNoiseAdapter
        result = _run_async(GreyNoiseAdapter().lookup_ips_and_publish(ips))
        return result
    except Exception as exc:
        logger.error("GreyNoise lookup failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=1)
def process_gwern_archive(self, archive_path: str = None) -> dict:
    """
    Process Gwern Silk Road archive (one-time or on-demand).

    Not scheduled — run manually when archive is downloaded.
    """
    logger.info("Processing Gwern archive")
    try:
        from backend.app.adapters.archives import GwernArchiveAdapter
        adapter = GwernArchiveAdapter(archive_path=archive_path)
        result = _run_async(adapter.process_and_publish(max_files=500))
        logger.info("Gwern archive processing complete: %s", result)
        return result
    except Exception as exc:
        logger.error("Gwern archive processing failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


# ── Pipeline tasks ──────────────────────────────────────────

@celery_app.task(bind=True, max_retries=2)
def process_event(self, event_data: dict) -> dict:
    """
    Process a single event through the analysis pipeline.

    Called by the event bus consumer for each new event.
    Runs: extraction → analysis → resolution → scoring.
    """
    logger.info("Processing event", extra={"event_id": event_data.get("event_id")})
    try:
        from backend.app.core.pipeline import process_raw_event
        result = _run_async(process_raw_event(event_data))
        return result
    except Exception as exc:
        logger.error("Pipeline error: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task
def close_merkle_batch() -> dict:
    """Close any open Merkle batch that has timed out."""
    logger.info("Checking for open Merkle batches")
    try:
        from backend.app.core.provenance import MerkleBatchManager
        manager = MerkleBatchManager()
        closed = manager.close_expired_batches()
        return {"status": "ok", "batches_closed": closed}
    except Exception as exc:
        logger.error("Merkle batch close failed: %s", exc)
        return {"status": "error", "error": str(exc)}


@celery_app.task
def enforce_retention() -> dict:
    """Delete data past its retention period (per source registry)."""
    logger.info("Enforcing retention policies")
    # TODO: query source registry for retention_days, delete expired events
    return {"status": "not_implemented"}


@celery_app.task(bind=True, max_retries=1)
def generate_export(self, job_id: str, format: str, filters: dict) -> dict:
    """Generate a CSV/JSON/PDF export asynchronously."""
    logger.info("Generating export", extra={"job_id": job_id, "format": format})
    try:
        from backend.app.exports.reports import generate_report
        result = _run_async(generate_report(job_id, format, filters))
        return result
    except Exception as exc:
        logger.error("Export generation failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


# ── Graph analytics tasks ──────────────────────────────────

@celery_app.task(bind=True, max_retries=1, time_limit=600)
def run_graph_analytics_task(self) -> dict:
    """
    Run all graph analytics (wallet clustering, correlations, merge candidates).

    Triggered on-demand or scheduled weekly.
    """
    logger.info("Starting graph analytics")
    try:
        from neo4j import AsyncGraphDatabase
        from backend.app.config import get_settings

        async def _run_analytics():
            settings = get_settings()
            driver = AsyncGraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password.get_secret_value()),
            )
            try:
                async with driver.session() as session:
                    from backend.app.graph.analytics import run_graph_analytics
                    return await run_graph_analytics(session)
            finally:
                try:
                    await driver.close()
                except Exception:
                    pass
                await asyncio.sleep(0.1)

        result = _run_async(_run_analytics())
        logger.info("Graph analytics complete: %s", result)
        return result
    except Exception as exc:
        logger.error("Graph analytics failed: %s", exc)
        return {"status": "error", "detail": str(exc)}


@celery_app.task(bind=True, max_retries=1)
def start_event_consumer_task(self) -> dict:
    """
    Start the event bus consumer.

    Runs as a long-lived task that processes events from the bus.
    """
    logger.info("Starting event bus consumer")
    try:
        from backend.app.workers.consumer import start_event_consumer
        _run_async(start_event_consumer())
        return {"status": "consumer_stopped"}
    except Exception as exc:
        logger.error("Event consumer failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)

