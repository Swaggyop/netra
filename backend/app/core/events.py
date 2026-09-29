"""
NETRA — Event schemas and EventBus protocol.

The EventBus abstraction decouples the pipeline from the transport layer.
Default: Redpanda (Kafka API).  Fallback: Redis Streams (set EVENT_BUS=redis).

All events are immutable after creation.  Pipeline stages append their outputs
to Postgres rows keyed by event_id — they never mutate the stream message.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, AsyncIterator

import orjson
from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────

class AdapterType(StrEnum):
    SYNTHETIC = "synthetic"
    REPLAY = "replay"
    OSINT_FEED = "osint_feed"
    CLEARNET_INTEL = "clearnet_intel"
    BLOCKCHAIN = "blockchain"
    AUTHORIZED = "authorized"


class CollectionMode(StrEnum):
    LIVE = "live"
    REPLAY = "replay"
    AUTHORIZED = "authorized"


class ContentType(StrEnum):
    TEXT = "text"
    JSON = "json"


# ── Event schema (frozen contract — §5 of the impl plan) ────

class RawEvent(BaseModel):
    """
    Immutable event published by source adapters after policy + safety gates.

    This is the canonical wire format.  All fields are set at creation time
    and never modified.  Pipeline stage outputs (entities, fingerprints,
    links) are appended to Postgres rows, not to this message.
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str
    adapter_type: AdapterType
    mode: CollectionMode
    observed_at: datetime
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    content_type: ContentType
    payload_ref: str                  # s3://netra-snapshots/...
    content_hash: str                 # sha256:...
    policy_decision_id: str
    language: str = "en"
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
    redactions: list[str] = Field(default_factory=list)

    def serialize(self) -> bytes:
        """Serialize to compact JSON bytes for the event bus."""
        return orjson.dumps(self.model_dump(mode="json"))

    @classmethod
    def deserialize(cls, data: bytes) -> RawEvent:
        """Deserialize from JSON bytes."""
        return cls.model_validate(orjson.loads(data))


# ── Topics (Redpanda / Kafka topic names) ────────────────────

class Topics(StrEnum):
    """Canonical topic names — create these at startup."""
    RAW_EVENTS = "netra.events.raw"
    EXTRACTION = "netra.events.extraction"
    ANALYSIS = "netra.events.analysis"
    ALERTS = "netra.events.alerts"
    DEAD_LETTER = "netra.events.dlq"


# ── EventBus protocol ───────────────────────────────────────

class EventBus(ABC):
    """
    Abstract event bus.  Implementations must handle serialisation,
    consumer groups, and offset management.
    """

    @abstractmethod
    async def start(self) -> None:
        """Initialise connections, create topics if needed."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Graceful shutdown."""
        ...

    @abstractmethod
    async def publish(self, topic: str, event: RawEvent) -> str:
        """
        Publish an event.  Returns an opaque offset/ID string.

        The implementation must serialise the event.
        """
        ...

    @abstractmethod
    async def subscribe(
        self,
        topic: str,
        group: str,
        *,
        from_beginning: bool = False,
    ) -> AsyncIterator[RawEvent]:
        """
        Yield events from a consumer group.

        If from_beginning is True, start from the earliest available offset
        (used by the replay engine).
        """
        ...

    @abstractmethod
    async def publish_dead_letter(
        self,
        original_topic: str,
        event_data: bytes,
        error: str,
    ) -> None:
        """Send a failed event to the dead-letter topic with error context."""
        ...


# ── Redpanda / Kafka implementation ─────────────────────────

class RedpandaEventBus(EventBus):
    """
    Production event bus using Redpanda (Kafka API) via aiokafka.

    Redpanda gives us:
    - Durable log with offsets → Replay mode can rewind to any point
    - Consumer groups → multiple independent analytics workers
    - Disk-based retention → not memory-bound like Redis Streams
    """

    def __init__(self, brokers: str) -> None:
        self._brokers = brokers
        self._producer: Any = None
        self._consumers: dict[str, Any] = {}

    async def start(self) -> None:
        from aiokafka import AIOKafkaProducer
        from aiokafka.admin import AIOKafkaAdminClient, NewTopic

        self._producer = AIOKafkaProducer(
            bootstrap_servers=self._brokers,
            value_serializer=lambda v: v,  # we pre-serialise
            acks="all",                    # durability
            enable_idempotence=True,       # exactly-once producer
            max_request_size=10 * 1024 * 1024,  # 10 MB cap
        )
        await self._producer.start()

        # Auto-create topics if they don't exist
        try:
            admin = AIOKafkaAdminClient(bootstrap_servers=self._brokers)
            await admin.start()
            topics = [
                NewTopic(
                    name=t.value,
                    num_partitions=3,
                    replication_factor=1,
                )
                for t in Topics
            ]
            await admin.create_topics(topics)
            await admin.close()
        except Exception:
            # Topics may already exist — that's fine
            pass

    async def stop(self) -> None:
        if self._producer:
            await self._producer.stop()
        for consumer in self._consumers.values():
            await consumer.stop()

    async def publish(self, topic: str, event: RawEvent) -> str:
        if not self._producer:
            raise RuntimeError("EventBus not started")

        result = await self._producer.send_and_wait(
            topic,
            value=event.serialize(),
            key=event.source_id.encode(),
        )
        return f"{result.partition}:{result.offset}"

    async def subscribe(
        self,
        topic: str,
        group: str,
        *,
        from_beginning: bool = False,
    ) -> AsyncIterator[RawEvent]:
        from aiokafka import AIOKafkaConsumer

        consumer_key = f"{topic}:{group}"
        if consumer_key not in self._consumers:
            consumer = AIOKafkaConsumer(
                topic,
                bootstrap_servers=self._brokers,
                group_id=group,
                auto_offset_reset="earliest" if from_beginning else "latest",
                enable_auto_commit=True,
                auto_commit_interval_ms=5000,
                value_deserializer=lambda v: v,
                max_poll_records=100,
            )
            await consumer.start()
            self._consumers[consumer_key] = consumer

        consumer = self._consumers[consumer_key]
        async for msg in consumer:
            try:
                yield RawEvent.deserialize(msg.value)
            except Exception as exc:
                await self.publish_dead_letter(
                    topic, msg.value, str(exc),
                )

    async def publish_dead_letter(
        self,
        original_topic: str,
        event_data: bytes,
        error: str,
    ) -> None:
        if not self._producer:
            return

        dlq_payload = orjson.dumps({
            "original_topic": original_topic,
            "error": error,
            "event_data": event_data.decode("utf-8", errors="replace"),
            "failed_at": datetime.now(UTC).isoformat(),
        })
        await self._producer.send_and_wait(
            Topics.DEAD_LETTER.value,
            value=dlq_payload,
        )


# ── Redis Streams fallback (lightweight dev) ─────────────────

class RedisEventBus(EventBus):
    """
    Lightweight dev fallback using Redis Streams.

    Set EVENT_BUS=redis in .env to use this instead of Redpanda.
    Not recommended for production due to memory-bound retention.
    """

    MAX_STREAM_LEN = 100_000  # auto-trim to prevent unbounded memory

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._redis: Any = None

    async def start(self) -> None:
        import redis.asyncio as aioredis
        self._redis = aioredis.from_url(
            self._redis_url,
            decode_responses=False,
        )

    async def stop(self) -> None:
        if self._redis:
            await self._redis.aclose()

    async def publish(self, topic: str, event: RawEvent) -> str:
        if not self._redis:
            raise RuntimeError("EventBus not started")

        msg_id: bytes = await self._redis.xadd(
            topic,
            {"data": event.serialize()},
            maxlen=self.MAX_STREAM_LEN,
        )
        return msg_id.decode()

    async def subscribe(
        self,
        topic: str,
        group: str,
        *,
        from_beginning: bool = False,
    ) -> AsyncIterator[RawEvent]:
        if not self._redis:
            raise RuntimeError("EventBus not started")

        # Create consumer group (idempotent)
        try:
            await self._redis.xgroup_create(
                topic, group,
                id="0" if from_beginning else "$",
                mkstream=True,
            )
        except Exception:
            pass  # group may already exist

        consumer_name = f"worker-{uuid.uuid4().hex[:8]}"
        while True:
            messages = await self._redis.xreadgroup(
                group, consumer_name,
                {topic: ">"},
                count=100,
                block=5000,
            )
            for _stream, entries in messages:
                for msg_id, data in entries:
                    try:
                        event = RawEvent.deserialize(data[b"data"])
                        yield event
                        await self._redis.xack(topic, group, msg_id)
                    except Exception as exc:
                        await self.publish_dead_letter(
                            topic, data.get(b"data", b""), str(exc),
                        )
                        await self._redis.xack(topic, group, msg_id)

    async def publish_dead_letter(
        self,
        original_topic: str,
        event_data: bytes,
        error: str,
    ) -> None:
        if not self._redis:
            return

        dlq_payload = orjson.dumps({
            "original_topic": original_topic,
            "error": error,
            "event_data": event_data.decode("utf-8", errors="replace"),
            "failed_at": datetime.now(UTC).isoformat(),
        })
        await self._redis.xadd(
            Topics.DEAD_LETTER.value,
            {"data": dlq_payload},
            maxlen=self.MAX_STREAM_LEN,
        )


# ── Factory ──────────────────────────────────────────────────

def create_event_bus() -> EventBus:
    """Create the configured EventBus implementation."""
    from backend.app.config import get_settings
    settings = get_settings()

    if settings.event_bus == "redpanda":
        return RedpandaEventBus(settings.redpanda_brokers)
    else:
        return RedisEventBus(settings.redis_url)
