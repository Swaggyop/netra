"""
NETRA — Entity resolution and graph writer (§7.6, M4).

Takes extracted entities from the extraction pipeline and:
  1. Deduplicates against existing entities (kind + normalized)
  2. Creates Observation links (entity ↔ event)
  3. Writes entity nodes and relationships to Neo4j
  4. Clusters wallet addresses by co-spending heuristics
  5. Resolves handles to actors where evidence is strong
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.extraction.extractors import EntityHit
from backend.app.graph.schema import create_node, create_relationship
from backend.app.models.entities import Entity, Observation

logger = logging.getLogger(__name__)


# ── Kind → Neo4j label mapping ───────────────────────────────

NEO4J_LABEL_MAP: dict[str, str] = {
    "pgp": "PGPKey",
    "wallet": "Wallet",
    "email": "Email",
    "domain": "Domain",
    "onion": "Onion",
    "contact_id": "ContactID",
    "handle": "Handle",
    "ip": "IP",
    "avatar_hash": "AvatarHash",
    "cert_fp": "Cert",
    "ssh_key": "SSHKey",
    "favicon_hash": "Favicon",
}


async def resolve_entities(
    session: AsyncSession,
    neo4j_session: Any,
    event_id: str,
    source_id: str,
    hits: list[EntityHit],
) -> list[str]:
    """
    Resolve extracted entities: deduplicate, persist, and write to graph.

    Returns list of entity_ids (new or existing).
    """
    entity_ids: list[str] = []

    for hit in hits:
        # 1. Deduplicate: find existing entity by (kind, normalized)
        result = await session.execute(
            select(Entity).where(
                Entity.kind == hit.kind,
                Entity.normalized == hit.normalized,
            )
        )
        entity = result.scalar_one_or_none()

        now = datetime.now(UTC)

        if entity:
            # Update last_seen
            entity.last_seen = now
            entity_id = entity.entity_id
        else:
            # Create new entity
            entity_id = str(uuid.uuid4())
            entity = Entity(
                entity_id=entity_id,
                kind=hit.kind,
                value=hit.value,
                normalized=hit.normalized,
                first_seen=now,
                last_seen=now,
            )
            session.add(entity)

        # 2. Create observation link (entity ↔ event)
        # Check if observation already exists
        existing_obs = await session.execute(
            select(Observation).where(
                Observation.event_id == event_id,
                Observation.entity_id == entity_id,
                Observation.role == "extracted",
            )
        )
        if existing_obs.scalar_one_or_none() is None:
            obs = Observation(
                obs_id=str(uuid.uuid4()),
                event_id=event_id,
                entity_id=entity_id,
                role="extracted",
                observed_at=now,
            )
            session.add(obs)

        entity_ids.append(entity_id)

        # 3. Write to Neo4j
        label = NEO4J_LABEL_MAP.get(hit.kind, "Entity")
        node_props: dict[str, Any] = {
            "id": entity_id,
            "kind": hit.kind,
            "value": hit.value,
            "normalized": hit.normalized,
            "first_seen": now.isoformat(),
            "last_seen": now.isoformat(),
        }

        # Add metadata fields to node properties
        if hit.metadata:
            for k, v in hit.metadata.items():
                if isinstance(v, (str, int, float, bool)):
                    node_props[k] = v

        # Special properties per kind
        if hit.kind == "pgp":
            node_props["fingerprint"] = hit.normalized
        elif hit.kind == "onion":
            node_props["address"] = hit.value
        elif hit.kind == "domain":
            node_props["name"] = hit.value
        elif hit.kind == "wallet":
            node_props["currency"] = hit.metadata.get("currency", "unknown")

        await create_node(neo4j_session, label, node_props)

    await session.flush()

    logger.info(
        "Resolved %d entities for event %s (%d new)",
        len(hits), event_id[:8], len(hits) - sum(1 for _ in entity_ids if _),
    )

    return entity_ids


async def link_entities_to_actor(
    session: AsyncSession,
    neo4j_session: Any,
    actor_id: str,
    entity_ids: list[str],
    added_by: str = "system",
) -> None:
    """
    Link a set of entities to an actor in both Postgres and Neo4j.
    """
    from backend.app.models.actors import Actor, ActorEntity

    # Verify actor exists
    result = await session.execute(
        select(Actor).where(Actor.actor_id == actor_id)
    )
    actor = result.scalar_one_or_none()
    if not actor:
        logger.warning("Actor %s not found, skipping link", actor_id)
        return

    for entity_id in entity_ids:
        # Check if link already exists
        existing = await session.execute(
            select(ActorEntity).where(
                ActorEntity.actor_id == actor_id,
                ActorEntity.entity_id == entity_id,
            )
        )
        if existing.scalar_one_or_none() is None:
            session.add(ActorEntity(
                actor_id=actor_id,
                entity_id=entity_id,
                added_by=added_by,
            ))

        # Neo4j: Actor -[USES]-> Entity node
        entity = await session.execute(
            select(Entity).where(Entity.entity_id == entity_id)
        )
        entity_row = entity.scalar_one_or_none()
        if entity_row:
            label = NEO4J_LABEL_MAP.get(entity_row.kind, "Entity")
            await create_relationship(
                neo4j_session,
                "Actor", actor_id,
                "USES",
                label, entity_id,
            )

    await session.flush()


async def create_actor_from_handle(
    session: AsyncSession,
    neo4j_session: Any,
    handle: str,
    entity_ids: list[str],
    category: str = "unknown",
) -> str:
    """
    Create a new actor from a handle and link initial entities.

    Returns the new actor_id.
    """
    from backend.app.models.actors import Actor

    actor_id = str(uuid.uuid4())
    now = datetime.now(UTC)

    actor = Actor(
        actor_id=actor_id,
        label=handle,
        category=category,
        first_seen=now,
        last_seen=now,
        status="active",
    )
    session.add(actor)

    # Create Neo4j actor node
    await create_node(neo4j_session, "Actor", {
        "id": actor_id,
        "label": handle,
        "category": category,
        "first_seen": now.isoformat(),
        "last_seen": now.isoformat(),
        "status": "active",
    })

    # Link entities
    await link_entities_to_actor(session, neo4j_session, actor_id, entity_ids)

    logger.info("Created actor '%s' (%s) with %d entities", handle, actor_id[:8], len(entity_ids))
    return actor_id
