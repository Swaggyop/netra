"""
NETRA — Neo4j graph schema and connection management (§6.2).

Manages Neo4j driver lifecycle, applies uniqueness constraints and indexes
at startup, and provides typed query helpers.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncSession

from backend.app.config import get_settings

logger = logging.getLogger(__name__)


# ── Node labels ──────────────────────────────────────────────

NODE_LABELS = [
    "Actor",
    "Handle",
    "PGPKey",
    "Wallet",
    "WalletCluster",
    "Email",
    "ContactID",
    "AvatarHash",
    "Onion",
    "Domain",
    "IP",
    "Cert",
    "Favicon",
    "SSHKey",
    "Market",
    "Listing",
    "Post",
]

# ── Relationship types ───────────────────────────────────────

RELATIONSHIP_TYPES = [
    "USES",                # Actor → Handle|PGPKey|Wallet|Email|ContactID|AvatarHash
    "ACTIVE_ON",           # Handle → Market
    "MEMBER_OF",           # Wallet → WalletCluster
    "SENT_TO",             # Wallet → Wallet  (amount, ts)
    "SHARES_FINGERPRINT",  # Onion → Domain|IP  (kind, value)
    "OPERATED_BY_LIKELY",  # Onion → Actor  (score)
    "LINKED_TO",           # Actor → Actor  (score, band, link_id)
    "TRUSTS",              # Handle → Handle
    "VOUCHES_FOR",         # Handle → Handle
]


# ── Constraints + indexes (applied at startup) ──────────────

SCHEMA_STATEMENTS = [
    # Uniqueness constraints (each has a built-in index)
    *[
        f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE"
        for label in NODE_LABELS
    ],

    # Additional indexes for query performance
    "CREATE INDEX IF NOT EXISTS FOR (n:Actor) ON (n.label)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Actor) ON (n.first_seen)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Actor) ON (n.last_seen)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Handle) ON (n.value)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Wallet) ON (n.value)",
    "CREATE INDEX IF NOT EXISTS FOR (n:PGPKey) ON (n.fingerprint)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Onion) ON (n.address)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Domain) ON (n.name)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Email) ON (n.value)",
    "CREATE INDEX IF NOT EXISTS FOR (n:ContactID) ON (n.value)",

    # Full-text search index for investigator queries
    (
        "CREATE FULLTEXT INDEX actorSearch IF NOT EXISTS "
        "FOR (n:Actor|Handle|PGPKey|Wallet|Email|Onion|ContactID) "
        "ON EACH [n.value, n.label, n.fingerprint, n.address, n.name]"
    ),
]


# ── Driver management ────────────────────────────────────────

_driver: AsyncDriver | None = None


async def init_neo4j() -> AsyncDriver:
    """Initialise the Neo4j async driver and apply schema."""
    global _driver  # noqa: PLW0603

    settings = get_settings()
    _driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password.get_secret_value()),
        max_connection_pool_size=50,
        connection_acquisition_timeout=30.0,
    )

    # Verify connectivity
    await _driver.verify_connectivity()
    logger.info("Neo4j connection verified")

    # Apply schema
    async with _driver.session() as session:
        for stmt in SCHEMA_STATEMENTS:
            try:
                await session.run(stmt)
            except Exception as exc:
                logger.warning("Schema statement failed (may already exist): %s — %s", stmt[:60], exc)

    logger.info("Neo4j schema applied: %d constraints/indexes", len(SCHEMA_STATEMENTS))
    return _driver


async def close_neo4j() -> None:
    """Close the Neo4j driver."""
    global _driver  # noqa: PLW0603
    if _driver:
        await _driver.close()
        _driver = None


def get_driver() -> AsyncDriver:
    """Get the active Neo4j driver. Raises if not initialised."""
    if _driver is None:
        raise RuntimeError("Neo4j not initialised — call init_neo4j() first")
    return _driver


@asynccontextmanager
async def get_neo4j_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: yields a Neo4j session."""
    global _driver
    if _driver is None:
        await init_neo4j()
    driver = get_driver()
    async with driver.session() as session:
        yield session


# ── Typed query helpers ──────────────────────────────────────

async def create_node(
    session: AsyncSession,
    label: str,
    properties: dict[str, Any],
) -> dict[str, Any]:
    """Create or merge a node by its id property."""
    query = f"""
    MERGE (n:{label} {{id: $id}})
    SET n += $props
    RETURN n
    """
    result = await session.run(query, id=properties["id"], props=properties)
    record = await result.single()
    return dict(record["n"]) if record else {}


async def create_relationship(
    session: AsyncSession,
    from_label: str,
    from_id: str,
    rel_type: str,
    to_label: str,
    to_id: str,
    properties: dict[str, Any] | None = None,
) -> None:
    """Create or update a relationship between two nodes."""
    props = properties or {}
    query = f"""
    MATCH (a:{from_label} {{id: $from_id}})
    MATCH (b:{to_label} {{id: $to_id}})
    MERGE (a)-[r:{rel_type}]->(b)
    SET r += $props
    """
    await session.run(
        query,
        from_id=from_id,
        to_id=to_id,
        props=props,
    )


async def get_actor_graph(
    session: AsyncSession,
    actor_id: str,
    depth: int = 2,
) -> dict[str, Any]:
    """
    Return the ego graph around an actor up to N hops.

    Used by the dashboard graph view.
    """
    # Parameterised depth to prevent injection (OWASP A03)
    # Note: Cypher doesn't support parameterised relationship length,
    # so we validate depth is within bounds and interpolate safely.
    depth = max(1, min(depth, 5))  # cap at 5 to prevent expensive queries

    query = f"""
    MATCH path = (a:Actor {{id: $actor_id}})-[*1..{depth}]-(connected)
    WITH nodes(path) AS ns, relationships(path) AS rs
    UNWIND ns AS n
    WITH collect(DISTINCT n) AS nodes, rs
    UNWIND rs AS r
    RETURN nodes, collect(DISTINCT r) AS relationships
    """
    result = await session.run(query, actor_id=actor_id)
    record = await result.single()

    if not record:
        return {"nodes": [], "relationships": []}

    return {
        "nodes": [dict(n) for n in record["nodes"]],
        "relationships": [
            {
                "type": type(r).__name__,
                "start": r.start_node["id"] if r.start_node else None,
                "end": r.end_node["id"] if r.end_node else None,
                "properties": dict(r),
            }
            for r in record["relationships"]
        ],
    }


async def search_graph(
    session: AsyncSession,
    query_text: str,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """
    Full-text search across actor-related nodes.

    Input is sanitised to prevent Lucene injection (OWASP A03).
    """
    # Sanitise: escape Lucene special characters
    import re
    sanitised = re.sub(r'([+\-&|!(){}[\]^"~*?:\\])', r"\\\1", query_text)

    if not sanitised.strip():
        return []

    query = """
    CALL db.index.fulltext.queryNodes('actorSearch', $search_term)
    YIELD node, score
    RETURN labels(node) AS labels, node AS data, score
    ORDER BY score DESC
    LIMIT $limit
    """
    result = await session.run(query, search_term=sanitised, limit=limit)
    records = [record async for record in result]
    return [
        {
            "labels": record["labels"],
            "data": dict(record["data"]),
            "score": record["score"],
        }
        for record in records
    ]
