"""
NETRA — Graph analytics engine.

Post-processing analytics that run on the Neo4j knowledge graph:
  1. Wallet clustering (common-input-ownership heuristic)
  2. Clock-skew correlation (SHARES_CLOCK_SKEW edges)
  3. Favicon fingerprint correlation (SHARES_FINGERPRINT edges)
  4. Entity co-occurrence scoring (entities seen together → likely same actor)
  5. Actor merge recommendations (when evidence is strong enough)
  6. Graph statistics and topology metrics
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from neo4j import AsyncSession

from backend.app.graph.schema import create_node, create_relationship

logger = logging.getLogger(__name__)


# ── Wallet clustering ────────────────────────────────────────

async def cluster_wallets(
    session: AsyncSession,
    co_spent_groups: list[list[str]],
) -> dict[str, Any]:
    """
    Apply common-input-ownership heuristic to group wallets.

    The heuristic: if two addresses appear as inputs in the same
    Bitcoin transaction, they are likely controlled by the same entity.

    Creates WalletCluster nodes and MEMBER_OF edges.

    Args:
        session: Neo4j session
        co_spent_groups: List of groups, each group is a list of
                         addresses that were co-spent in a single tx.
    """
    clusters_created = 0
    memberships_created = 0

    for group in co_spent_groups:
        if len(group) < 2:
            continue

        # Find or create a cluster for this group
        # Use the first address as a deterministic cluster ID
        cluster_id = f"cluster_{group[0][:16]}"

        await create_node(session, "WalletCluster", {
            "id": cluster_id,
            "size": len(group),
            "created_at": datetime.now(UTC).isoformat(),
            "heuristic": "common_input_ownership",
        })
        clusters_created += 1

        for addr in group:
            # Find the wallet node
            result = await session.run(
                "MATCH (w:Wallet {normalized: $addr}) RETURN w.id AS id",
                addr=addr,
            )
            record = await result.single()
            if record:
                wallet_id = record["id"]
                await create_relationship(
                    session,
                    "Wallet", wallet_id,
                    "MEMBER_OF",
                    "WalletCluster", cluster_id,
                    {"joined_at": datetime.now(UTC).isoformat()},
                )
                memberships_created += 1

    logger.info(
        "Wallet clustering: %d clusters, %d memberships",
        clusters_created, memberships_created,
    )
    return {
        "clusters_created": clusters_created,
        "memberships_created": memberships_created,
    }


# ── Clock-skew correlation graph edges ──────────────────────

async def write_clock_skew_correlations(
    session: AsyncSession,
    correlations: list[dict[str, Any]],
) -> dict[str, int]:
    """
    Write SHARES_CLOCK_SKEW edges from the ClockSkewCorrelator output.

    Each correlation has url_a, url_b, confidence, and skew measurements.
    """
    edges_created = 0

    for corr in correlations:
        url_a = corr["url_a"]
        url_b = corr["url_b"]
        confidence = corr["confidence"]

        # Find onion nodes by address
        result_a = await session.run(
            "MATCH (o:Onion) WHERE o.value CONTAINS $url RETURN o.id AS id LIMIT 1",
            url=url_a.replace("http://", "").replace("https://", "").split("/")[0],
        )
        result_b = await session.run(
            "MATCH (o:Onion) WHERE o.value CONTAINS $url RETURN o.id AS id LIMIT 1",
            url=url_b.replace("http://", "").replace("https://", "").split("/")[0],
        )

        record_a = await result_a.single()
        record_b = await result_b.single()

        if record_a and record_b:
            await create_relationship(
                session,
                "Onion", record_a["id"],
                "SHARES_CLOCK_SKEW",
                "Onion", record_b["id"],
                {
                    "confidence": confidence,
                    "skew_diff": corr["skew_diff"],
                    "samples_a": corr["samples_a"],
                    "samples_b": corr["samples_b"],
                    "detected_at": datetime.now(UTC).isoformat(),
                },
            )
            edges_created += 1

    logger.info("Clock-skew correlation: %d edges created", edges_created)
    return {"edges_created": edges_created}


# ── Favicon fingerprint correlation ─────────────────────────

async def write_favicon_correlations(
    session: AsyncSession,
) -> dict[str, int]:
    """
    Find onion services sharing the same favicon hash and create
    SHARES_FINGERPRINT edges.

    Same favicon hash on different .onion addresses = likely same operator.
    """
    query = """
    MATCH (a:Onion), (b:Onion)
    WHERE a.id < b.id
      AND a.favicon_hash IS NOT NULL
      AND a.favicon_hash = b.favicon_hash
      AND NOT (a)-[:SHARES_FINGERPRINT]-(b)
    RETURN a.id AS id_a, b.id AS id_b, a.favicon_hash AS hash
    """
    result = await session.run(query)
    records = [record async for record in result]

    edges_created = 0
    for record in records:
        await create_relationship(
            session,
            "Onion", record["id_a"],
            "SHARES_FINGERPRINT",
            "Onion", record["id_b"],
            {
                "kind": "favicon",
                "value": str(record["hash"]),
                "detected_at": datetime.now(UTC).isoformat(),
            },
        )
        edges_created += 1

    logger.info("Favicon correlation: %d edges created", edges_created)
    return {"edges_created": edges_created}


# ── Entity co-occurrence scoring ────────────────────────────

async def compute_entity_cooccurrence(
    session: AsyncSession,
    min_cooccurrences: int = 3,
) -> list[dict[str, Any]]:
    """
    Find entities that frequently co-occur across events.

    If handle "ShadowX" and PGP key "ABCD1234" appear in 5+ events
    together, they likely belong to the same actor.

    Returns list of co-occurrence pairs with strength scores.
    """
    query = """
    MATCH (e1)-[:OBSERVED_IN]->(event)<-[:OBSERVED_IN]-(e2)
    WHERE e1.id < e2.id
      AND labels(e1) <> labels(e2)
    WITH e1, e2, COUNT(DISTINCT event) AS cooccurrences
    WHERE cooccurrences >= $min_co
    RETURN e1.id AS entity_a, labels(e1)[0] AS type_a, e1.value AS value_a,
           e2.id AS entity_b, labels(e2)[0] AS type_b, e2.value AS value_b,
           cooccurrences
    ORDER BY cooccurrences DESC
    LIMIT 100
    """
    result = await session.run(query, min_co=min_cooccurrences)
    records = [record async for record in result]

    pairs = [
        {
            "entity_a": {"id": r["entity_a"], "type": r["type_a"], "value": r["value_a"]},
            "entity_b": {"id": r["entity_b"], "type": r["type_b"], "value": r["value_b"]},
            "cooccurrences": r["cooccurrences"],
            "strength": min(1.0, r["cooccurrences"] / 10.0),
        }
        for r in records
    ]

    logger.info("Entity co-occurrence: %d pairs found", len(pairs))
    return pairs


# ── Actor merge recommendations ─────────────────────────────

async def find_merge_candidates(
    session: AsyncSession,
    min_shared_entities: int = 2,
) -> list[dict[str, Any]]:
    """
    Find actors that share multiple entities and recommend merges.

    If Actor A and Actor B both USES the same PGP key and the same
    wallet address, they are likely the same person.
    """
    query = """
    MATCH (a1:Actor)-[:USES]->(shared)<-[:USES]-(a2:Actor)
    WHERE a1.id < a2.id
    WITH a1, a2, COLLECT(DISTINCT shared) AS shared_entities
    WHERE SIZE(shared_entities) >= $min_shared
    RETURN a1.id AS actor_a, a1.label AS label_a,
           a2.id AS actor_b, a2.label AS label_b,
           SIZE(shared_entities) AS shared_count,
           [e IN shared_entities | {labels: labels(e), value: e.value}] AS shared_details
    ORDER BY shared_count DESC
    """
    result = await session.run(query, min_shared=min_shared_entities)
    records = [record async for record in result]

    candidates = [
        {
            "actor_a": {"id": r["actor_a"], "label": r["label_a"]},
            "actor_b": {"id": r["actor_b"], "label": r["label_b"]},
            "shared_count": r["shared_count"],
            "shared_entities": r["shared_details"],
            "recommendation": "merge" if r["shared_count"] >= 3 else "review",
        }
        for r in records
    ]

    logger.info("Merge candidates: %d pairs found", len(candidates))
    return candidates


# ── Graph topology stats ────────────────────────────────────

async def compute_graph_stats(session: AsyncSession) -> dict[str, Any]:
    """
    Compute topology metrics for the knowledge graph.

    Used by the dashboard for overview statistics.
    """
    stats: dict[str, Any] = {}

    # Node counts by label
    result = await session.run("""
        CALL db.labels() YIELD label
        CALL {
            WITH label
            CALL db.schema.nodeTypeProperties() YIELD nodeLabels
            WHERE label IN nodeLabels
            RETURN COUNT(*) AS count
        }
        RETURN label, count
    """)

    # Simpler approach — count each known label
    for label in ["Actor", "Handle", "Wallet", "PGPKey", "Email", "Onion",
                   "ContactID", "Domain", "IP", "WalletCluster"]:
        try:
            result = await session.run(f"MATCH (n:{label}) RETURN COUNT(n) AS c")
            record = await result.single()
            stats[f"node_{label.lower()}"] = record["c"] if record else 0
        except Exception:
            stats[f"node_{label.lower()}"] = 0

    # Relationship counts
    for rel_type in ["USES", "LINKED_TO", "SHARES_FINGERPRINT", "SHARES_CLOCK_SKEW",
                     "MEMBER_OF", "SENT_TO"]:
        try:
            result = await session.run(
                f"MATCH ()-[r:{rel_type}]->() RETURN COUNT(r) AS c"
            )
            record = await result.single()
            stats[f"rel_{rel_type.lower()}"] = record["c"] if record else 0
        except Exception:
            stats[f"rel_{rel_type.lower()}"] = 0

    # Total nodes and edges
    try:
        result = await session.run("MATCH (n) RETURN COUNT(n) AS total")
        record = await result.single()
        stats["total_nodes"] = record["total"] if record else 0
    except Exception:
        stats["total_nodes"] = 0

    try:
        result = await session.run("MATCH ()-[r]->() RETURN COUNT(r) AS total")
        record = await result.single()
        stats["total_edges"] = record["total"] if record else 0
    except Exception:
        stats["total_edges"] = 0

    stats["computed_at"] = datetime.now(UTC).isoformat()
    return stats


# ── Orchestrator ────────────────────────────────────────────

async def run_graph_analytics(session: AsyncSession) -> dict[str, Any]:
    """Run all graph analytics tasks."""
    results: dict[str, Any] = {"started_at": datetime.now(UTC).isoformat()}

    # 1. Favicon correlation
    try:
        results["favicon"] = await write_favicon_correlations(session)
    except Exception as exc:
        logger.error("Favicon correlation failed: %s", exc)
        results["favicon"] = {"error": str(exc)}

    # 2. Entity co-occurrence
    try:
        results["cooccurrence"] = await compute_entity_cooccurrence(session)
    except Exception as exc:
        logger.error("Co-occurrence failed: %s", exc)
        results["cooccurrence"] = {"error": str(exc)}

    # 3. Merge candidates
    try:
        results["merge_candidates"] = await find_merge_candidates(session)
    except Exception as exc:
        logger.error("Merge candidates failed: %s", exc)
        results["merge_candidates"] = {"error": str(exc)}

    # 4. Graph stats
    try:
        results["stats"] = await compute_graph_stats(session)
    except Exception as exc:
        logger.error("Graph stats failed: %s", exc)
        results["stats"] = {"error": str(exc)}

    results["completed_at"] = datetime.now(UTC).isoformat()
    return results
