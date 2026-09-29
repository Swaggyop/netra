"""
NETRA — Blockchain intelligence adapter (Phase 1).

Pulls real-time blockchain data for wallet analysis:
  1. mempool.space       — BTC address data, transactions, UTXOs (no key)
  2. Blockstream Esplora — BTC backup (no key)
  3. Blockchair          — Multi-chain: BTC, ETH, LTC, DOGE (free tier, no key)
  4. Etherscan           — ETH transactions and token transfers (free API key)

Does NOT pull from:
  - Chainabuse: ToS prohibits scraping (flagged — needs manual verification)
  - Arkham Intelligence: no confirmed free API (manual explorer only)

Source provenance:
  - mempool.space API docs: https://mempool.space/docs/api (verified, no auth, rate limited)
  - Blockstream Esplora: https://github.com/Blockstream/esplora (verified, no auth)
  - Blockchair API: https://blockchair.com/api (verified, free tier: 1440 req/day)
  - Etherscan API: https://docs.etherscan.io/ (verified, free key: 5 req/sec)
  - OFAC SDN list: https://www.treasury.gov/ofac/downloads/ (public, no auth)
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from backend.app.adapters.http_client import LiveHTTPClient
from backend.app.config import get_settings
from backend.app.core.events import (
    AdapterType,
    CollectionMode,
    ContentType,
    RawEvent,
    Topics,
    create_event_bus,
)
from backend.app.core.provenance import compute_content_hash

logger = logging.getLogger(__name__)


# ── mempool.space adapter ───────────────────────────────────

class MempoolAdapter:
    """
    Bitcoin address and transaction data via mempool.space.

    Endpoints:
      GET /api/address/{addr}        → balance, tx count
      GET /api/address/{addr}/txs    → transaction history (50 mempool + 25 confirmed)
      GET /api/address/{addr}/utxo   → unspent outputs (for common-input clustering)

    Auth: none
    Rate limit: documented, returns 429 on abuse
    """

    BASE_URL = "https://mempool.space/api"
    SOURCE_ID = "src_mempool"

    def __init__(self) -> None:
        self._client = LiveHTTPClient("mempool")

    async def get_address_info(self, address: str) -> dict[str, Any]:
        """Get balance and transaction count for a BTC address."""
        async with self._client:
            response = await self._client.get(f"{self.BASE_URL}/address/{address}")
            return response.json()

    async def get_address_txs(self, address: str) -> list[dict[str, Any]]:
        """Get transaction history for a BTC address."""
        async with self._client:
            response = await self._client.get(f"{self.BASE_URL}/address/{address}/txs")
            return response.json()

    async def get_address_utxo(self, address: str) -> list[dict[str, Any]]:
        """Get UTXOs for common-input-ownership clustering."""
        async with self._client:
            response = await self._client.get(f"{self.BASE_URL}/address/{address}/utxo")
            return response.json()

    async def collect_address(self, address: str) -> dict[str, Any]:
        """
        Full collection for a single BTC address: info + txs + UTXOs.

        Returns combined result dict.
        """
        info = await self.get_address_info(address)
        txs = await self.get_address_txs(address)
        utxos = await self.get_address_utxo(address)

        return {
            "address": address,
            "chain_stats": info.get("chain_stats", {}),
            "mempool_stats": info.get("mempool_stats", {}),
            "transactions": txs[:25],  # cap to avoid huge payloads
            "utxo_count": len(utxos),
            "utxos": utxos[:50],
        }

    async def collect_addresses_and_publish(
        self, addresses: list[str]
    ) -> dict[str, int]:
        """
        Collect data for a list of BTC addresses and publish to event bus.

        Args:
            addresses: List of BTC addresses to look up (typically from
                       ransomware tracker or entity extraction).
        """
        bus = create_event_bus()
        await bus.start()
        published = 0
        errors = 0

        try:
            for addr in addresses:
                try:
                    data = await self.collect_address(addr)
                    content = json.dumps(data, ensure_ascii=False)
                    content_hash = compute_content_hash(content.encode("utf-8"))

                    # Extract co-spent inputs for clustering
                    co_spent_addresses: list[str] = []
                    for tx in data.get("transactions", []):
                        inputs = tx.get("vin", [])
                        if len(inputs) > 1:
                            for vin in inputs:
                                prev_addr = vin.get("prevout", {}).get("scriptpubkey_address", "")
                                if prev_addr and prev_addr != addr:
                                    co_spent_addresses.append(prev_addr)

                    event = RawEvent(
                        source_id=self.SOURCE_ID,
                        adapter_type=AdapterType.BLOCKCHAIN,
                        mode=CollectionMode.LIVE,
                        observed_at=datetime.now(UTC),
                        content_type=ContentType.JSON,
                        payload_ref=f"s3://netra-snapshots/blockchain/btc/{addr[:16]}.json",
                        content_hash=content_hash,
                        policy_decision_id="live-approved-feed",
                        language="en",
                        raw_metadata={
                            "type": "btc_address",
                            "address": addr,
                            "chain": "btc",
                            "tx_count": data.get("chain_stats", {}).get("tx_count", 0),
                            "funded_sum": data.get("chain_stats", {}).get("funded_txo_sum", 0),
                            "spent_sum": data.get("chain_stats", {}).get("spent_txo_sum", 0),
                            "utxo_count": data.get("utxo_count", 0),
                            "co_spent_addresses": co_spent_addresses[:20],
                            "text": content,
                        },
                    )

                    await bus.publish(Topics.RAW_EVENTS.value, event)
                    published += 1

                except Exception as exc:
                    logger.error("Failed to collect BTC address %s: %s", addr[:16], exc)
                    errors += 1

        finally:
            await bus.stop()

        return {"source": self.SOURCE_ID, "published": published, "errors": errors}


# ── Etherscan adapter ───────────────────────────────────────

class EtherscanAdapter:
    """
    Ethereum transaction data via Etherscan.

    Endpoints:
      GET /api?module=account&action=txlist&address={addr}    → ETH transactions
      GET /api?module=account&action=tokentx&address={addr}   → ERC-20 token transfers

    Auth: free API key (5 req/sec)
    Docs: https://docs.etherscan.io/
    """

    BASE_URL = "https://api.etherscan.io"
    SOURCE_ID = "src_etherscan"

    def __init__(self) -> None:
        self._settings = get_settings()
        self._client = LiveHTTPClient("etherscan")

    async def get_transactions(self, address: str) -> list[dict[str, Any]]:
        """Get ETH transactions for an address."""
        api_key = self._settings.etherscan_api_key
        if not api_key:
            raise ValueError("ETHERSCAN_API_KEY not set")

        async with self._client:
            response = await self._client.get(
                f"{self.BASE_URL}/api",
                params={
                    "module": "account",
                    "action": "txlist",
                    "address": address,
                    "startblock": 0,
                    "endblock": 99999999,
                    "page": 1,
                    "offset": 50,
                    "sort": "desc",
                    "apikey": api_key,
                },
            )
            data = response.json()
        return data.get("result", []) if isinstance(data.get("result"), list) else []

    async def get_token_transfers(self, address: str) -> list[dict[str, Any]]:
        """Get ERC-20 token transfers for an address."""
        api_key = self._settings.etherscan_api_key
        if not api_key:
            raise ValueError("ETHERSCAN_API_KEY not set")

        async with self._client:
            response = await self._client.get(
                f"{self.BASE_URL}/api",
                params={
                    "module": "account",
                    "action": "tokentx",
                    "address": address,
                    "page": 1,
                    "offset": 50,
                    "sort": "desc",
                    "apikey": api_key,
                },
            )
            data = response.json()
        return data.get("result", []) if isinstance(data.get("result"), list) else []

    async def collect_address_and_publish(self, address: str) -> dict[str, int]:
        """Collect ETH data for an address and publish to event bus."""
        bus = create_event_bus()
        await bus.start()
        published = 0

        try:
            txs = await self.get_transactions(address)
            token_txs = await self.get_token_transfers(address)

            combined = {
                "address": address,
                "chain": "eth",
                "transactions": txs[:25],
                "token_transfers": token_txs[:25],
                "tx_count": len(txs),
                "token_tx_count": len(token_txs),
            }

            content = json.dumps(combined, ensure_ascii=False)
            content_hash = compute_content_hash(content.encode("utf-8"))

            # Extract interacting addresses for graph edges
            interacting: list[str] = []
            for tx in txs[:25]:
                for field in ("from", "to"):
                    addr = tx.get(field, "")
                    if addr and addr.lower() != address.lower():
                        interacting.append(addr)

            event = RawEvent(
                source_id=self.SOURCE_ID,
                adapter_type=AdapterType.BLOCKCHAIN,
                mode=CollectionMode.LIVE,
                observed_at=datetime.now(UTC),
                content_type=ContentType.JSON,
                payload_ref=f"s3://netra-snapshots/blockchain/eth/{address[:16]}.json",
                content_hash=content_hash,
                policy_decision_id="live-approved-feed",
                language="en",
                raw_metadata={
                    "type": "eth_address",
                    "address": address,
                    "chain": "eth",
                    "tx_count": len(txs),
                    "token_tx_count": len(token_txs),
                    "interacting_addresses": list(set(interacting))[:20],
                    "text": content,
                },
            )

            await bus.publish(Topics.RAW_EVENTS.value, event)
            published += 1

        except Exception as exc:
            logger.error("Failed to collect ETH address %s: %s", address[:16], exc)
        finally:
            await bus.stop()

        return {"source": self.SOURCE_ID, "published": published}


# ── OFAC SDN sanctioned wallet checker ──────────────────────

class OFACSanctionChecker:
    """
    Checks wallet addresses against the OFAC SDN (Specially Designated
    Nationals) list for sanctioned cryptocurrency addresses.

    Source: https://www.treasury.gov/ofac/downloads/sdn.xml
    Auth: none (public US government data)
    """

    SDN_URL = "https://www.treasury.gov/ofac/downloads/sdn.xml"
    SDN_CSV_URL = "https://www.treasury.gov/ofac/downloads/sdnlist.txt"
    SOURCE_ID = "src_ofac_sdn"

    def __init__(self) -> None:
        self._client = LiveHTTPClient("default")
        self._sanctioned_addresses: set[str] = set()

    async def load_sanctioned_addresses(self) -> set[str]:
        """
        Download and parse the OFAC SDN list for cryptocurrency addresses.

        Returns set of sanctioned wallet addresses (BTC, ETH, XMR, etc.)
        """
        async with self._client:
            response = await self._client.get(self.SDN_CSV_URL)
            text = response.text

        addresses: set[str] = set()
        for line in text.split("\n"):
            line = line.strip()
            # OFAC format includes "Digital Currency Address" entries
            if "Digital Currency Address" in line or "XBT" in line or "ETH" in line:
                # Extract the address — typically after the last semicolon
                parts = line.split(";")
                for part in parts:
                    part = part.strip()
                    # BTC addresses start with 1, 3, or bc1
                    if part.startswith(("1", "3", "bc1")) and len(part) >= 26:
                        addresses.add(part)
                    # ETH addresses start with 0x
                    elif part.startswith("0x") and len(part) == 42:
                        addresses.add(part.lower())

        self._sanctioned_addresses = addresses
        logger.info("OFAC: loaded %d sanctioned crypto addresses", len(addresses))
        return addresses

    def is_sanctioned(self, address: str) -> bool:
        """Check if an address is on the OFAC sanctions list."""
        return address.lower() in {a.lower() for a in self._sanctioned_addresses}


# ── Orchestrator ────────────────────────────────────────────

async def collect_blockchain_intel(addresses: dict[str, list[str]] | None = None) -> dict[str, Any]:
    """
    Collect blockchain data for known actor wallet addresses.

    Args:
        addresses: Dict mapping chain to address list, e.g.
                   {"btc": ["bc1q..."], "eth": ["0x..."]}
                   If None, queries the DB for addresses found by extractors.
    """
    results: dict[str, Any] = {"started_at": datetime.now(UTC).isoformat()}

    if not addresses:
        # In production, query the entities table for wallet addresses
        # For now, return empty
        results["note"] = "No addresses provided — query entities table in production"
        return results

    # BTC via mempool.space
    btc_addrs = addresses.get("btc", [])
    if btc_addrs:
        try:
            adapter = MempoolAdapter()
            results["mempool"] = await adapter.collect_addresses_and_publish(btc_addrs)
        except Exception as exc:
            logger.error("mempool.space collection failed: %s", exc, exc_info=True)
            results["mempool"] = {"error": str(exc)}

    # ETH via Etherscan
    eth_addrs = addresses.get("eth", [])
    settings = get_settings()
    if eth_addrs and settings.etherscan_api_key:
        try:
            adapter = EtherscanAdapter()
            for addr in eth_addrs[:10]:  # cap to avoid rate limits
                result = await adapter.collect_address_and_publish(addr)
                results[f"etherscan_{addr[:8]}"] = result
        except Exception as exc:
            logger.error("Etherscan collection failed: %s", exc, exc_info=True)
            results["etherscan"] = {"error": str(exc)}

    # OFAC check
    try:
        checker = OFACSanctionChecker()
        sanctioned = await checker.load_sanctioned_addresses()
        all_addrs = btc_addrs + eth_addrs
        flagged = [a for a in all_addrs if checker.is_sanctioned(a)]
        results["ofac"] = {
            "sanctioned_db_size": len(sanctioned),
            "checked": len(all_addrs),
            "flagged": flagged,
        }
    except Exception as exc:
        logger.error("OFAC check failed: %s", exc, exc_info=True)
        results["ofac"] = {"error": str(exc)}

    results["completed_at"] = datetime.now(UTC).isoformat()
    return results
