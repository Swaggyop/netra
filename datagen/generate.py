"""
NETRA — Synthetic data generator (§13).

Generates realistic dark-web marketplace data with ground truth
for testing entity resolution, stylometry, and the rebrand detector.

Usage:
    python -m datagen.generate --seed 42 --output datagen/output
    python -m datagen.generate --scenario datagen/scenarios/rebrand_basic.yaml

Outputs:
    - markets.json       — synthetic marketplace definitions
    - actors.json        — actors with identifiers, wallets, keys
    - posts.json         — forum/marketplace posts with persona-specific text
    - transactions.json  — wallet transaction sets
    - truth.json         — ground truth: rebrand pairs, decoys, clusters

Hard rules:
    - No real person data. No real illegal listing content.
    - Market items are neutral placeholders (e.g., "Item-1042").
    - Text is generated from templates + persona style profiles.
    - Deterministic with --seed flag.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import string
import uuid
from dataclasses import dataclass, field, asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


# ── Persona style profiles ───────────────────────────────────

@dataclass
class PersonaStyle:
    """Text generation profile for a synthetic actor."""
    name: str
    vocabulary_level: str       # "basic" | "moderate" | "advanced"
    avg_sentence_length: int    # words
    punctuation_style: str      # "minimal" | "normal" | "heavy"
    capitalization: str         # "normal" | "all_lower" | "all_caps" | "mixed"
    typo_rate: float            # 0.0–0.15
    uses_abbreviations: bool
    uses_emoji: bool
    language_mix: str           # "en" | "hinglish" | "mixed"
    greeting_style: str         # "none" | "casual" | "formal"
    signature_pattern: str | None  # e.g., "-- {handle}" or None


PERSONA_PROFILES: list[PersonaStyle] = [
    PersonaStyle("formal_en", "advanced", 15, "normal", "normal", 0.02, False, False, "en", "formal", "-- {handle}"),
    PersonaStyle("casual_en", "basic", 8, "minimal", "all_lower", 0.08, True, True, "en", "casual", None),
    PersonaStyle("technical", "advanced", 12, "heavy", "normal", 0.01, False, False, "en", "none", "pgp: {pgp_short}"),
    PersonaStyle("hinglish_casual", "moderate", 10, "minimal", "mixed", 0.06, True, True, "hinglish", "casual", None),
    PersonaStyle("terse", "basic", 5, "minimal", "all_lower", 0.1, True, False, "en", "none", None),
    PersonaStyle("verbose_formal", "advanced", 20, "heavy", "normal", 0.02, False, False, "en", "formal", "Regards, {handle}"),
    PersonaStyle("mixed_lang", "moderate", 10, "normal", "normal", 0.05, True, False, "mixed", "casual", None),
    PersonaStyle("aggressive", "basic", 6, "heavy", "all_caps", 0.12, True, True, "en", "none", None),
]


# ── Templates for post generation ────────────────────────────

LISTING_TEMPLATES = [
    "Selling {item}. Price: {price} {currency}. {quality} quality. Ships within {days}d. Contact: {contact}",
    "NEW STOCK: {item} available now. {price}{currency}. Bulk discounts. {contact}",
    "{item} - tested and verified. {price} {currency}. Escrow accepted. DM {contact}",
    "Fresh {item} in stock. Best {quality} on the market. {price}{currency}. {contact}",
    "Premium {item}. {quality} grade. Price negotiable from {price}{currency}. Reach: {contact}",
]

FORUM_TEMPLATES = [
    "Has anyone tried {vendor}'s {item}? Looking for reviews before ordering.",
    "Warning: {vendor} is a scammer. Lost {price}{currency}. Avoid!",
    "Vouching for {vendor}. Great {item}, fast shipping, {quality} quality.",
    "Looking for a reliable vendor for {item}. Budget around {price}{currency}.",
    "Market update: new listings on {market}. Check out {vendor} for {item}.",
    "PSA: {market} going down for maintenance. Use {alt_market} in the meantime.",
    "Anyone know if {vendor} moved to {alt_market}? Can't find their profile.",
    "Just received my order from {vendor}. {item} was exactly as described.",
    "New vendor here. Offering {item} at competitive prices. PGP verified.",
    "Escrow dispute with {vendor} on {market}. Need moderator help.",
]

# Hinglish templates
HINGLISH_TEMPLATES = [
    "Bhai {vendor} ka {item} try karo, mast quality hai. {price}{currency} mein mil jayega.",
    "Koi {vendor} ke baare mein jaanta hai? Reviews nahi mil rahe.",
    "Warning: {vendor} scammer hai. {price}{currency} dooba. Mat lo.",
    "Naya stock aaya hai {item} ka. Best price {price}{currency}. Contact karo {contact}.",
    "{market} pe naya vendor hun. {item} available hai. Escrow accept karta hun.",
]

NEUTRAL_ITEMS = [
    "Item-1042", "Product-A7", "Package-Delta", "Bundle-X9", "Widget-Pro",
    "Module-K3", "Component-R2", "Kit-Sigma", "Unit-7B", "Sample-Y4",
    "Device-M8", "Tool-Z1", "Part-Q6", "Element-V5", "Pack-W3",
]

QUALITY_LABELS = ["standard", "premium", "verified", "tested", "certified"]
CURRENCIES = ["BTC", "XMR", "USDT", "ETH"]
MARKETS = ["AlphaMarket", "BetaBazaar", "GammaGate", "DeltaDen", "SigmaShop"]

# ── Data generation ──────────────────────────────────────────

def _generate_pgp_fingerprint(rng: random.Random) -> str:
    """Generate a fake 40-hex PGP fingerprint."""
    return "".join(rng.choices("0123456789ABCDEF", k=40))


def _generate_btc_address(rng: random.Random) -> str:
    """Generate a fake Bitcoin address (bech32-like)."""
    chars = string.ascii_lowercase + string.digits
    suffix = "".join(rng.choices(chars, k=38))
    return f"bc1q{suffix}"


def _generate_eth_address(rng: random.Random) -> str:
    """Generate a fake Ethereum address."""
    return "0x" + "".join(rng.choices("0123456789abcdef", k=40))


def _generate_xmr_address(rng: random.Random) -> str:
    """Generate a fake Monero address (95 chars, starts with 4)."""
    chars = string.ascii_letters + string.digits
    return "4" + "".join(rng.choices(chars, k=94))


def _generate_onion_v3(rng: random.Random) -> str:
    """Generate a fake .onion v3 address (56 chars)."""
    chars = string.ascii_lowercase + "234567"
    return "".join(rng.choices(chars, k=56)) + ".onion"


def _generate_handle(rng: random.Random) -> str:
    """Generate a fake handle."""
    prefixes = ["Shadow", "Dark", "Crypto", "Ghost", "Phantom", "Silent", "Storm",
                "Night", "Cyber", "Zero", "Neo", "Stealth", "Black", "Deep", "Rogue"]
    suffixes = ["X", "Wolf", "Hawk", "Fox", "Byte", "Node", "Crypt", "Null",
                "Void", "Core", "King", "Lord", "Master", "Runner", "Blade"]
    num = rng.choice(["", str(rng.randint(1, 999)), "_" + str(rng.randint(10, 99))])
    return rng.choice(prefixes) + rng.choice(suffixes) + num


def _generate_contact_id(rng: random.Random) -> str:
    """Generate a fake contact ID (Telegram-style or Jabber)."""
    kind = rng.choice(["telegram", "jabber", "session"])
    if kind == "telegram":
        return f"@{''.join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(5, 15)))}"
    elif kind == "jabber":
        user = "".join(rng.choices(string.ascii_lowercase, k=rng.randint(5, 10)))
        return f"{user}@jabber.{''.join(rng.choices(string.ascii_lowercase, k=5))}.im"
    else:
        return "05" + "".join(rng.choices("0123456789abcdef", k=64))


def _apply_typos(text: str, rate: float, rng: random.Random) -> str:
    """Introduce random typos at the given rate."""
    if rate <= 0:
        return text
    chars = list(text)
    for i in range(len(chars)):
        if rng.random() < rate and chars[i].isalpha():
            chars[i] = rng.choice(string.ascii_lowercase)
    return "".join(chars)


def _apply_style(text: str, style: PersonaStyle, rng: random.Random) -> str:
    """Apply persona style transformations to text."""
    result = text

    # Capitalization
    if style.capitalization == "all_lower":
        result = result.lower()
    elif style.capitalization == "all_caps":
        result = result.upper()

    # Abbreviations
    if style.uses_abbreviations:
        result = result.replace("you", "u").replace("are", "r").replace("please", "pls")
        result = result.replace("message", "msg").replace("because", "cuz")

    # Typos
    result = _apply_typos(result, style.typo_rate, rng)

    return result


def _generate_post_text(
    style: PersonaStyle,
    actor_handle: str,
    actor_pgp: str,
    actor_contact: str,
    rng: random.Random,
) -> str:
    """Generate a forum/marketplace post with persona-specific styling."""
    # Choose template source based on language mix
    if style.language_mix == "hinglish":
        templates = HINGLISH_TEMPLATES + FORUM_TEMPLATES[:3]
    elif style.language_mix == "mixed":
        templates = FORUM_TEMPLATES + HINGLISH_TEMPLATES[:2]
    else:
        templates = LISTING_TEMPLATES + FORUM_TEMPLATES

    template = rng.choice(templates)

    # Fill template
    text = template.format(
        item=rng.choice(NEUTRAL_ITEMS),
        price=str(rng.randint(10, 5000)),
        currency=rng.choice(CURRENCIES),
        quality=rng.choice(QUALITY_LABELS),
        days=rng.randint(1, 14),
        contact=actor_contact,
        vendor=_generate_handle(rng),
        market=rng.choice(MARKETS),
        alt_market=rng.choice(MARKETS),
        pgp_short=actor_pgp[:16],
    )

    # Apply style
    text = _apply_style(text, style, rng)

    # Add greeting
    if style.greeting_style == "casual":
        text = rng.choice(["yo ", "hey ", "sup ", "hi "]) + text
    elif style.greeting_style == "formal":
        text = rng.choice(["Greetings. ", "Hello. ", "Dear community, "]) + text

    # Add signature
    if style.signature_pattern:
        sig = style.signature_pattern.format(
            handle=actor_handle,
            pgp_short=actor_pgp[:16],
        )
        text += f"\n{sig}"

    return text


@dataclass
class SyntheticActor:
    """A generated synthetic actor with all identifiers."""
    actor_id: str
    handle: str
    alt_handles: list[str]
    pgp_fingerprint: str
    wallets: dict[str, list[str]]   # currency → addresses
    contact_ids: list[str]
    email: str | None
    onion: str | None
    style_profile: str
    category: str
    markets: list[str]
    timezone_offset: int            # hours from UTC
    active_hours: list[int]         # typical hours of activity
    first_seen: str
    last_seen: str
    is_dormant: bool = False
    dormant_since: str | None = None


@dataclass
class SyntheticPost:
    """A generated forum/marketplace post."""
    post_id: str
    actor_id: str
    handle: str
    market: str
    text: str
    posted_at: str
    language: str


@dataclass
class SyntheticTransaction:
    """A generated wallet transaction."""
    tx_id: str
    from_address: str
    to_address: str
    amount: float
    currency: str
    timestamp: str
    from_actor: str | None = None
    to_actor: str | None = None


@dataclass
class GroundTruth:
    """Ground truth for evaluation."""
    rebrand_pairs: list[dict[str, str]]
    decoy_pairs: list[dict[str, str]]
    wallet_clusters: list[dict[str, Any]]
    actor_entity_map: dict[str, list[str]]  # actor_id → entity_ids


def generate_dataset(
    seed: int = 42,
    n_actors: int = 20,
    n_markets: int = 5,
    n_rebrand_pairs: int = 3,
    n_decoys: int = 3,
    n_posts_per_actor: int = 15,
    n_transactions: int = 50,
    time_span_days: int = 180,
    output_dir: str = "datagen/output",
) -> dict[str, Any]:
    """
    Generate a complete synthetic dataset.

    Returns paths to generated files.
    """
    rng = random.Random(seed)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    start_date = datetime(2025, 6, 1, tzinfo=UTC)
    end_date = start_date + timedelta(days=time_span_days)

    markets = MARKETS[:n_markets]
    actors: list[SyntheticActor] = []
    posts: list[SyntheticPost] = []
    transactions: list[SyntheticTransaction] = []

    # ── Generate actors ──────────────────────────────────────
    used_handles: set[str] = set()
    style_assignments: list[PersonaStyle] = []

    for i in range(n_actors):
        handle = _generate_handle(rng)
        while handle in used_handles:
            handle = _generate_handle(rng)
        used_handles.add(handle)

        style = PERSONA_PROFILES[i % len(PERSONA_PROFILES)]
        style_assignments.append(style)

        # Alt handles (slight variations)
        alt_handles = []
        if rng.random() < 0.4:
            alt = handle.lower() + str(rng.randint(1, 99))
            alt_handles.append(alt)
            used_handles.add(alt)

        pgp = _generate_pgp_fingerprint(rng)
        btc_addrs = [_generate_btc_address(rng) for _ in range(rng.randint(1, 3))]
        eth_addrs = [_generate_eth_address(rng)] if rng.random() < 0.5 else []
        xmr_addrs = [_generate_xmr_address(rng)] if rng.random() < 0.3 else []
        contacts = [_generate_contact_id(rng) for _ in range(rng.randint(1, 2))]

        tz = rng.choice([-5, -4, 0, 1, 2, 3, 5, 5, 8, 9])  # weighted toward IST
        active_hours = list(range(rng.randint(8, 14), rng.randint(20, 24)))

        first_seen = start_date + timedelta(days=rng.randint(0, time_span_days // 2))
        last_seen = first_seen + timedelta(days=rng.randint(30, time_span_days // 2))

        actor = SyntheticActor(
            actor_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"actor_{seed}_{i}")),
            handle=handle,
            alt_handles=alt_handles,
            pgp_fingerprint=pgp,
            wallets={"BTC": btc_addrs, "ETH": eth_addrs, "XMR": xmr_addrs},
            contact_ids=contacts,
            email=f"{handle.lower()}@protonmail.com" if rng.random() < 0.5 else None,
            onion=_generate_onion_v3(rng) if rng.random() < 0.3 else None,
            style_profile=style.name,
            category=rng.choice(["vendor", "buyer", "admin", "unknown"]),
            markets=rng.sample(markets, k=rng.randint(1, min(3, len(markets)))),
            timezone_offset=tz,
            active_hours=active_hours,
            first_seen=first_seen.isoformat(),
            last_seen=last_seen.isoformat(),
        )
        actors.append(actor)

    # ── Generate rebrand pairs ───────────────────────────────
    rebrand_pairs: list[dict[str, str]] = []
    rebrand_actor_indices = rng.sample(range(n_actors), k=min(n_rebrand_pairs * 2, n_actors))

    for pair_idx in range(min(n_rebrand_pairs, len(rebrand_actor_indices) // 2)):
        old_idx = rebrand_actor_indices[pair_idx * 2]
        new_idx = rebrand_actor_indices[pair_idx * 2 + 1]
        old_actor = actors[old_idx]
        new_actor = actors[new_idx]

        # Make old actor dormant
        dormant_date = datetime.fromisoformat(old_actor.first_seen) + timedelta(
            days=rng.randint(30, 60)
        )
        old_actor.is_dormant = True
        old_actor.dormant_since = dormant_date.isoformat()
        old_actor.last_seen = dormant_date.isoformat()

        # New actor appears after dormancy
        new_first = dormant_date + timedelta(days=rng.randint(7, 30))
        new_actor.first_seen = new_first.isoformat()

        difficulty = "easy" if pair_idx == 0 else ("hard" if pair_idx == n_rebrand_pairs - 1 else "medium")

        if difficulty in ("easy", "medium"):
            # Share PGP key
            new_actor.pgp_fingerprint = old_actor.pgp_fingerprint
        if difficulty == "easy":
            # Share wallets and contact
            new_actor.wallets["BTC"] = old_actor.wallets["BTC"]
            if old_actor.contact_ids:
                new_actor.contact_ids = old_actor.contact_ids

        # Same style profile for rebrands
        style_assignments[new_idx] = style_assignments[old_idx]
        new_actor.style_profile = old_actor.style_profile

        rebrand_pairs.append({
            "old_actor_id": old_actor.actor_id,
            "new_actor_id": new_actor.actor_id,
            "old_handle": old_actor.handle,
            "new_handle": new_actor.handle,
            "difficulty": difficulty,
            "shared_evidence": ["pgp"] if difficulty != "hard" else ["stylometry"],
        })

    # ── Generate decoy pairs (look-alikes that are NOT the same person) ──
    decoy_pairs: list[dict[str, str]] = []
    remaining = [i for i in range(n_actors) if i not in rebrand_actor_indices]

    for d in range(min(n_decoys, len(remaining) // 2)):
        idx_a = remaining[d * 2]
        idx_b = remaining[d * 2 + 1]
        a = actors[idx_a]
        b = actors[idx_b]

        # Same category and overlapping markets but different identifiers
        b.category = a.category
        b.markets = a.markets

        decoy_pairs.append({
            "actor_a_id": a.actor_id,
            "actor_b_id": b.actor_id,
            "handle_a": a.handle,
            "handle_b": b.handle,
            "should_link": False,
            "reason": "Same category/market but different identifiers and style",
        })

    # ── Generate posts ───────────────────────────────────────
    for actor_idx, actor in enumerate(actors):
        style = style_assignments[actor_idx]
        first = datetime.fromisoformat(actor.first_seen)
        last = datetime.fromisoformat(actor.last_seen)
        span = max(1, (last - first).days)

        for p in range(n_posts_per_actor):
            day_offset = rng.randint(0, span)
            hour = rng.choice(actor.active_hours) if actor.active_hours else rng.randint(0, 23)
            posted_at = first + timedelta(days=day_offset, hours=hour, minutes=rng.randint(0, 59))

            text = _generate_post_text(
                style, actor.handle, actor.pgp_fingerprint,
                actor.contact_ids[0] if actor.contact_ids else actor.handle,
                rng,
            )

            # Occasionally include PGP fingerprint or wallet in post
            if rng.random() < 0.2:
                text += f"\n\nPGP: {actor.pgp_fingerprint}"
            if rng.random() < 0.15 and actor.wallets["BTC"]:
                text += f"\n\nBTC: {actor.wallets['BTC'][0]}"

            lang = "hi" if style.language_mix == "hinglish" else "en"

            posts.append(SyntheticPost(
                post_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"post_{seed}_{actor_idx}_{p}")),
                actor_id=actor.actor_id,
                handle=rng.choice([actor.handle] + actor.alt_handles) if actor.alt_handles and rng.random() < 0.3 else actor.handle,
                market=rng.choice(actor.markets),
                text=text,
                posted_at=posted_at.isoformat(),
                language=lang,
            ))

    # ── Generate transactions ────────────────────────────────
    actors_with_btc = [a for a in actors if a.wallets.get("BTC")]
    for t in range(n_transactions):
        sender = rng.choice(actors_with_btc)
        receiver = rng.choice(actors_with_btc)
        if sender.actor_id == receiver.actor_id:
            continue

        tx_time = start_date + timedelta(
            days=rng.randint(0, time_span_days),
            hours=rng.randint(0, 23),
        )

        transactions.append(SyntheticTransaction(
            tx_id=hashlib.sha256(f"tx_{seed}_{t}".encode()).hexdigest()[:64],
            from_address=rng.choice(sender.wallets["BTC"]),
            to_address=rng.choice(receiver.wallets["BTC"]),
            amount=round(rng.uniform(0.001, 2.0), 8),
            currency="BTC",
            timestamp=tx_time.isoformat(),
            from_actor=sender.actor_id,
            to_actor=receiver.actor_id,
        ))

    # ── Build ground truth ───────────────────────────────────
    wallet_clusters: list[dict[str, Any]] = []
    for actor in actors:
        if len(actor.wallets.get("BTC", [])) > 1:
            wallet_clusters.append({
                "cluster_id": f"cluster_{actor.actor_id[:8]}",
                "addresses": actor.wallets["BTC"],
                "actor_id": actor.actor_id,
            })

    actor_entity_map: dict[str, list[str]] = {}
    for actor in actors:
        entities = [actor.handle] + actor.alt_handles
        entities.append(f"pgp:{actor.pgp_fingerprint}")
        for currency, addrs in actor.wallets.items():
            entities.extend(f"{currency}:{a}" for a in addrs)
        entities.extend(actor.contact_ids)
        if actor.email:
            entities.append(actor.email)
        if actor.onion:
            entities.append(actor.onion)
        actor_entity_map[actor.actor_id] = entities

    truth = GroundTruth(
        rebrand_pairs=rebrand_pairs,
        decoy_pairs=decoy_pairs,
        wallet_clusters=wallet_clusters,
        actor_entity_map=actor_entity_map,
    )

    # ── Write files ──────────────────────────────────────────
    def _write(name: str, data: Any) -> str:
        path = out / name
        with open(path, "w") as f:
            if hasattr(data, "__dataclass_fields__"):
                json.dump(asdict(data), f, indent=2, default=str)
            elif isinstance(data, list) and data and hasattr(data[0], "__dataclass_fields__"):
                json.dump([asdict(d) for d in data], f, indent=2, default=str)
            else:
                json.dump(data, f, indent=2, default=str)
        return str(path)

    files = {
        "markets": _write("markets.json", {"markets": markets}),
        "actors": _write("actors.json", actors),
        "posts": _write("posts.json", posts),
        "transactions": _write("transactions.json", transactions),
        "truth": _write("truth.json", truth),
    }

    print(f"Generated dataset with seed={seed}:")
    print(f"  Actors: {len(actors)}")
    print(f"  Posts: {len(posts)}")
    print(f"  Transactions: {len(transactions)}")
    print(f"  Rebrand pairs: {len(rebrand_pairs)}")
    print(f"  Decoy pairs: {len(decoy_pairs)}")
    print(f"  Files: {', '.join(files.values())}")

    return files


# ── CLI entry point ──────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="NETRA synthetic data generator")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--actors", type=int, default=20, help="Number of actors")
    parser.add_argument("--posts-per-actor", type=int, default=15, help="Posts per actor")
    parser.add_argument("--rebrand-pairs", type=int, default=3, help="Number of rebrand pairs")
    parser.add_argument("--decoys", type=int, default=3, help="Number of decoy pairs")
    parser.add_argument("--transactions", type=int, default=50, help="Number of transactions")
    parser.add_argument("--output", type=str, default="datagen/output", help="Output directory")
    args = parser.parse_args()

    generate_dataset(
        seed=args.seed,
        n_actors=args.actors,
        n_posts_per_actor=args.posts_per_actor,
        n_rebrand_pairs=args.rebrand_pairs,
        n_decoys=args.decoys,
        n_transactions=args.transactions,
        output_dir=args.output,
    )


if __name__ == "__main__":
    main()
