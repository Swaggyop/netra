"""
Tests for entity extractors — must achieve ≥ 95% on labelled fixtures (M3 acceptance).
"""

from __future__ import annotations

from backend.app.extraction.extractors import (
    EntityHit,
    extract_all,
    extract_contact_ids,
    extract_domains,
    extract_emails,
    extract_handles,
    extract_ipv4,
    extract_onions,
    extract_pgp,
    extract_wallets,
)


# ── PGP ──────────────────────────────────────────────────────

class TestPGPExtractor:
    def test_contiguous_40_hex(self):
        text = "My PGP: ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"
        hits = extract_pgp(text)
        assert len(hits) == 1
        assert hits[0].normalized == "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"

    def test_spaced_fingerprint(self):
        text = "PGP: ABCD 1234 ABCD 1234 ABCD 1234 ABCD 1234 ABCD 1234"
        hits = extract_pgp(text)
        assert len(hits) >= 1
        assert "ABCD1234" in hits[0].normalized

    def test_lowercase_hex(self):
        fp = "abcd1234abcd1234abcd1234abcd1234abcd1234"
        text = f"PGP: {fp}"
        hits = extract_pgp(text)
        assert len(hits) >= 1
        assert any(h.normalized == fp.upper() for h in hits)

    def test_armored_block_detected(self):
        text = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey data here\n-----END PGP PUBLIC KEY BLOCK-----"
        hits = extract_pgp(text)
        assert any(h.metadata.get("type") == "armored_block" for h in hits)

    def test_no_false_positive_on_short_hex(self):
        text = "The hash is ABCD1234"
        hits = extract_pgp(text)
        assert len(hits) == 0


# ── Wallets ──────────────────────────────────────────────────

class TestWalletExtractor:
    def test_btc_bech32(self):
        text = "Send to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        hits = extract_wallets(text)
        assert len(hits) == 1
        assert hits[0].metadata["currency"] == "BTC"

    def test_btc_legacy(self):
        text = "BTC: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        hits = extract_wallets(text)
        assert any(h.metadata["currency"] == "BTC" for h in hits)

    def test_eth_address(self):
        text = "ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD38"
        hits = extract_wallets(text)
        assert len(hits) == 1
        assert hits[0].metadata["currency"] == "ETH"
        assert hits[0].normalized.startswith("0x")

    def test_tron_address(self):
        text = "USDT TRC20: TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW"
        hits = extract_wallets(text)
        assert any(h.metadata["currency"] == "TRON" for h in hits)

    def test_xmr_tagged_untraceable(self):
        chars = "4" + "A" * 94
        text = f"XMR: {chars}"
        hits = extract_wallets(text)
        xmr_hits = [h for h in hits if h.metadata.get("currency") == "XMR"]
        assert len(xmr_hits) == 1
        assert xmr_hits[0].metadata.get("traceable") is False

    def test_no_false_positive(self):
        text = "The temperature is 0x42 degrees."
        hits = extract_wallets(text)
        # 0x42 is only 2 hex chars, not 40
        eth_hits = [h for h in hits if h.metadata.get("currency") == "ETH"]
        assert len(eth_hits) == 0


# ── Emails ───────────────────────────────────────────────────

class TestEmailExtractor:
    def test_simple_email(self):
        text = "Contact me at user@example.com"
        hits = extract_emails(text)
        assert len(hits) == 1
        assert hits[0].normalized == "user@example.com"

    def test_protonmail(self):
        text = "Reach: dealer@protonmail.com"
        hits = extract_emails(text)
        assert len(hits) == 1
        assert "protonmail" in hits[0].normalized

    def test_multiple_emails(self):
        text = "Main: a@b.com, Alt: c@d.org"
        hits = extract_emails(text)
        assert len(hits) == 2


# ── Onion v3 ─────────────────────────────────────────────────

class TestOnionExtractor:
    def test_valid_onion_v3(self):
        addr = "a" * 56 + ".onion"
        text = f"Visit {addr}"
        hits = extract_onions(text)
        assert len(hits) == 1
        assert hits[0].normalized == addr

    def test_no_v2_onion(self):
        addr = "a" * 16 + ".onion"  # v2 is 16 chars
        text = f"Old site: {addr}"
        hits = extract_onions(text)
        assert len(hits) == 0  # v2 should not match


# ── Contact IDs ──────────────────────────────────────────────

class TestContactExtractor:
    def test_telegram_handle(self):
        text = "DM me @darkvendor42"
        hits = extract_contact_ids(text)
        assert len(hits) == 1
        assert hits[0].metadata["platform"] == "telegram"

    def test_jabber_jid(self):
        text = "XMPP: user123@jabber.server.im"
        hits = extract_contact_ids(text)
        assert len(hits) == 1
        assert hits[0].metadata["platform"] == "xmpp"

    def test_session_id(self):
        sid = "05" + "a1" * 32  # 05 + 64 hex
        text = f"Session: {sid}"
        hits = extract_contact_ids(text)
        assert len(hits) == 1
        assert hits[0].metadata["platform"] == "session"

    def test_wickr_id(self):
        text = "Wickr: mywickrid"
        hits = extract_contact_ids(text)
        assert len(hits) == 1
        assert hits[0].metadata["platform"] == "wickr"


# ── IPv4 ─────────────────────────────────────────────────────

class TestIPv4Extractor:
    def test_valid_ip(self):
        text = "Server at 192.168.1.100"
        hits = extract_ipv4(text)
        assert len(hits) == 1

    def test_no_false_positive(self):
        text = "Version 1.2.3"
        hits = extract_ipv4(text)
        assert len(hits) == 0  # not a valid IP


# ── Handles ──────────────────────────────────────────────────

class TestHandleExtractor:
    def test_from_metadata(self):
        hits = extract_handles("post text", {"handle": "ShadowX"})
        assert len(hits) == 1
        assert hits[0].normalized == "shadowx"

    def test_from_signature(self):
        text = "Great product, recommended.\n-- DarkVendor"
        hits = extract_handles(text)
        assert any(h.normalized == "darkvendor" for h in hits)

    def test_regards_signature(self):
        text = "Thank you for your business.\nRegards, CryptoKing"
        hits = extract_handles(text)
        assert any(h.normalized == "cryptoking" for h in hits)


# ── Master pipeline ──────────────────────────────────────────

class TestExtractAll:
    def test_mixed_content(self):
        text = (
            "Selling Item-1042. Contact @darkvendor or darkvendor@protonmail.com. "
            "BTC: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq. "
            "PGP: ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"
        )
        hits = extract_all(text)
        kinds = {h.kind for h in hits}
        assert "wallet" in kinds
        assert "email" in kinds
        assert "pgp" in kinds
        assert "contact_id" in kinds

    def test_deduplication(self):
        text = "BTC: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq and again bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        hits = extract_all(text)
        wallet_hits = [h for h in hits if h.kind == "wallet"]
        assert len(wallet_hits) == 1

    def test_empty_text(self):
        hits = extract_all("")
        assert hits == []

    def test_no_false_positives_normal_text(self):
        text = "The weather today is sunny and warm. Temperature is 72 degrees."
        hits = extract_all(text)
        # Should have no or very few false hits
        assert len(hits) <= 1
