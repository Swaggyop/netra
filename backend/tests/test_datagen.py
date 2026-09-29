"""
Tests for the synthetic data generator.

Verifies determinism, ground truth structure, and data integrity.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from datagen.generate import generate_dataset


class TestDataGenerator:
    def test_deterministic_with_seed(self):
        """Same seed → same data."""
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            generate_dataset(seed=42, n_actors=5, n_posts_per_actor=3, output_dir=d1)
            generate_dataset(seed=42, n_actors=5, n_posts_per_actor=3, output_dir=d2)

            for filename in ["actors.json", "posts.json", "truth.json"]:
                with open(Path(d1) / filename) as f1, open(Path(d2) / filename) as f2:
                    assert json.load(f1) == json.load(f2), f"{filename} differs across runs"

    def test_generates_all_files(self):
        """All expected output files are created."""
        with tempfile.TemporaryDirectory() as d:
            generate_dataset(seed=1, n_actors=5, n_posts_per_actor=2, output_dir=d)
            expected = ["actors.json", "posts.json", "transactions.json", "truth.json", "markets.json"]
            for f in expected:
                assert (Path(d) / f).exists(), f"{f} not found"

    def test_rebrand_pairs_in_truth(self):
        """Ground truth contains rebrand pairs with required fields."""
        with tempfile.TemporaryDirectory() as d:
            generate_dataset(seed=42, n_actors=10, n_rebrand_pairs=2, output_dir=d)
            with open(Path(d) / "truth.json") as f:
                truth = json.load(f)

            pairs = truth["rebrand_pairs"]
            assert len(pairs) >= 1
            for pair in pairs:
                assert "old_actor_id" in pair
                assert "new_actor_id" in pair
                assert "difficulty" in pair

    def test_decoys_exist(self):
        """Decoy pairs exist and are marked should_link=False."""
        with tempfile.TemporaryDirectory() as d:
            generate_dataset(seed=42, n_actors=10, n_decoys=2, output_dir=d)
            with open(Path(d) / "truth.json") as f:
                truth = json.load(f)

            decoys = truth["decoy_pairs"]
            assert len(decoys) >= 1
            for decoy in decoys:
                assert decoy["should_link"] is False

    def test_posts_have_required_fields(self):
        """Every post has the required fields."""
        with tempfile.TemporaryDirectory() as d:
            generate_dataset(seed=42, n_actors=5, n_posts_per_actor=3, output_dir=d)
            with open(Path(d) / "posts.json") as f:
                posts = json.load(f)

            assert len(posts) > 0
            for post in posts:
                assert "post_id" in post
                assert "actor_id" in post
                assert "handle" in post
                assert "text" in post
                assert "posted_at" in post
                assert len(post["text"]) > 0

    def test_no_real_illegal_content(self):
        """Posts contain only neutral item placeholders."""
        with tempfile.TemporaryDirectory() as d:
            generate_dataset(seed=42, n_actors=5, n_posts_per_actor=5, output_dir=d)
            with open(Path(d) / "posts.json") as f:
                posts = json.load(f)

            for post in posts:
                text = post["text"].lower()
                # Check for neutral items pattern
                # Should not contain real illicit substance names
                assert "cocaine" not in text
                assert "heroin" not in text
                assert "fentanyl" not in text

    def test_actors_have_wallets_and_pgp(self):
        """Actors have at least basic identifiers."""
        with tempfile.TemporaryDirectory() as d:
            generate_dataset(seed=42, n_actors=5, output_dir=d)
            with open(Path(d) / "actors.json") as f:
                actors = json.load(f)

            for actor in actors:
                assert "pgp_fingerprint" in actor
                assert len(actor["pgp_fingerprint"]) == 40
                assert "wallets" in actor
                assert "BTC" in actor["wallets"]
