"""
NETRA — Stylometry baseline models (§9).

Implements S1–S4 from the plan.  S5 (fine-tuned SBERT) is stretch.

| ID | Model                                              |
|----|-----------------------------------------------------|
| S1 | Character n-grams (3–5) TF-IDF + cosine             |
| S2 | Word n-grams (1–2) TF-IDF + cosine                  |
| S3 | Function-word freq + punctuation + length → LogReg   |
| S4 | SBERT embeddings (all-MiniLM-L6-v2) cosine           |

Each model exposes:
  - fit(texts_by_author: dict[str, list[str]]) → trains on labelled texts
  - similarity(text_a: str, text_b: str) → float (0–1)
  - get_embedding(text: str) → list[float]  (for storage / downstream)
"""

from __future__ import annotations

import logging
import re
import string
from abc import ABC, abstractmethod
from collections import Counter
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


# ── Feature helpers ──────────────────────────────────────────

FUNCTION_WORDS = frozenset({
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "as", "is", "was", "are", "were", "been",
    "be", "have", "has", "had", "do", "does", "did", "will", "would",
    "could", "should", "may", "might", "shall", "can", "need", "must",
    "i", "you", "he", "she", "it", "we", "they", "me", "him", "her",
    "us", "them", "my", "your", "his", "its", "our", "their",
    "this", "that", "these", "those", "not", "no", "if", "then",
})

MIN_TEXT_LENGTH = 100  # characters — below this, stylometry is unreliable


def compute_function_word_features(text: str) -> dict[str, float]:
    """Compute relative frequencies of function words."""
    words = text.lower().split()
    total = len(words) or 1
    features = {}
    for fw in FUNCTION_WORDS:
        features[f"fw_{fw}"] = words.count(fw) / total
    return features


def compute_punctuation_features(text: str) -> dict[str, float]:
    """Compute punctuation usage features."""
    total = len(text) or 1
    features = {}
    for char in ".,!?;:-'\"()[]{}":
        features[f"punct_{char}"] = text.count(char) / total

    # Exclamation/question density
    features["excl_density"] = text.count("!") / total
    features["quest_density"] = text.count("?") / total
    features["ellipsis_count"] = text.count("...") / total

    return features


def compute_length_features(text: str) -> dict[str, float]:
    """Compute text length and structure features."""
    words = text.split()
    sentences = re.split(r"[.!?]+", text)
    sentences = [s.strip() for s in sentences if s.strip()]

    word_lengths = [len(w) for w in words] if words else [0]
    sent_lengths = [len(s.split()) for s in sentences] if sentences else [0]

    return {
        "avg_word_length": np.mean(word_lengths),
        "std_word_length": np.std(word_lengths),
        "avg_sentence_length": np.mean(sent_lengths),
        "std_sentence_length": np.std(sent_lengths),
        "vocabulary_richness": len(set(w.lower() for w in words)) / (len(words) or 1),
        "uppercase_ratio": sum(1 for c in text if c.isupper()) / (len(text) or 1),
        "digit_ratio": sum(1 for c in text if c.isdigit()) / (len(text) or 1),
    }


def extract_style_features(text: str) -> dict[str, float]:
    """Extract all stylometric features from text."""
    features: dict[str, float] = {}
    features.update(compute_function_word_features(text))
    features.update(compute_punctuation_features(text))
    features.update(compute_length_features(text))
    return features


# ── Base model ───────────────────────────────────────────────

class StylometryModel(ABC):
    """Abstract base for stylometry models."""

    model_id: str
    model_name: str

    @abstractmethod
    def fit(self, texts_by_author: dict[str, list[str]]) -> None:
        """Train on labelled texts."""
        ...

    @abstractmethod
    def similarity(self, text_a: str, text_b: str) -> float:
        """Compute similarity between two texts (0–1)."""
        ...

    @abstractmethod
    def get_embedding(self, text: str) -> list[float]:
        """Get a feature/embedding vector for storage."""
        ...

    def is_sufficient(self, text: str) -> bool:
        """Check if text is long enough for reliable analysis."""
        return len(text) >= MIN_TEXT_LENGTH


# ── S1: Character n-grams TF-IDF ────────────────────────────

class CharNgramModel(StylometryModel):
    """S1: Character n-grams (3–5) TF-IDF + cosine similarity."""

    model_id = "S1"
    model_name = "Character N-grams (3-5) TF-IDF"

    def __init__(self) -> None:
        self._vectorizer = None

    def fit(self, texts_by_author: dict[str, list[str]]) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        all_texts = [t for texts in texts_by_author.values() for t in texts]
        self._vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            max_features=5000,
        )
        self._vectorizer.fit(all_texts)

    def similarity(self, text_a: str, text_b: str) -> float:
        if self._vectorizer is None:
            raise RuntimeError("Model not fitted")
        from sklearn.metrics.pairwise import cosine_similarity
        vecs = self._vectorizer.transform([text_a, text_b])
        return float(cosine_similarity(vecs[0:1], vecs[1:2])[0][0])

    def get_embedding(self, text: str) -> list[float]:
        if self._vectorizer is None:
            raise RuntimeError("Model not fitted")
        vec = self._vectorizer.transform([text])
        return vec.toarray()[0].tolist()


# ── S2: Word n-grams TF-IDF ─────────────────────────────────

class WordNgramModel(StylometryModel):
    """S2: Word n-grams (1–2) TF-IDF + cosine similarity."""

    model_id = "S2"
    model_name = "Word N-grams (1-2) TF-IDF"

    def __init__(self) -> None:
        self._vectorizer = None

    def fit(self, texts_by_author: dict[str, list[str]]) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        all_texts = [t for texts in texts_by_author.values() for t in texts]
        self._vectorizer = TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            max_features=5000,
            stop_words="english",
        )
        self._vectorizer.fit(all_texts)

    def similarity(self, text_a: str, text_b: str) -> float:
        if self._vectorizer is None:
            raise RuntimeError("Model not fitted")
        from sklearn.metrics.pairwise import cosine_similarity
        vecs = self._vectorizer.transform([text_a, text_b])
        return float(cosine_similarity(vecs[0:1], vecs[1:2])[0][0])

    def get_embedding(self, text: str) -> list[float]:
        if self._vectorizer is None:
            raise RuntimeError("Model not fitted")
        vec = self._vectorizer.transform([text])
        return vec.toarray()[0].tolist()


# ── S3: Function words + punctuation → LogisticRegression ────

class FunctionWordModel(StylometryModel):
    """S3: Function-word frequency + punctuation + length → logistic regression on pair features."""

    model_id = "S3"
    model_name = "Function Words + Punctuation Features"

    def __init__(self) -> None:
        self._scaler = None

    def fit(self, texts_by_author: dict[str, list[str]]) -> None:
        from sklearn.preprocessing import StandardScaler
        all_features = []
        for texts in texts_by_author.values():
            for text in texts:
                features = extract_style_features(text)
                all_features.append(list(features.values()))

        self._scaler = StandardScaler()
        self._scaler.fit(all_features)

    def similarity(self, text_a: str, text_b: str) -> float:
        feat_a = np.array(list(extract_style_features(text_a).values()))
        feat_b = np.array(list(extract_style_features(text_b).values()))

        if self._scaler:
            feat_a = self._scaler.transform([feat_a])[0]
            feat_b = self._scaler.transform([feat_b])[0]

        # Cosine similarity on feature vectors
        dot = np.dot(feat_a, feat_b)
        norm = np.linalg.norm(feat_a) * np.linalg.norm(feat_b)
        if norm == 0:
            return 0.0
        return float(max(0, dot / norm))

    def get_embedding(self, text: str) -> list[float]:
        features = extract_style_features(text)
        vec = list(features.values())
        if self._scaler:
            vec = self._scaler.transform([vec])[0].tolist()
        return vec


# ── S4: SBERT embeddings ────────────────────────────────────

class SBERTModel(StylometryModel):
    """S4: Sentence-Transformer embeddings (all-MiniLM-L6-v2) cosine similarity."""

    model_id = "S4"
    model_name = "SBERT Embeddings (all-MiniLM-L6-v2)"

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        self._model_name = model_name
        self._model = None

    def _load_model(self) -> None:
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer(self._model_name)
                logger.info("SBERT model loaded: %s", self._model_name)
            except ImportError:
                raise RuntimeError(
                    "sentence-transformers not installed. "
                    "Install with: pip install sentence-transformers"
                )

    def fit(self, texts_by_author: dict[str, list[str]]) -> None:
        self._load_model()
        # SBERT doesn't need fitting for basic similarity
        # S5 (stretch) would fine-tune with contrastive loss

    def similarity(self, text_a: str, text_b: str) -> float:
        self._load_model()
        from sentence_transformers import util
        emb_a = self._model.encode(text_a, convert_to_tensor=True)
        emb_b = self._model.encode(text_b, convert_to_tensor=True)
        return float(util.cos_sim(emb_a, emb_b)[0][0])

    def get_embedding(self, text: str) -> list[float]:
        self._load_model()
        return self._model.encode(text).tolist()


# ── Model registry ───────────────────────────────────────────

MODELS: dict[str, type[StylometryModel]] = {
    "S1": CharNgramModel,
    "S2": WordNgramModel,
    "S3": FunctionWordModel,
    "S4": SBERTModel,
}


def get_model(model_id: str) -> StylometryModel:
    """Instantiate a stylometry model by ID."""
    cls = MODELS.get(model_id)
    if cls is None:
        raise ValueError(f"Unknown model: {model_id}. Available: {list(MODELS.keys())}")
    return cls()
