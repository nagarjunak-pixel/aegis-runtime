"""Tenant-isolated cosine-similarity semantic cache using signed feature hashing."""

from __future__ import annotations

import hashlib
import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

_WORD_RE = re.compile(r"[a-z0-9_]+")


def embed_text_signed_hash(text: str, dims: int = 192) -> tuple[float, ...]:
    """Compute L2-normalized signed feature-hashing embedding (Weinberger et al., 2009).

    Combines word unigrams, word bigrams, and character 4-grams so semantically
    near-identical enterprise queries achieve high cosine similarity in <0.2ms
    with zero external embedding API dependency.
    """
    normalized = text.lower().strip()
    words = _WORD_RE.findall(normalized)
    features: list[str] = [f"w:{w}" for w in words]
    for i in range(len(words) - 1):
        features.append(f"bg:{words[i]}_{words[i + 1]}")
    compact = " ".join(words)
    for i in range(max(0, len(compact) - 3)):
        features.append(f"c4:{compact[i : i + 4]}")

    vec = [0.0] * dims
    for feat in features:
        digest = hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest()
        h = int.from_bytes(digest, "little")
        bucket = h % dims
        sign = 1.0 if ((h >> 32) & 1) == 0 else -1.0
        vec[bucket] += sign

    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0.0:
        return tuple(vec)
    return tuple(v / norm for v in vec)


def cosine_similarity(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=True))


@dataclass(frozen=True, slots=True)
class _CacheItem:
    vector: tuple[float, ...]
    response_text: str
    model_id: str
    created_at: float


class SemanticVectorCache:
    """Strict tenant-partitioned semantic cache preventing cross-tenant prompt leakage."""

    def __init__(
        self,
        *,
        similarity_threshold: float = 0.90,
        ttl_seconds: float = 600.0,
        max_entries_per_tenant: int = 256,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._threshold = similarity_threshold
        self._ttl = ttl_seconds
        self._max_per_tenant = max_entries_per_tenant
        self._clock = clock
        self._lock = threading.RLock()
        self._store: dict[str, list[_CacheItem]] = {}
        self._hits = 0
        self._misses = 0

    def lookup(self, tenant_id: str, prompt: str) -> tuple[str, str, float] | None:
        now = self._clock()
        q_vec = embed_text_signed_hash(prompt)
        with self._lock:
            items = self._store.get(tenant_id, [])
            alive = [it for it in items if (now - it.created_at) <= self._ttl]
            self._store[tenant_id] = alive

            best_score = -1.0
            best_item: _CacheItem | None = None
            for it in alive:
                score = cosine_similarity(q_vec, it.vector)
                if score > best_score:
                    best_score = score
                    best_item = it

            if best_item is not None and best_score >= self._threshold:
                self._hits += 1
                return best_item.response_text, best_item.model_id, round(best_score, 4)

            self._misses += 1
            return None

    def store(self, tenant_id: str, prompt: str, response_text: str, model_id: str) -> None:
        vec = embed_text_signed_hash(prompt)
        now = self._clock()
        with self._lock:
            bucket = self._store.setdefault(tenant_id, [])
            bucket.append(
                _CacheItem(
                    vector=vec,
                    response_text=response_text,
                    model_id=model_id,
                    created_at=now,
                )
            )
            if len(bucket) > self._max_per_tenant:
                del bucket[0 : len(bucket) - self._max_per_tenant]

    @property
    def stats(self) -> dict[str, float]:
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total) if total > 0 else 0.0
            return {
                "hits": float(self._hits),
                "misses": float(self._misses),
                "hit_rate": round(hit_rate, 4),
            }
