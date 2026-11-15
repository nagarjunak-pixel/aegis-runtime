"""Hierarchical tenant Token-Bucket rate limiter and FinOps USD budget ledger."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


class QuotaExceededError(RuntimeError):
    """Raised when a tenant exceeds token-rate admission or cumulative USD budget."""


@dataclass
class _TenantBucket:
    tokens: float
    last_refill: float
    cumulative_spend_usd: float = 0.0


class TenantTokenBucketLimiter:
    """Enforces continuous token-bucket admission rate AND hard FinOps USD spend ceilings."""

    def __init__(
        self,
        *,
        capacity_tokens: float = 50_000.0,
        refill_tokens_per_sec: float = 5_000.0,
        max_tenant_budget_usd: float = 100.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._capacity = capacity_tokens
        self._refill_rate = refill_tokens_per_sec
        self._max_budget_usd = max_tenant_budget_usd
        self._clock = clock
        self._lock = threading.RLock()
        self._buckets: dict[str, _TenantBucket] = {}

    def acquire(
        self, tenant_id: str, estimated_tokens: int, estimated_cost_usd: float = 0.0
    ) -> None:
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(tenant_id)
            if bucket is None:
                bucket = _TenantBucket(tokens=self._capacity, last_refill=now)
                self._buckets[tenant_id] = bucket
            else:
                elapsed = max(0.0, now - bucket.last_refill)
                bucket.tokens = min(self._capacity, bucket.tokens + elapsed * self._refill_rate)
                bucket.last_refill = now

            if bucket.cumulative_spend_usd + estimated_cost_usd > self._max_budget_usd:
                raise QuotaExceededError(
                    f"FinOps budget ceiling exceeded for tenant '{tenant_id}': "
                    f"${bucket.cumulative_spend_usd + estimated_cost_usd:.4f} > ${self._max_budget_usd:.2f}"
                )

            if estimated_tokens > bucket.tokens:
                raise QuotaExceededError(
                    f"Token-bucket rate limit exceeded for tenant '{tenant_id}': "
                    f"requested {estimated_tokens} tokens, available {bucket.tokens:.0f}"
                )

            bucket.tokens -= float(estimated_tokens)
            bucket.cumulative_spend_usd += estimated_cost_usd

    def tenant_spend_usd(self, tenant_id: str) -> float:
        with self._lock:
            b = self._buckets.get(tenant_id)
            return round(b.cumulative_spend_usd, 6) if b else 0.0
