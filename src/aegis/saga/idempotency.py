"""Content-addressed idempotency registry guaranteeing exactly-once ERP side effects."""

from __future__ import annotations

import copy
import threading
from typing import Any


class IdempotencyStore:
    """Thread-safe idempotency cache keyed by `(tenant_id, idempotency_key)`."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[tuple[str, str], dict[str, Any]] = {}

    def get(self, tenant_id: str, idempotency_key: str) -> dict[str, Any] | None:
        with self._lock:
            val = self._entries.get((tenant_id, idempotency_key))
            return copy.deepcopy(val) if val is not None else None

    def put(self, tenant_id: str, idempotency_key: str, result: dict[str, Any]) -> None:
        with self._lock:
            self._entries[(tenant_id, idempotency_key)] = copy.deepcopy(result)

    def clear_for_compensation(self, tenant_id: str, idempotency_key: str) -> None:
        with self._lock:
            self._entries.pop((tenant_id, idempotency_key), None)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._entries)
