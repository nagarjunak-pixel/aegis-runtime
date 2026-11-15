"""3-state sliding-window failure circuit breaker for downstream LLM & MCP endpoints."""

from __future__ import annotations

import collections
import threading
import time
from collections.abc import Callable
from enum import StrEnum


class CircuitState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreaker:
    """Thread-safe 3-state circuit breaker (CLOSED -> OPEN -> HALF_OPEN -> CLOSED)."""

    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        window_seconds: float = 30.0,
        recovery_timeout_seconds: float = 10.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._failure_threshold = failure_threshold
        self._window_seconds = window_seconds
        self._recovery_timeout = recovery_timeout_seconds
        self._clock = clock
        self._lock = threading.RLock()
        self._state = CircuitState.CLOSED
        self._failure_timestamps: collections.deque[float] = collections.deque()
        self._opened_at: float = 0.0
        self._half_open_probe_in_flight = False

    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._check_transition()
            return self._state

    def allow_request(self) -> bool:
        with self._lock:
            self._check_transition()
            if self._state == CircuitState.CLOSED:
                return True
            if self._state == CircuitState.HALF_OPEN and not self._half_open_probe_in_flight:
                self._half_open_probe_in_flight = True
                return True
            return False

    def record_success(self) -> None:
        with self._lock:
            self._failure_timestamps.clear()
            self._state = CircuitState.CLOSED
            self._half_open_probe_in_flight = False

    def record_failure(self) -> None:
        now = self._clock()
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._opened_at = now
                self._half_open_probe_in_flight = False
                return

            self._prune_old_failures(now)
            self._failure_timestamps.append(now)
            if len(self._failure_timestamps) >= self._failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = now

    def _check_transition(self) -> None:
        now = self._clock()
        if self._state == CircuitState.OPEN and (now - self._opened_at) >= self._recovery_timeout:
            self._state = CircuitState.HALF_OPEN
            self._half_open_probe_in_flight = False

    def _prune_old_failures(self, now: float) -> None:
        cutoff = now - self._window_seconds
        while self._failure_timestamps and self._failure_timestamps[0] < cutoff:
            self._failure_timestamps.popleft()
