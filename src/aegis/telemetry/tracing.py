"""OpenTelemetry tracer integration with ring-buffer span inspection & Prometheus exposition."""

from __future__ import annotations

import collections
import threading
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from pydantic import BaseModel, ConfigDict


class SpanSnapshot(BaseModel):
    """Serializable W3C span record for observability APIs and UI waterfall rendering."""

    model_config = ConfigDict(frozen=True)

    trace_id: str
    span_id: str
    name: str
    duration_ms: float
    attributes: dict[str, Any]
    status: str


class TelemetryCollector:
    """Unified OpenTelemetry span emitter and Prometheus metrics registry."""

    def __init__(self, service_name: str = "aegis-runtime", max_spans: int = 500) -> None:
        self._lock = threading.RLock()
        self._provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        self._tracer: trace.Tracer = self._provider.get_tracer(service_name)
        self._recent_spans: collections.deque[SpanSnapshot] = collections.deque(maxlen=max_spans)
        self._counters: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = {}

    @contextmanager
    def span(
        self,
        name: str,
        attributes: Mapping[str, Any] | None = None,
    ) -> Iterator[None]:
        attrs = dict(attributes or {})
        t0 = time.perf_counter()
        status_label = "OK"
        with self._tracer.start_as_current_span(name) as otel_span:
            for k, v in attrs.items():
                if isinstance(v, (str, bool, int, float)):
                    otel_span.set_attribute(k, v)
            ctx = otel_span.get_span_context()
            trace_hex = f"{ctx.trace_id:032x}" if ctx.trace_id else uuid.uuid4().hex
            span_hex = f"{ctx.span_id:016x}" if ctx.span_id else uuid.uuid4().hex[:16]
            try:
                yield
            except Exception as exc:
                status_label = f"ERROR:{type(exc).__name__}"
                otel_span.record_exception(exc)
                raise
            finally:
                dur_ms = round((time.perf_counter() - t0) * 1000.0, 3)
                snap = SpanSnapshot(
                    trace_id=trace_hex,
                    span_id=span_hex,
                    name=name,
                    duration_ms=dur_ms,
                    attributes=attrs,
                    status=status_label,
                )
                with self._lock:
                    self._recent_spans.append(snap)
                    self._histograms.setdefault(name, []).append(dur_ms)

    def increment_counter(self, metric_name: str, delta: float = 1.0) -> None:
        with self._lock:
            self._counters[metric_name] = self._counters.get(metric_name, 0.0) + delta

    def recent_spans(self, limit: int = 100) -> list[SpanSnapshot]:
        with self._lock:
            items = list(self._recent_spans)
        return items[-limit:]

    def render_prometheus_metrics(self) -> str:
        """Render counters and latency summaries in Prometheus text exposition format."""
        lines: list[str] = [
            "# HELP aegis_spans_recorded_total Total traced spans recorded in ring buffer",
            "# TYPE aegis_spans_recorded_total gauge",
        ]
        with self._lock:
            lines.append(f"aegis_spans_recorded_total {len(self._recent_spans)}")
            for metric, val in sorted(self._counters.items()):
                lines.append(f"{metric} {val}")
            for span_name, samples in sorted(self._histograms.items()):
                safe = span_name.replace(".", "_")
                count = len(samples)
                total = round(sum(samples), 4)
                lines.append(f"{safe}_duration_ms_count {count}")
                lines.append(f"{safe}_duration_ms_sum {total}")
        return "\n".join(lines) + "\n"
