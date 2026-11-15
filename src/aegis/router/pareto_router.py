"""Pareto-optimal Multi-Model FinOps Router with cascade fallback and circuit breaking."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aegis.router.circuit_breaker import CircuitBreaker
from aegis.router.rate_limiter import TenantTokenBucketLimiter
from aegis.router.semantic_cache import SemanticVectorCache


class ModelEndpointProfile(BaseModel):
    """Cost, latency SLO, and reasoning capability profile for a candidate LLM endpoint."""

    model_config = ConfigDict(frozen=True)

    model_id: str
    provider: str
    input_cost_per_1k_usd: float
    output_cost_per_1k_usd: float
    p95_latency_ms: float
    quality_score: float = Field(ge=0.0, le=1.0)
    supports_structured_tools: bool = True


DEFAULT_MODEL_FLEET: tuple[ModelEndpointProfile, ...] = (
    ModelEndpointProfile(
        model_id="gemini-2.5-flash",
        provider="google",
        input_cost_per_1k_usd=0.00015,
        output_cost_per_1k_usd=0.00060,
        p95_latency_ms=340.0,
        quality_score=0.88,
    ),
    ModelEndpointProfile(
        model_id="gpt-4.1-mini",
        provider="openai",
        input_cost_per_1k_usd=0.00040,
        output_cost_per_1k_usd=0.00160,
        p95_latency_ms=420.0,
        quality_score=0.89,
    ),
    ModelEndpointProfile(
        model_id="gemini-2.5-pro",
        provider="google",
        input_cost_per_1k_usd=0.00125,
        output_cost_per_1k_usd=0.00500,
        p95_latency_ms=920.0,
        quality_score=0.97,
    ),
    ModelEndpointProfile(
        model_id="claude-sonnet-4",
        provider="anthropic",
        input_cost_per_1k_usd=0.00300,
        output_cost_per_1k_usd=0.01500,
        p95_latency_ms=1050.0,
        quality_score=0.98,
    ),
    ModelEndpointProfile(
        model_id="vllm-llama-3.3-70b-int8",
        provider="internal-onprem",
        input_cost_per_1k_usd=0.00008,
        output_cost_per_1k_usd=0.00020,
        p95_latency_ms=280.0,
        quality_score=0.84,
    ),
)


@dataclass(frozen=True, slots=True)
class RoutingRequest:
    tenant_id: str
    prompt: str
    estimated_input_tokens: int = 600
    estimated_output_tokens: int = 300
    min_quality_score: float = 0.85
    max_latency_ms: float = 2500.0
    cost_weight: float = 0.40
    latency_weight: float = 0.25
    quality_weight: float = 0.35
    bypass_cache: bool = False


class RoutingDecision(BaseModel):
    """Auditable FinOps routing verdict including Pareto frontier & cascade metadata."""

    model_config = ConfigDict(frozen=True)

    selected_model_id: str
    provider: str
    estimated_cost_usd: float
    expected_p95_latency_ms: float
    quality_score: float
    cache_hit: bool = False
    cache_similarity: float = 0.0
    pareto_frontier_models: tuple[str, ...]
    cascade_attempts: tuple[str, ...]
    response_text: str


def compute_pareto_frontier(
    candidates: list[tuple[ModelEndpointProfile, float]],
) -> list[tuple[ModelEndpointProfile, float]]:
    """Filter out dominated endpoints across (minimize cost, minimize latency, maximize quality)."""
    non_dominated: list[tuple[ModelEndpointProfile, float]] = []
    for cand, cand_cost in candidates:
        dominated = False
        for other, other_cost in candidates:
            if other.model_id == cand.model_id:
                continue
            no_worse = (
                other_cost <= cand_cost
                and other.p95_latency_ms <= cand.p95_latency_ms
                and other.quality_score >= cand.quality_score
            )
            strictly_better = (
                other_cost < cand_cost
                or other.p95_latency_ms < cand.p95_latency_ms
                or other.quality_score > cand.quality_score
            )
            if no_worse and strictly_better:
                dominated = True
                break
        if not dominated:
            non_dominated.append((cand, cand_cost))
    return non_dominated


class ParetoModelRouter:
    """Multi-objective FinOps model router with semantic cache, circuit breakers & cascade."""

    def __init__(
        self,
        *,
        fleet: tuple[ModelEndpointProfile, ...] = DEFAULT_MODEL_FLEET,
        limiter: TenantTokenBucketLimiter | None = None,
        cache: SemanticVectorCache | None = None,
        simulator_fn: Callable[[ModelEndpointProfile, str], str] | None = None,
    ) -> None:
        self._fleet = fleet
        self._limiter = limiter or TenantTokenBucketLimiter()
        self._cache = cache or SemanticVectorCache()
        self._breakers: dict[str, CircuitBreaker] = {m.model_id: CircuitBreaker() for m in fleet}
        self._simulator_fn = simulator_fn or self._default_simulator

    @property
    def cache(self) -> SemanticVectorCache:
        return self._cache

    @property
    def limiter(self) -> TenantTokenBucketLimiter:
        return self._limiter

    def breaker_for(self, model_id: str) -> CircuitBreaker:
        return self._breakers[model_id]

    def route_and_invoke(self, req: RoutingRequest) -> RoutingDecision:
        if not req.bypass_cache:
            cached = self._cache.lookup(req.tenant_id, req.prompt)
            if cached is not None:
                resp_text, cached_model, sim = cached
                return RoutingDecision(
                    selected_model_id=cached_model,
                    provider="semantic-cache",
                    estimated_cost_usd=0.0,
                    expected_p95_latency_ms=0.2,
                    quality_score=1.0,
                    cache_hit=True,
                    cache_similarity=sim,
                    pareto_frontier_models=(cached_model,),
                    cascade_attempts=(cached_model,),
                    response_text=resp_text,
                )

        eligible: list[tuple[ModelEndpointProfile, float]] = []
        for m in self._fleet:
            if m.quality_score < req.min_quality_score:
                continue
            if m.p95_latency_ms > req.max_latency_ms:
                continue
            if not self._breakers[m.model_id].allow_request():
                continue
            est_cost = (req.estimated_input_tokens / 1000.0) * m.input_cost_per_1k_usd + (
                req.estimated_output_tokens / 1000.0
            ) * m.output_cost_per_1k_usd
            eligible.append((m, est_cost))

        if not eligible:
            raise RuntimeError(
                "No healthy model endpoints satisfy SLO & CircuitBreaker constraints"
            )

        frontier = compute_pareto_frontier(eligible)
        ranked = self._rank_candidates(eligible, req)
        frontier_ids = tuple(m.model_id for m, _ in frontier)

        total_tokens = req.estimated_input_tokens + req.estimated_output_tokens
        attempted: list[str] = []
        last_err: Exception | None = None

        for profile, est_cost in ranked:
            attempted.append(profile.model_id)
            self._limiter.acquire(req.tenant_id, total_tokens, est_cost)
            try:
                output_text = self._simulator_fn(profile, req.prompt)
                self._breakers[profile.model_id].record_success()
                self._cache.store(req.tenant_id, req.prompt, output_text, profile.model_id)
                return RoutingDecision(
                    selected_model_id=profile.model_id,
                    provider=profile.provider,
                    estimated_cost_usd=round(est_cost, 6),
                    expected_p95_latency_ms=profile.p95_latency_ms,
                    quality_score=profile.quality_score,
                    cache_hit=False,
                    cache_similarity=0.0,
                    pareto_frontier_models=frontier_ids,
                    cascade_attempts=tuple(attempted),
                    response_text=output_text,
                )
            except Exception as exc:
                last_err = exc
                self._breakers[profile.model_id].record_failure()
                continue

        raise RuntimeError(f"All cascade endpoints failed; last error: {last_err}")

    @staticmethod
    def _rank_candidates(
        candidates: list[tuple[ModelEndpointProfile, float]],
        req: RoutingRequest,
    ) -> list[tuple[ModelEndpointProfile, float]]:
        max_cost = max(c for _, c in candidates) or 1e-9
        max_lat = max(m.p95_latency_ms for m, _ in candidates) or 1.0

        def _score(item: tuple[ModelEndpointProfile, float]) -> float:
            m, cost = item
            norm_cost = cost / max_cost
            norm_lat = m.p95_latency_ms / max_lat
            # Lower objective score is better
            return (
                req.cost_weight * norm_cost
                + req.latency_weight * norm_lat
                - req.quality_weight * m.quality_score
            )

        return sorted(candidates, key=_score)

    @staticmethod
    def _default_simulator(profile: ModelEndpointProfile, prompt: str) -> str:
        summary = prompt.strip().splitlines()[0][:96]
        return f"[{profile.model_id}] Verified structured plan generated for: {summary}"

    def fleet_snapshot(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for m in self._fleet:
            data = m.model_dump()
            data["circuit_state"] = self._breakers[m.model_id].state.value
            out.append(data)
        return out
