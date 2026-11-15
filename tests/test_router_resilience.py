"""Unit tests for CircuitBreaker, Token-Bucket Limiter, Semantic Cache & Pareto Router."""

from __future__ import annotations

import pytest

from aegis.router.circuit_breaker import CircuitBreaker, CircuitState
from aegis.router.pareto_router import (
    ModelEndpointProfile,
    ParetoModelRouter,
    RoutingRequest,
    compute_pareto_frontier,
)
from aegis.router.rate_limiter import QuotaExceededError, TenantTokenBucketLimiter
from aegis.router.semantic_cache import SemanticVectorCache


def test_circuit_breaker_full_state_machine() -> None:
    now = [100.0]
    cb = CircuitBreaker(
        failure_threshold=2,
        window_seconds=10.0,
        recovery_timeout_seconds=5.0,
        clock=lambda: now[0],
    )
    assert cb.state == CircuitState.CLOSED
    assert cb.allow_request()

    cb.record_failure()
    assert cb.state == CircuitState.CLOSED
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert not cb.allow_request()

    # Advance past recovery timeout -> HALF_OPEN allows exactly one probe
    now[0] += 6.0
    assert cb.state == CircuitState.HALF_OPEN
    assert cb.allow_request()
    assert not cb.allow_request()  # Second concurrent probe blocked

    # Failed probe re-opens circuit immediately
    cb.record_failure()
    assert cb.state == CircuitState.OPEN

    # Next recovery probe succeeds -> returns to CLOSED
    now[0] += 6.0
    assert cb.allow_request()
    cb.record_success()
    assert cb.state == CircuitState.CLOSED


def test_token_bucket_rate_limit_and_finops_budget_ceiling() -> None:
    now = [0.0]
    limiter = TenantTokenBucketLimiter(
        capacity_tokens=1000.0,
        refill_tokens_per_sec=100.0,
        max_tenant_budget_usd=1.00,
        clock=lambda: now[0],
    )
    limiter.acquire("tenant-1", 800, 0.40)
    with pytest.raises(QuotaExceededError, match="rate limit"):
        limiter.acquire("tenant-1", 300, 0.10)

    # Advance 5 seconds -> refills 500 tokens
    now[0] += 5.0
    limiter.acquire("tenant-1", 300, 0.50)
    assert limiter.tenant_spend_usd("tenant-1") == pytest.approx(0.90)

    with pytest.raises(QuotaExceededError, match="budget ceiling"):
        limiter.acquire("tenant-1", 50, 0.20)


def test_semantic_cache_hit_and_tenant_isolation() -> None:
    now = [10.0]
    cache = SemanticVectorCache(
        similarity_threshold=0.85,
        ttl_seconds=60.0,
        clock=lambda: now[0],
    )
    prompt = "Reserve 120 units of MAT-CHIP-7NM in Munich plant PLANT-DE-01"
    cache.store("tenant-A", prompt, "cached-plan-A", "gemini-2.5-flash")

    hit = cache.lookup("tenant-A", "Reserve 120 units of MAT-CHIP-7NM in Munich plant PLANT-DE-01!")
    assert hit is not None
    assert hit[0] == "cached-plan-A"

    # Tenant B must NEVER see Tenant A's cached prompt
    assert cache.lookup("tenant-B", prompt) is None

    # Advance beyond TTL -> expires cleanly
    now[0] += 120.0
    assert cache.lookup("tenant-A", prompt) is None


def test_pareto_frontier_eliminates_dominated_models_and_cascades_on_failure() -> None:
    fast_cheap_good = ModelEndpointProfile(
        model_id="m-pareto-1",
        provider="p1",
        input_cost_per_1k_usd=0.0002,
        output_cost_per_1k_usd=0.0004,
        p95_latency_ms=300.0,
        quality_score=0.92,
    )
    dominated = ModelEndpointProfile(
        model_id="m-dominated",
        provider="p2",
        input_cost_per_1k_usd=0.0020,
        output_cost_per_1k_usd=0.0040,
        p95_latency_ms=900.0,
        quality_score=0.88,
    )
    frontier = compute_pareto_frontier([(fast_cheap_good, 0.001), (dominated, 0.010)])
    assert [m.model_id for m, _ in frontier] == ["m-pareto-1"]

    calls: list[str] = []

    def _flaky_sim(profile: ModelEndpointProfile, _prompt: str) -> str:
        calls.append(profile.model_id)
        if profile.model_id == "m-pareto-1":
            raise RuntimeError("Primary regional endpoint 503")
        return "cascade-ok"

    router = ParetoModelRouter(fleet=(fast_cheap_good, dominated), simulator_fn=_flaky_sim)
    decision = router.route_and_invoke(
        RoutingRequest(tenant_id="t-1", prompt="Plan procurement", min_quality_score=0.80)
    )
    assert decision.selected_model_id == "m-dominated"
    assert decision.cascade_attempts == ("m-pareto-1", "m-dominated")
    assert decision.response_text == "cascade-ok"
