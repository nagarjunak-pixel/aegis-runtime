# ADR-0005: Pareto-Optimal Multi-Model Routing & Signed Feature-Hashing Cache

- **Status**: Accepted
- **Date**: 2026-11

## Context

Routing every enterprise agent step to a frontier reasoning model wastes 60–80% of token spend and inflates tail latency, while static model pinning creates single-provider outage fragility. Furthermore, semantic prompt caches that call an external embedding API add 80–200ms network latency and risk cross-tenant cache poisoning if shared globally.

## Decision

`ParetoModelRouter` (`src/aegis/router/`) implements a 4-stage pipeline:
1. **Tenant-Partitioned Signed Feature-Hashing Semantic Cache (`semantic_cache.py`)**: Computes 192-dimensional L2-normalized vectors over word unigrams, bigrams, and character 4-grams using signed `BLAKE2b` feature hashing (Weinberger et al., 2009) in `<0.2 ms` with zero network calls and strict `tenant_id` key isolation.
2. **SLO & Circuit-Breaker Pruning**: Filters out endpoints failing `min_quality_score`, `max_latency_ms`, or currently `OPEN` in their 3-state sliding-window `CircuitBreaker`.
3. **Pareto Dominance Filtering & Scalarization**: Computes the non-dominated Pareto frontier over `(minimize cost, minimize p95 latency, maximize quality)` and ranks candidates via normalized weighted scalarization, cascading automatically on transient provider failures.
4. **Token-Bucket & USD Ceiling Admission (`rate_limiter.py`)**: Enforces both token-per-second burst protection and cumulative tenant FinOps spend caps.

## Consequences

- **Positive**: Zero-dependency sub-millisecond semantic caching, automatic provider failover, strict FinOps budget enforcement.
- **Negative / Trade-off**: Lexical/n-gram feature hashing captures near-duplicate operational queries (`similarity >= 0.90`) rather than deep cross-lingual paraphrases (by design, reducing false-positive cache collisions in financial workflows).
