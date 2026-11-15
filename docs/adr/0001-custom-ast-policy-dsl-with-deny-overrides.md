# ADR-0001: Custom `.aegis` AST Policy DSL with Deny-Overrides Semantics

- **Status**: Accepted
- **Date**: 2026-11

## Context

Autonomous agents invoking enterprise ERP and financial tools require deterministic, sub-millisecond authorization before executing side effects. Relying on "LLM-as-a-Judge" guardrails for SOX Segregation of Duties or spend caps is non-deterministic, vulnerable to prompt injection, and adds 300–1,000ms of tail latency per step. Conversely, using Python `eval()` on dynamic rule expressions introduces arbitrary code execution risks (`__subclasses__` sandbox escapes).

## Options Considered

1. **Prompt-Based LLM Guardrails**: Probabilistic (<99.9%), high latency, non-reproducible. Rejected.
2. **Restricted Python `eval()`**: Trivial to implement, catastrophic blast radius if policy authors or dynamic expressions access Python object internals. Rejected.
3. **External Sidecar Daemon (OPA/Rego over gRPC)**: Strong semantics, but adds IPC serialization hops and operational complexity for embedded agent workers.
4. **Custom In-Process `.aegis` Lexer + Recursive-Descent AST Compiler (`src/aegis/policy/`)**: Inspired by AWS Cedar (`permit`/`forbid` blocks, explicit namespace whitelisting, Deny-Overrides conflict resolution).

## Decision

We implemented a dedicated lexer (`lexer.py`), recursive-descent compiler (`parser.py`), and side-effect-free evaluator (`evaluator.py`) for `.aegis` policies:
- Only three root attribute namespaces (`principal`, `action`, `context`) are grammar-valid; any `__` dunder token is rejected at lex time.
- Conflict resolution follows **Deny-Overrides with Implicit Default-Deny**: if any `forbid` rule matches, the verdict is `DENY` regardless of matching `permit` rules; if zero `permit` rules match, the verdict is `DENY`.
- Every evaluation emits a full `RuleEvaluationTrace` tuple and completes in **29 µs median (`p99 < 90 µs`)**.

## Consequences

- **Positive**: Deterministic, auditable, sub-100µs overhead, zero external daemon required, immune to code-execution escapes.
- **Negative / Trade-off**: Intentionally Turing-incomplete (no loops, recursion, or external network lookups inside rules); enrichment attributes (`vendor_country`) must be hydrated into `context` before evaluation.
