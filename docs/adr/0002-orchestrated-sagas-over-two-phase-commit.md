# ADR-0002: Orchestrated Sagas & Quarantine Isolation Over Two-Phase Commit (2PC)

- **Status**: Accepted
- **Date**: 2026-11

## Context

Enterprise agent workflows routinely span heterogeneous systems—SAP Inventory ATP, Procurement Purchase Orders, Freight Carrier APIs, and SWIFT/SEPA Treasury Gateways. Holding distributed XA / Two-Phase Commit (2PC) database locks across multi-hundred-millisecond REST/MCP calls or human dual-control pauses causes severe lock contention, head-of-line blocking, and is unsupported by most external SaaS/ERP APIs.

## Decision

We adopted **Orchestrated Sagas** (`src/aegis/saga/coordinator.py`) with four hard engineering guarantees:
1. **Content-Addressed Idempotency (`IdempotencyStore`)**: Every step derives `idem_<sha256>` over `(tenant_id, workflow_id, step_name, tool_name, sanitized_params)`, ensuring transient HTTP 503 retries never double-deduct inventory or double-encumber budgets.
2. **Pre-Step Policy Mediation with Partial-Saga Rollback**: If Step $i > 1$ is denied by policy (e.g., dynamic discovery that a vendor is in an OFAC-sanctioned country), Steps $i-1 \dots 1$ are automatically compensated in reverse topological order before returning `BLOCKED_BY_POLICY`.
3. **Exact Integer Cents Accounting**: Financial state uses integer cents (`_usd_to_cents`) rather than IEEE-754 float accumulation, guaranteeing exact zero-drift conservation (`available + encumbered + settled == initial_allocation`).
4. **Explicit `QUARANTINED` Terminal State**: If a compensating action itself exhausts bounded retries, the coordinator transitions the workflow to `QUARANTINED` and logs `SAGA_COMPENSATION_FAILED` rather than silently masking orphaned state.

## Consequences

- **Positive**: High concurrency, zero cross-service lock holding, verified `0` orphan mutations under 25% chaos fault injection.
- **Negative / Trade-off**: Isolation is *ACD* (no strict *I*solation—intermediate encumbered states are briefly visible as `ENCUMBERED` / `RESERVED` prior to compensation, requiring explicit reservation semantics in ERP tables).
