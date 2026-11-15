# AegisRuntime — System Architecture & Execution Lifecycles

## 1. Layered Control-Plane Topology

`AegisRuntime` enforces a strict separation between **probabilistic planning** (LLMs routed via `ParetoModelRouter`) and **deterministic state mutation** (governed by `PolicyEngine`, `TaintAnalyzer`, `PIITokenVault`, `SagaCoordinator`, and `EventLedger`).

```mermaid
sequenceDiagram
    autonumber
    participant Caller as Principal / Agent
    participant Vault as AES-256-GCM PII Vault
    participant Router as Pareto FinOps Router
    participant Saga as SagaCoordinator
    participant Policy as .aegis AST + Taint Gate
    participant ERP as Enterprise MCP (.erp)
    participant Ledger as SHA-256 + Ed25519 Ledger

    Caller->>Vault: Submit Prompt + Tool Saga (raw IBAN/Email)
    Vault-->>Caller: HMAC-SHA256 Surrogate Tokens [PII:IBAN:...]
    Caller->>Router: Route sanitized prompt under (Cost, p95, Quality) SLO
    Router-->>Ledger: Append MODEL_ROUTED
    Caller->>Saga: Execute Multi-Step SagaDefinition

    loop For Step i = 1..k
        Saga->>Policy: Evaluate(Principal, ActionIntent, DynamicContext)
        Policy-->>Ledger: Append POLICY_EVALUATED (latency_us + trace)
        alt Verdict == PERMIT
            Saga->>Vault: Detokenize strictly for *.erp target_domain
            Saga->>ERP: Forward RPC (Idempotency Key + Timeout + Retry)
            alt Downstream Fault on Step i
                ERP-->>Saga: HTTP 503 / PermanentStepError
                Saga-->>Ledger: Append SAGA_STEP_FAILED
                loop Reverse Compensation j = i-1 down to 1
                    Saga->>ERP: Compensate Step j
                    Saga-->>Ledger: Append SAGA_STEP_COMPENSATED
                end
            else Step Succeeded
                ERP-->>Saga: Mutation Receipt
                Saga-->>Ledger: Append SAGA_STEP_EXECUTED (redacted PII)
            end
        else Verdict == DENY
            Saga->>Saga: Trigger reverse compensation for steps 1..i-1
        end
    end
    Saga-->>Ledger: Append WORKFLOW_COMPLETED
```

## 2. Saga State Machine

```mermaid
stateDiagram-v2
    [*] --> PENDING
    PENDING --> EXECUTING: WORKFLOW_STARTED
    EXECUTING --> COMMITTED: All k steps PERMITTED & SUCCEEDED
    EXECUTING --> BLOCKED_BY_POLICY: Step 1 DENIED (0 prior mutations)
    EXECUTING --> COMPENSATING: Step i > 1 DENIED or FAILED
    COMPENSATING --> BLOCKED_BY_POLICY: Policy block & steps i-1..1 rolled back
    COMPENSATING --> COMPENSATED: Downstream fault & steps i-1..1 rolled back
    COMPENSATING --> QUARANTINED: Compensating action exhausted retries (P1 SRE Alert)
```

## 3. Repository Module Map

| Package | Responsibility | Key Classes / Algorithms |
| :--- | :--- | :--- |
| `aegis.policy` | Custom DSL compiler & information-flow security | `tokenize_policy`, `compile_policy`, `PolicyEngine`, `TaintAnalyzer` |
| `aegis.privacy` | Reversible cryptographic pseudonymization | `PIITokenVault` (HMAC-SHA256 + AES-256-GCM with tenant AAD) |
| `aegis.ledger` | Tamper-evident append-only audit journal | `EventLedger`, `MerkleTree` (RFC-6962 `0x00`/`0x01`), `LedgerSigner` (Ed25519) |
| `aegis.saga` | Orchestrated distributed transactions | `SagaCoordinator`, `IdempotencyStore`, reverse-order compensation |
| `aegis.router` | Multi-objective FinOps routing & resilience | `ParetoModelRouter`, `CircuitBreaker`, `TenantTokenBucketLimiter`, `SemanticVectorCache` |
| `aegis.replay` | Deterministic replay & policy blast radius | `ReplayEngine.replay_workflow`, `simulate_counterfactual_policy` |
| `aegis.enterprise` | SAP S/4HANA-inspired ERP & JSON-RPC 2.0 MCP | `EnterpriseERPSandbox`, `EnterpriseMCPServer`, `EnterpriseScenarioCatalog` |
