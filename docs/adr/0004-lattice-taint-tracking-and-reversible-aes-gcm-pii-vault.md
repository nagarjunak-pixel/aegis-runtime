# ADR-0004: Information-Flow Taint Lattice & Tenant-Bound AES-256-GCM PII Vault

- **Status**: Accepted
- **Date**: 2026-11

## Context

Agentic systems face the **Lethal Trifecta** (access to private data + exposure to untrusted external content + ability to invoke state-mutating or external-egress tools). Meanwhile, redacting PII completely (`[REDACTED]`) breaks downstream ERP settlement tools that genuinely need the vendor's real IBAN inside the trusted corporate network.

## Decision

1. **Classical Security Lattices (`src/aegis/policy/taint.py`)**:
   - **Biba Integrity Model**: Inputs derived from external documents carry `UNTRUSTED_EXTERNAL`. High-integrity sinks (`treasury.execute_wire`, `vendor.update_bank_iban`, approvals, IAM) reject `UNTRUSTED_EXTERNAL` unconditionally.
   - **Bell-LaPadula Confidentiality Model**: Contexts carrying `PII_SENSITIVE` or `SECRET_CREDENTIAL` cannot invoke tools targeting domains outside `*.erp`.
2. **Reversible Deterministic PII Vault (`src/aegis/privacy/vault.py`)**:
   - Replaces raw IBAN, SSN, Credit Card, Tax ID, and Email strings with `[PII:<KIND>:<12-hex-hmac>]` computed via `HMAC-SHA256(hmac_key, tenant_id:kind:plaintext)`—preserving referential equality for LLM reasoning while hiding raw PII from model providers AND the audit ledger.
   - Encrypts raw secrets with `AES-256-GCM` using `AAD = tenant_id:kind:token`, and permits detokenization strictly inside `SagaCoordinator` when `target_domain.endswith(".erp")`.

## Consequences

- **Positive**: Raw PII never enters LLM prompts or ledger disk storage; cross-tenant token substitution is cryptographically impossible (`RT-11`).
- **Negative / Trade-off**: Pattern-based detection covers structured PII (IBAN, SSN, Email, Card, EIN); unstructured free-prose PII requires pairing with an upstream NER classifier in production.
