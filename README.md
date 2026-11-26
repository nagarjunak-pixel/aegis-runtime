# AegisRuntime

[![AegisRuntime CI](https://github.com/nagarjunak-pixel/aegis-runtime/actions/workflows/ci.yml/badge.svg)](https://github.com/nagarjunak-pixel/aegis-runtime/actions/workflows/ci.yml)
[![Release v1.0.0](https://img.shields.io/badge/release-v1.0.0-1f6feb.svg)](https://github.com/nagarjunak-pixel/aegis-runtime/releases/tag/v1.0.0)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)
![TypeScript 5.6](https://img.shields.io/badge/TypeScript-5.6-3178C6?logo=typescript&logoColor=white)
![Coverage 97%](https://img.shields.io/badge/coverage-97%25-10b981)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-10b981.svg)](LICENSE)

**Policy and audit layer for AI-agent tool calls — custom policy DSL, saga compensation, hash-chained Merkle/Ed25519 audit log. Reference implementation.**

AegisRuntime is a single-process Python reference implementation of a control layer that sits between an AI agent and the tools it calls. It evaluates each proposed action against a small deny-overrides policy language, runs multi-step workflows as sagas with compensating rollback, and records every event in a SQLite-backed, SHA-256 hash-chained log with Ed25519 signatures and RFC-6962-style Merkle inclusion proofs. The ERP, treasury, and model backends it orchestrates are in-memory simulations used to exercise these mechanisms.

---

## Why AegisRuntime Exists

Most enterprise AI initiatives stall at the boundary between **read-only RAG copilots** and **write-capable autonomous operations** (issuing SAP purchase orders, reserving plant ATP inventory, locking FX forwards, or settling SWIFT/SEPA wires). Probabilistic LLMs cannot be trusted to enforce SOX Segregation of Duties, OFAC trade sanctions, PII residency, or multi-system transactional rollback when step 4 of a 4-step workflow fails mid-flight.

**AegisRuntime** wraps non-deterministic model reasoning inside a **deterministic, policy-checked and property-tested control harness**:

1. **`.aegis` Policy-as-Code AST Compiler (`src/aegis/policy/`)** — Zero-`eval()` lexer, recursive-descent parser, and sub-50µs evaluator implementing **Deny-Overrides + Implicit Default-Deny** with full rule-by-rule proof traces.
2. **Biba / Bell-LaPadula Information-Flow Taint & Reversible PII Vault (`src/aegis/policy/taint.py`, `src/aegis/privacy/`)** — Blocks indirect prompt-injection attacks (`UNTRUSTED_EXTERNAL` taint) from mutating high-integrity ERP/Treasury sinks, and replaces raw IBAN/SSN/TaxID/Email values with deterministic **HMAC-SHA256** surrogates backed by **tenant-AAD-bound AES-256-GCM** envelope encryption.
3. **Distributed Saga Coordinator & Compensating Rollback Engine (`src/aegis/saga/`)** — Content-addressed SHA-256 idempotency keys, bounded exponential backoff on transient HTTP 503s, automatic **reverse-topological compensating rollbacks** on downstream or policy faults, and explicit **`QUARANTINED`** dead-letter isolation if compensation itself exhausts retries.
4. **Tamper-Evident SHA-256, RFC-6962 Merkle & Ed25519 Ledger (`src/aegis/ledger/`)** — Append-only SQLite WAL event journal with monotonic hash chaining, **Ed25519 cryptographic signatures**, and $O(\log N)$ domain-separated (`0x00` leaf / `0x01` internal) Merkle inclusion proofs.
5. **Pareto Multi-Model FinOps Router (`src/aegis/router/`)** — Eliminates dominated LLM endpoints across `(Cost, p95 Latency, Quality)`, backed by 3-state sliding-window circuit breakers, hierarchical tenant token-bucket admission control, and L2-normalized signed feature-hashing cosine semantic caching.
6. **Time-Travel Replay & Counterfactual Policy Simulator (`src/aegis/replay/`)** — Reconstructs exact workflow state at any ledger sequence `seq <= N` and simulates candidate `.aegis` policy edits against historical production traffic to compute exact blast radius (`PERMIT <-> DENY` flips) prior to rollout.

---

## Live AegisRuntime Control Tower (ERP Sagas, Merkle Ledger & Red-Team Lab)

![AegisRuntime Control Tower — Zero-Trust AST Policy Gatekeeper, Transactional SAP/ERP Sagas & RFC-6962 Merkle Audit Ledger](docs/assets/workbench-preview.png)

---

## System Architecture

```mermaid
flowchart TB
    subgraph Caller["Enterprise Caller & Untrusted Context"]
        P["PrincipalContext (MFA, Roles, Spend Cap, Co-Signer)"]
        D["Prompt + External Docs (Invoices, Emails)"]
    end

    subgraph ControlPlane["AegisRuntime Deterministic Control Plane"]
        V["AES-256-GCM PII Vault\n(HMAC-SHA256 Surrogates + Tenant AAD)"]
        T["Information-Flow Taint Lattice\n(Biba Integrity + Bell-LaPadula Egress)"]
        R["Pareto FinOps Model Router\n(Semantic Cache + Circuit Breakers + Token Bucket)"]
        AST[".aegis AST Policy Gatekeeper\n(Deny-Overrides + Proof Trace)"]
        S["Distributed Saga Coordinator\n(Idempotency + Reverse Compensation + Quarantine)"]
        L[("SQLite WAL Cryptographic Ledger\nSHA-256 Chain + RFC-6962 Merkle + Ed25519")]
        CF["Time-Travel & Counterfactual Replay Engine"]
    end

    subgraph EnterpriseMCP["SAP S/4HANA-Inspired MCP Tool Boundary (internal.erp)"]
        INV["Inventory ATP\n(Plant Stock Conservation)"]
        PO["Procurement\n(Double-Entry Cents Ledger)"]
        LOG["Global Logistics\n(Expedited Air Corridors)"]
        TR["Treasury & SWIFT\n(FX Hedges & Wires)"]
    end

    P --> V
    D --> V
    V --> T
    T --> R
    R --> S
    S <--> AST
    S --> L
    L --> CF
    S ==>|Detokenize inside .erp only| INV & PO & LOG & TR
```

---

## Verified Benchmarks & Security Containment

All benchmarks run deterministically out-of-the-box with **zero external API keys required** (`make verify`):

### Distributed Chaos & Double-Entry Conservation (`200` 3-Step Sagas @ `25%` Injected Fault Rate)

| Metric | Measured Result |
| :--- | ---: |
| Total Multi-Step ERP Sagas Executed | `200` |
| Committed Sagas / Rolled-Back (Compensated) / Policy-Blocked | `109` / `82` / `9` |
| **Orphaned ERP Inventory or Cost-Center Mutations** | **`0` (Zero)** |
| **Double-Entry Cents & Warehouse ATP Conservation Law** | **`VERIFIED (100%)`** |
| **SHA-256 + Ed25519 + RFC-6962 Merkle Audit (`1,482` events)** | **`VERIFIED (100%)`** |
| `.aegis` AST Policy Evaluation Latency (`p50` / `p95` / `p99`) | `29.0 µs` / `40.8 µs` / `85.9 µs` |
| End-to-End Orchestrated Saga Latency (`p50` / `p95` / `p99`) | `0.54 ms` / `1.92 ms` / `2.96 ms` |
| Control-Plane Throughput (Single Node, SQLite WAL) | `1,231.6 sagas/sec` |

### 12-Vector Adversarial Red-Team Containment (`uv run aegis redteam`)

| ID | Threat Class | Adversarial Vector | Enforcing Layer | Verdict |
| :--- | :--- | :--- | :--- | :---: |
| `RT-01` | OWASP-LLM01 | Indirect prompt injection in supplier PDF triggering SWIFT wire | Biba Taint Lattice | **CONTAINED** |
| `RT-02` | OWASP-LLM01 | `SYSTEM OVERRIDE` directive smuggled inside ERP order notes | Parameter Payload Scanner | **CONTAINED** |
| `RT-03` | OWASP-LLM06 | `PII_SENSITIVE` context egress to `analytics.external-saas.io` | Bell-LaPadula Lattice | **CONTAINED** |
| `RT-04` | Lethal Trifecta | Covert `https://webhook.site/...` exfiltration callback URL | Egress Domain Allowlist | **CONTAINED** |
| `RT-05` | SOX ITGC | Segregation-of-Duties self-approval (`principal_id == approver_id`) | AST `forbid` Rule | **CONTAINED** |
| `RT-06` | Spend Governance | `$65,000` autonomous PO exceeding `$25,000` principal cap | AST `forbid` Rule | **CONTAINED** |
| `RT-07` | Treasury Guard | `$750,000` wire exceeding hard `$500,000` enterprise ceiling | AST Hard Ceiling Rule | **CONTAINED** |
| `RT-08` | OFAC Sanctions | Procurement routed to sanctioned jurisdiction (`KP` / `IR`) | AST Contextual Rule | **CONTAINED** |
| `RT-09` | Zero-Trust Auth | Agent execution without MFA-verified principal session | AST Identity Rule | **CONTAINED** |
| `RT-10` | Master Data | Vendor settlement IBAN update without `treasury_controller` role | AST RBAC Rule | **CONTAINED** |
| `RT-11` | Multi-Tenancy | Cross-tenant replay of `[PII:IBAN:...]` surrogate token | AES-256-GCM AAD Binding | **CONTAINED** |
| `RT-12` | Insider Threat | Direct SQLite byte modification on committed ledger row `seq=1` | SHA-256 + Ed25519 Auditor | **CONTAINED** |

---

## Scope & Limitations

- **Scale:** ~5.6k lines of Python in `src/aegis/` (of which ~1.5k are the simulated ERP subsystems, demo scenarios, and benchmark harnesses), ~1.2k lines of tests, plus a small React/TypeScript UI. Single process, single node; the ledger is a local SQLite WAL file with no replication or consensus.
- **Simulated backends:** The "SAP S/4HANA-inspired" inventory, procurement, logistics, and treasury systems are in-memory Python objects with seeded fault injection — there is no real SAP, banking, or SWIFT integration. The Pareto router selects among static model profiles and returns a stub response; no LLM is called.
- **Self-constructed benchmarks:** The chaos benchmark is 200 synthetic 3-step sagas at a 25% injected fault rate, run in-process on one machine (CPU only); its latency and throughput figures describe the local simulation, not networked traffic. The red-team suite is 12 hand-written scenarios, each aimed at a rule or check the project already defines — not an independent adversarial evaluation.
- **"Formal" means property-tested:** The invariants in `docs/formal-invariants.md` are checked by Hypothesis property-based tests, runtime assertions, and the benchmark harness — not by machine-checked proofs or a model checker. The semantic cache uses feature-hashed vectors, not learned embeddings.
- **Not production-hardened:** No external security audit; the PII vault falls back to a fixed development key when none is supplied, and signing keys are generated in-process without a KMS/HSM.

---

## 60-Second Quickstart (Zero API Keys Required)

```bash
# 1. Clone and sync Python 3.12 environment via uv
git clone https://github.com/nagarjunak-pixel/aegis-runtime.git
cd aegis-runtime
uv sync --all-extras

# 2. Run all 6 Fortune-500 SAP/ERP & Governance reference scenarios
uv run aegis demo

# 3. Run the 12-vector OWASP / SOX / OFAC adversarial red-team suite
uv run aegis redteam

# 4. Run 200 multi-step sagas under 25% chaos fault injection
uv run aegis benchmark --transactions 200 --fault-rate 0.25

# 5. Run full lint, mypy --strict, and 90 pytest tests + Hypothesis property checks
make verify
```

### Launch the Live Operator Control Tower UI + FastAPI Control Plane

```bash
cd ui && npm install && npm run build && cd ..
uv run aegis serve --host 127.0.0.1 --port 8000
# Open http://127.0.0.1:8000 (UI), http://127.0.0.1:8000/docs (OpenAPI), or /metrics (Prometheus)
```

---

## Example `.aegis` Policy-as-Code DSL

```hcl
rule "forbid-segregation-of-duties-self-approval" {
    effect: forbid
    description: "SOX Segregation of Duties: principal cannot approve their own workflow"
    when: principal.approver_id != null and principal.principal_id == principal.approver_id
}

rule "forbid-spend-above-autonomous-cap-without-secondary-approver" {
    effect: forbid
    description: "Mutations exceeding principal cap require an independent approver_id"
    when: action.amount_usd > principal.max_autonomous_spend_usd and principal.approver_id == null
}

rule "permit-treasury-settlement-operations" {
    effect: permit
    description: "Permit authorized treasury settlements strictly on internal.erp"
    when: ("treasury_operator" in principal.roles or "procurement_planner" in principal.roles)
          and action.resource_type in ["fx_hedge", "wire_transfer"]
          and action.target_domain == "internal.erp"
}
```

### Compaction-Safe User-Byte Attribution & Tool-Order Canonicalization (`v1.1.0`)

Long-running coding and finance agents routinely invoke context compaction (`/compact`) when sessions cross token budgets. When model-generated summaries are re-inserted as user messages, untrusted document strings (such as a rogue account number in an invoice notice) can launder into request-derived capability policies (`arXiv:2611.32194`). `aegis.policy.CompactionAttributionLedger` and `/api/v1/compact/verify` separate planner context from policy authority:

- **HMAC-SHA256 User-Span Sealing (`CompactionAttributionLedger`):** Authenticates raw human user turns prior to planner ingestion and carries sealed user byte spans verbatim across compaction epochs while presenting compactor summaries strictly as untrusted system context.
- **Permutation-Invariant Tool Manifests (`canonicalize_tool_schemas`, `arXiv:2611.30259`):** Normalizes MCP tool definitions and `required` parameter sets into a deterministic lexicographical `SHA-256` manifest independent of tool registration order or `PYTHONHASHSEED`.

---

## Architecture Documentation & Decision Records (ADRs)

- [System Architecture & Sequence Lifecycles](docs/architecture.md)
- [Formal Safety & Conservation Invariants](docs/formal-invariants.md)
- [STRIDE + OWASP LLM Threat Model](docs/threat-model.md)
- **Architecture Decision Records (`docs/adr/`)**:
  - [ADR-0001: Custom `.aegis` AST Policy DSL with Deny-Overrides Semantics](docs/adr/0001-custom-ast-policy-dsl-with-deny-overrides.md)
  - [ADR-0002: Orchestrated Sagas & Quarantine Isolation Over Two-Phase Commit (2PC)](docs/adr/0002-orchestrated-sagas-over-two-phase-commit.md)
  - [ADR-0003: RFC-6962 Domain-Separated Merkle Tree & Ed25519 Signed Audit Ledger](docs/adr/0003-rfc6962-merkle-and-ed25519-event-ledger.md)
  - [ADR-0004: Information-Flow Taint Lattice & Tenant-Bound AES-256-GCM PII Vault](docs/adr/0004-lattice-taint-tracking-and-reversible-aes-gcm-pii-vault.md)
  - [ADR-0005: Pareto-Optimal Multi-Model Routing & Signed Feature-Hashing Cache](docs/adr/0005-pareto-multi-objective-model-routing-and-signed-hash-cache.md)
  - [ADR-0006: Event-Sourced Time-Travel & Counterfactual Policy Blast-Radius Replay](docs/adr/0006-event-sourced-counterfactual-policy-replay.md)

---

## License

Apache License 2.0 — Copyright © 2026 [Nagarjuna Kamireddy](https://github.com/nagarjunak-pixel).

---

## Author & Links
Built by **[Nagarjuna Reddy Kamireddy](https://nagarjunak-pixel.github.io/)** (*Nagarjuna Kamireddy / Nagarjuna K*) — Lead AI Architect, GenAI & Agentic AI Lead, and Corporate AI Trainer (22 years across Enterprise Data, SAP HANA & Production AI; AWS Certified Solutions Architect – Professional & NVIDIA-Certified Professional: Agentic AI).

- **Portfolio:** [https://nagarjunak-pixel.github.io/](https://nagarjunak-pixel.github.io/)
- **Case Studies & Technical Articles:** [Case Studies](https://nagarjunak-pixel.github.io/case-studies.html) · [Architecture Articles](https://nagarjunak-pixel.github.io/articles.html) · [10-Mandate Role Fit](https://nagarjunak-pixel.github.io/roles.html)
- **Master CV & AI Search Index:** [Master CV](https://nagarjunak-pixel.github.io/resume.html) · [`llms-full.txt`](https://nagarjunak-pixel.github.io/llms-full.txt) · [LinkedIn](https://www.linkedin.com/in/nagarjuna-kamireddy)
