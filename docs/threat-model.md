# Threat Model (STRIDE + OWASP LLM Top-10 + SOX/OFAC)

## Scope & Trust Boundaries

1. **Untrusted Zone**: External documents (supplier PDF invoices, emails, scraped web pages), model completions/tool-call proposals.
2. **Control-Plane Enforcement Zone**: `AegisRuntime` (`TaintAnalyzer`, `PolicyEngine`, `PIITokenVault`, `SagaCoordinator`).
3. **Trusted Enterprise Resource Zone (`*.erp`)**: SAP S/4HANA Procurement, Inventory ATP, Logistics, and Treasury subsystems.
4. **Audit Persistence Zone**: SQLite WAL ledger (assumed readable/writable on disk by privileged host admins; protected against silent tampering via SHA-256 chaining + Ed25519 signatures).

## Threat & Mitigation Matrix

| Threat ID | Framework Mapping | Attack Scenario | Mitigation in `AegisRuntime` | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **TM-01** | OWASP LLM01 / Integrity | Indirect prompt injection in supplier invoice hijacks agent into calling `treasury.execute_wire` | Biba taint lattice (`UNTRUSTED_EXTERNAL`) + parameter signature scanner in `src/aegis/policy/taint.py` | `RT-01`, `RT-02` |
| **TM-02** | OWASP LLM06 / Information Disclosure | Raw IBANs, SSNs, or emails leak to external LLM provider logs or third-party webhooks | Pre-routing `PIITokenVault` tokenization + Bell-LaPadula domain egress gate in `src/aegis/privacy/vault.py` | `RT-03`, `RT-04` |
| **TM-03** | Elevation of Privilege / SOX ITGC | Principal or compromised agent self-approves a `$85,000` PO above `$25,000` autonomous cap | `forbid-segregation-of-duties-self-approval` & `forbid-spend-above-autonomous-cap` in `policies/enterprise_erp.aegis` | `RT-05`, `RT-06`, `RT-07` |
| **TM-04** | Regulatory / OFAC | Agent creates PO for sanctioned counterparty jurisdiction (`IR`, `KP`) after reserving stock | Dynamic context evaluation + reverse-order Saga compensation releasing Step-1 stock | `RT-08`, `test_replay_and_mcp.py` |
| **TM-05** | Spoofing / Multi-Tenancy | Tenant B replays Tenant A's `[PII:IBAN:...]` token or hits Tenant A's semantic prompt cache | AES-256-GCM AAD tenant binding + tenant-partitioned `SemanticVectorCache` | `RT-11`, `test_router_resilience.py` |
| **TM-06** | Repudiation / Insider Tampering | Malicious DBA modifies `payload_json` or deletes rows in `ledger_events` SQLite file | Monotonic sequence check + SHA-256 `prev_hash` chain + Ed25519 signature audit + RFC-6962 Merkle proofs | `RT-12`, `test_merkle_ledger.py` |
| **TM-07** | Denial of Wallet / DoS | Runaway agent loop exhausts LLM budget or hammers failing downstream endpoint | `TenantTokenBucketLimiter` USD ceiling + 3-state `CircuitBreaker` | `test_router_resilience.py` |
| **TM-08** | Code Execution via Policy | Attacker crafts policy expression accessing Python `__subclasses__` or `__globals__` | Lexer rejects `__` dunder tokens; recursive-descent AST evaluator supports only whitelisted namespaces (`principal`, `action`, `context`) | `test_policy_compiler.py` |
