# Formal Safety & Conservation Invariants

`AegisRuntime` enforces five machine-checkable invariants across runtime execution, Hypothesis property-based tests (`tests/test_saga_properties.py`), and chaos benchmarks (`src/aegis/benchmarks/chaos_suite.py`).

## Invariant 1 — Pre-Execution Policy Mediation (Complete Mediation)
No forward tool invocation $f_i$ on an external or internal MCP resource executes unless:
$$\text{TaintCheck}(a_i) = \text{OK} \;\land\; \text{EvalPolicy}(P, p, a_i, c_i) = \text{PERMIT}$$
where conflict resolution satisfies **Deny-Overrides**:
$$\text{EvalPolicy}(P, p, a_i, c_i) = \text{PERMIT} \iff (\exists r \in P_{\text{permit}}: \llbracket r \rrbracket = \top) \;\land\; (\forall r \in P_{\text{forbid}}: \llbracket r \rrbracket = \bot)$$

## Invariant 2 — Information-Flow Lattice Containment
Let $\mathcal{L}$ be the security label set $\{\text{UNTRUSTED\_EXTERNAL}, \text{PII\_SENSITIVE}, \text{SECRET\_CREDENTIAL}\}$.
1. **Biba Integrity**: If $\text{UNTRUSTED\_EXTERNAL} \in \text{taint}(a_i)$ and $\text{sink}(a_i) \in \mathcal{S}_{\text{high}}$ (financial transfers, approvals, vendor IBAN master data, IAM), execution is rejected unconditionally prior to AST rule evaluation.
2. **Bell-LaPadula Confidentiality**: If $\{\text{PII\_SENSITIVE}, \text{SECRET\_CREDENTIAL}\} \cap \text{taint}(a_i) \neq \emptyset$ and $\neg \text{endswith}(\text{domain}(a_i), \text{".erp"})$, egress is rejected unconditionally.

## Invariant 3 — Double-Entry Financial & Physical Stock Conservation
Across every cost center $k$ (tracked in exact integer cents) and every plant-material lot $(p, m)$:
$$A^{\text{initial}}_k = A^{\text{available}}_k + A^{\text{encumbered}}_k + A^{\text{settled}}_k, \quad A^{\bullet}_k \ge 0$$
$$U^{\text{physical}}_{(p,m)} = U^{\text{atp}}_{(p,m)} + U^{\text{reserved}}_{(p,m)}, \quad U^{\bullet}_{(p,m)} \ge 0$$
For any non-quarantined saga $w$ terminating in $\text{COMPENSATED}$ or $\text{BLOCKED\_BY\_POLICY}$, its net delta on $A^{\text{encumbered}}_k$, $A^{\text{settled}}_k$, and $U^{\text{reserved}}_{(p,m)}$ is **identically zero**.

## Invariant 4 — Tenant-Bound Cryptographic Non-Substitutability
Every surrogate token $\tau = \text{[PII:}K\text{:}h\text{]}$ encrypts plaintext $m$ under AES-256-GCM with Additional Authenticated Data:
$$\text{AAD} = \text{tenant\_id} \,\|\, \text{":"} \,\|\, K \,\|\, \text{":"} \,\|\, \tau$$
Any attempt by tenant $t' \neq t$ to detokenize $\tau$ fails lookup and AEAD tag authentication.

## Invariant 5 — Tamper-Evident Monotonic Hash & Signature Chain
For every ledger sequence $n \ge 1$:
$$H_n = \text{SHA256}\big(\text{CanonicalJSON}(n, H_{n-1}, t_n, \text{tenant}_n, w_n, \text{type}_n, \text{payload}_n)\big), \quad H_0 = 0^{64}$$
$$\text{Ed25519.Verify}(\text{pk}, H_n, \sigma_n) = \top$$
Merkle inclusion proofs use RFC-6962 domain prefixes (`0x00` for leaves, `0x01` for internal nodes), preventing second-preimage tree-height substitution attacks.
