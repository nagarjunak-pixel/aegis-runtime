# ADR-0003: RFC-6962 Domain-Separated Merkle Tree & Ed25519 Signed Audit Ledger

- **Status**: Accepted
- **Date**: 2026-11

## Context

Regulated enterprises (banking, healthcare, defense manufacturing) require non-repudiable, tamper-evident audit trails of autonomous agent decisions for SOX, OCC, HIPAA, and EU AI Act audits. Standard relational audit tables can be silently altered (`UPDATE` / `DELETE`) by a compromised service credential or privileged DBA.

## Decision

`EventLedger` (`src/aegis/ledger/`) combines three cryptographic mechanisms over SQLite WAL:
1. **Canonical SHA-256 Hash Chain**: Payloads are canonicalized with sorted UTF-8 keys (`canonical_json`) and hashed alongside monotonic `seq` and `prev_hash` (`H_0 = "0" * 64`).
2. **Ed25519 Asymmetric Signatures**: Every `event_hash` is signed with an `Ed25519` private key (`cryptography` C/Rust backend), preventing an attacker with write access to the SQLite file from recomputing a valid hash chain after modifying a historical row.
3. **RFC-6962 Domain-Separated Binary Merkle Tree**: Leaf hashes use `SHA256(0x00 || leaf)` and internal nodes use `SHA256(0x01 || left || right)`, with odd trailing nodes promoted directly without self-duplication—preventing both second-preimage interior-node collisions and CVE-2012-2459-style duplicate-leaf attacks.

## Consequences

- **Positive**: $O(\log N)$ inclusion proofs (`generate_inclusion_proof`) for external auditors; immediate detection of single-byte SQLite tampering (`RT-12`).
- **Negative / Trade-off**: Monotonic sequence assignment serializes writes per ledger shard (`threading.RLock`), bounding single-file append throughput to ~5,000–10,000 events/sec (sufficient per node; horizontally sharded by `tenant_id` at fleet scale).
