# Security Policy

## Architectural Security Posture

`AegisRuntime` is designed as a Zero-Trust reference control plane for autonomous enterprise agents:

- **No `eval()` or `exec()`**: All `.aegis` policy files are tokenized and compiled into typed, immutable AST dataclasses (`src/aegis/policy/`). Dunder (`__*`) identifiers and non-whitelisted root namespaces are rejected at compile time.
- **Authenticated Encryption**: All vaulted PII secrets use `AES-256-GCM` (`cryptography` library) with unique 96-bit nonces and tenant-bound Additional Authenticated Data (AAD).
- **Tamper-Evident Auditability**: Ledger entries are chained with SHA-256, structured into RFC-6962 domain-separated Merkle trees, and signed using `Ed25519`.

## Running the Adversarial Verification Suite

```bash
uv run aegis redteam
```

## Reporting a Vulnerability

Please report security findings via GitHub Security Advisories on `nagarjunak-pixel/aegis-runtime`.
