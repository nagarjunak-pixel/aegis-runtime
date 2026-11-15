"""Tenant-isolated Reversible PII Vault using HMAC-SHA256 surrogates + AES-256-GCM."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CARD", re.compile(r"\b(?:\d[ -]*?){15,16}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("TAXID", re.compile(r"\bEIN-\d{2}-\d{7}\b")),
)

_TOKEN_RE = re.compile(r"\[PII:([A-Z]+):([0-9a-f]{12})\]")


class PIIBoundaryViolationError(PermissionError):
    """Raised when detokenization is attempted outside a trusted internal ERP boundary."""


@dataclass(frozen=True, slots=True)
class VaultRecord:
    tenant_id: str
    pii_kind: str
    token: str
    nonce: bytes
    ciphertext: bytes


@dataclass(frozen=True, slots=True)
class TokenizationResult:
    sanitized_value: Any
    tokens_created: tuple[str, ...]
    pii_kinds_detected: tuple[str, ...]


class PIITokenVault:
    """Reversible PII pseudonymization vault with cryptographic tenant binding.

    - Surrogate tokens are deterministic per `(tenant_id, pii_kind, plaintext)` via HMAC-SHA256
      so LLM reasoning preserves referential equality without seeing raw PII.
    - Raw PII is encrypted in memory/storage using AES-256-GCM with AAD bound to
      `tenant_id:pii_kind:token`, preventing cross-tenant token replay or substitution.
    """

    def __init__(self, master_key: bytes | None = None) -> None:
        if master_key is not None and len(master_key) != 32:
            raise ValueError("master_key must be exactly 32 bytes for AES-256-GCM")
        self._master_key = master_key or hashlib.sha256(b"aegis-default-dev-key-material").digest()
        self._hmac_key = hashlib.sha256(b"hmac:" + self._master_key).digest()
        self._aesgcm = AESGCM(self._master_key)
        self._records: dict[tuple[str, str], VaultRecord] = {}

    def tokenize_text(self, tenant_id: str, text: str) -> TokenizationResult:
        tokens_created: list[str] = []
        kinds_detected: list[str] = []
        sanitized = text

        for kind, pattern in _PII_PATTERNS:

            def _replace(match: re.Match[str], pii_kind: str = kind) -> str:
                raw = match.group(0)
                token = self._store_secret(tenant_id=tenant_id, pii_kind=pii_kind, plaintext=raw)
                tokens_created.append(token)
                if pii_kind not in kinds_detected:
                    kinds_detected.append(pii_kind)
                return token

            sanitized = pattern.sub(_replace, sanitized)

        return TokenizationResult(
            sanitized_value=sanitized,
            tokens_created=tuple(tokens_created),
            pii_kinds_detected=tuple(kinds_detected),
        )

    def tokenize_payload(self, tenant_id: str, payload: Any) -> TokenizationResult:
        all_tokens: list[str] = []
        all_kinds: list[str] = []

        def _walk(val: Any) -> Any:
            if isinstance(val, str):
                res = self.tokenize_text(tenant_id, val)
                all_tokens.extend(res.tokens_created)
                for k in res.pii_kinds_detected:
                    if k not in all_kinds:
                        all_kinds.append(k)
                return res.sanitized_value
            if isinstance(val, dict):
                return {k: _walk(v) for k, v in val.items()}
            if isinstance(val, list):
                return [_walk(v) for v in val]
            if isinstance(val, tuple):
                return tuple(_walk(v) for v in val)
            return val

        sanitized_payload = _walk(payload)
        return TokenizationResult(
            sanitized_value=sanitized_payload,
            tokens_created=tuple(all_tokens),
            pii_kinds_detected=tuple(all_kinds),
        )

    def detokenize_payload(
        self,
        tenant_id: str,
        payload: Any,
        *,
        target_domain: str,
    ) -> Any:
        """Detokenize surrogates strictly for authorized `.erp` internal destinations."""
        if not target_domain.endswith(".erp"):
            raise PIIBoundaryViolationError(
                f"Detokenization denied for untrusted target_domain '{target_domain}'"
            )

        def _restore_str(text: str) -> str:
            def _sub(match: re.Match[str]) -> str:
                full_token = match.group(0)
                rec = self._records.get((tenant_id, full_token))
                if rec is None:
                    raise PIIBoundaryViolationError(
                        f"Unknown or cross-tenant PII token '{full_token}' for tenant '{tenant_id}'"
                    )
                aad = f"{rec.tenant_id}:{rec.pii_kind}:{rec.token}".encode()
                plaintext_bytes = self._aesgcm.decrypt(rec.nonce, rec.ciphertext, aad)
                return plaintext_bytes.decode("utf-8")

            return _TOKEN_RE.sub(_sub, text)

        def _walk(val: Any) -> Any:
            if isinstance(val, str):
                return _restore_str(val)
            if isinstance(val, dict):
                return {k: _walk(v) for k, v in val.items()}
            if isinstance(val, list):
                return [_walk(v) for v in val]
            if isinstance(val, tuple):
                return tuple(_walk(v) for v in val)
            return val

        return _walk(payload)

    def _store_secret(self, tenant_id: str, pii_kind: str, plaintext: str) -> str:
        mac = hmac.new(
            self._hmac_key,
            f"{tenant_id}:{pii_kind}:{plaintext}".encode(),
            hashlib.sha256,
        ).hexdigest()[:12]
        token = f"[PII:{pii_kind}:{mac}]"
        key = (tenant_id, token)
        if key not in self._records:
            nonce = os.urandom(12)
            aad = f"{tenant_id}:{pii_kind}:{token}".encode()
            ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
            self._records[key] = VaultRecord(
                tenant_id=tenant_id,
                pii_kind=pii_kind,
                token=token,
                nonce=nonce,
                ciphertext=ciphertext,
            )
        return token

    @property
    def vaulted_count(self) -> int:
        return len(self._records)
