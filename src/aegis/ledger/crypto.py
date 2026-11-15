"""Cryptographic primitives: canonical JSON, SHA-256 hash chains, RFC-6962 Merkle trees, Ed25519."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

GENESIS_PREV_HASH = "0" * 64


def canonical_json(data: Any) -> str:
    """Serialize data into deterministic, sorted-key UTF-8 JSON for cryptographic hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def compute_event_hash(
    *,
    seq: int,
    prev_hash: str,
    timestamp: str,
    tenant_id: str,
    workflow_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> str:
    """Compute the SHA-256 digest over an event envelope linked to `prev_hash`."""
    envelope = {
        "seq": seq,
        "prev_hash": prev_hash,
        "timestamp": timestamp,
        "tenant_id": tenant_id,
        "workflow_id": workflow_id,
        "event_type": event_type,
        "payload": payload,
    }
    return hashlib.sha256(canonical_json(envelope).encode("utf-8")).hexdigest()


class LedgerSigner:
    """Ed25519 cryptographic attestation signer & offline signature verifier."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

    @classmethod
    def from_seed(cls, seed_32_bytes: bytes) -> LedgerSigner:
        if len(seed_32_bytes) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed_32_bytes))

    @property
    def public_key_hex(self) -> str:
        raw = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return raw.hex()

    def export_private_bytes(self) -> bytes:
        return self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def sign_digest(self, event_hash_hex: str) -> str:
        sig = self._private_key.sign(event_hash_hex.encode("ascii"))
        return sig.hex()

    @staticmethod
    def verify_digest(public_key_hex: str, event_hash_hex: str, signature_hex: str) -> bool:
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            pub.verify(bytes.fromhex(signature_hex), event_hash_hex.encode("ascii"))
            return True
        except (ValueError, InvalidSignature):
            return False


def _leaf_hash(data_hex: str) -> bytes:
    """RFC-6962 domain-separated leaf hash: SHA256(0x00 || leaf_bytes)."""
    return hashlib.sha256(b"\x00" + bytes.fromhex(data_hex)).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """RFC-6962 domain-separated internal node hash: SHA256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


@dataclass(frozen=True, slots=True)
class ProofStep:
    sibling_hash_hex: str
    is_left_sibling: bool


@dataclass(frozen=True, slots=True)
class MerkleInclusionProof:
    leaf_index: int
    tree_size: int
    event_hash_hex: str
    root_hash_hex: str
    audit_path: tuple[ProofStep, ...]


class MerkleTree:
    """RFC-6962 Binary Merkle Tree supporting O(log N) cryptographic inclusion proofs."""

    def __init__(self, event_hashes: list[str]) -> None:
        self._event_hashes = list(event_hashes)
        self._levels: list[list[bytes]] = []
        if self._event_hashes:
            self._build()

    def _build(self) -> None:
        current = [_leaf_hash(h) for h in self._event_hashes]
        self._levels.append(current)
        while len(current) > 1:
            next_level: list[bytes] = []
            i = 0
            while i < len(current):
                if i + 1 < len(current):
                    next_level.append(_node_hash(current[i], current[i + 1]))
                else:
                    # Odd trailing node promoted without duplicate self-concatenation vulnerability
                    next_level.append(current[i])
                i += 2
            self._levels.append(next_level)
            current = next_level

    @property
    def root_hex(self) -> str:
        if not self._levels:
            return hashlib.sha256(b"").hexdigest()
        return self._levels[-1][0].hex()

    def prove_inclusion(self, leaf_index: int) -> MerkleInclusionProof:
        if leaf_index < 0 or leaf_index >= len(self._event_hashes):
            raise IndexError(f"Leaf index {leaf_index} out of range [0, {len(self._event_hashes)})")

        steps: list[ProofStep] = []
        idx = leaf_index
        for level in self._levels[:-1]:
            if idx % 2 == 0:
                if idx + 1 < len(level):
                    steps.append(
                        ProofStep(sibling_hash_hex=level[idx + 1].hex(), is_left_sibling=False)
                    )
            else:
                steps.append(ProofStep(sibling_hash_hex=level[idx - 1].hex(), is_left_sibling=True))
            idx //= 2

        return MerkleInclusionProof(
            leaf_index=leaf_index,
            tree_size=len(self._event_hashes),
            event_hash_hex=self._event_hashes[leaf_index],
            root_hash_hex=self.root_hex,
            audit_path=tuple(steps),
        )


def verify_merkle_proof(proof: MerkleInclusionProof) -> bool:
    """Independently verify an O(log N) RFC-6962 Merkle inclusion proof against its root."""
    try:
        acc = _leaf_hash(proof.event_hash_hex)
        for step in proof.audit_path:
            sibling = bytes.fromhex(step.sibling_hash_hex)
            acc = _node_hash(sibling, acc) if step.is_left_sibling else _node_hash(acc, sibling)
        return acc.hex() == proof.root_hash_hex
    except ValueError:
        return False
