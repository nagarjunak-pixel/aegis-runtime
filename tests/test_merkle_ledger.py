"""Cryptographic tests for SHA-256 hash chain, RFC-6962 Merkle proofs, and Ed25519 ledger."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from aegis.ledger.crypto import (
    GENESIS_PREV_HASH,
    LedgerSigner,
    MerkleInclusionProof,
    MerkleTree,
    ProofStep,
    verify_merkle_proof,
)
from aegis.ledger.store import EventLedger
from aegis.types import LedgerEventType


@pytest.mark.parametrize("tree_size", [1, 2, 3, 4, 5, 7, 8, 13, 16, 25])
def test_rfc6962_merkle_inclusion_proofs_for_all_leaves(tree_size: int) -> None:
    hashes = [f"{i + 1:064x}" for i in range(tree_size)]
    tree = MerkleTree(hashes)
    assert len(tree.root_hex) == 64

    for idx in range(tree_size):
        proof = tree.prove_inclusion(idx)
        assert verify_merkle_proof(proof)

        # Flipping a single bit in the event hash must invalidate the proof
        tampered = MerkleInclusionProof(
            leaf_index=proof.leaf_index,
            tree_size=proof.tree_size,
            event_hash_hex="f" * 64,
            root_hash_hex=proof.root_hash_hex,
            audit_path=proof.audit_path,
        )
        assert not verify_merkle_proof(tampered)


def test_merkle_empty_and_bounds_check() -> None:
    empty = MerkleTree([])
    assert len(empty.root_hex) == 64
    with pytest.raises(IndexError):
        empty.prove_inclusion(0)

    bad_hex_proof = MerkleInclusionProof(
        leaf_index=0,
        tree_size=2,
        event_hash_hex="not-hex",
        root_hash_hex="0" * 64,
        audit_path=(ProofStep(sibling_hash_hex="zz", is_left_sibling=False),),
    )
    assert not verify_merkle_proof(bad_hex_proof)


def test_ed25519_signer_deterministic_seed_and_verification() -> None:
    seed = b"\x07" * 32
    s1 = LedgerSigner.from_seed(seed)
    s2 = LedgerSigner.from_seed(seed)
    assert s1.public_key_hex == s2.public_key_hex
    assert len(s1.export_private_bytes()) == 32

    digest = "a" * 64
    sig = s1.sign_digest(digest)
    assert LedgerSigner.verify_digest(s1.public_key_hex, digest, sig)
    assert not LedgerSigner.verify_digest(s1.public_key_hex, "b" * 64, sig)
    assert not LedgerSigner.verify_digest("invalid", digest, sig)

    with pytest.raises(ValueError, match="32 bytes"):
        LedgerSigner.from_seed(b"short")


def test_sqlite_wal_ledger_chain_and_tamper_detection(tmp_path: Path) -> None:
    db_file = tmp_path / "audit.db"
    ledger = EventLedger(db_path=db_file)

    e1 = ledger.append(
        tenant_id="t-1",
        workflow_id="wf-100",
        event_type=LedgerEventType.WORKFLOW_STARTED,
        payload={"step_count": 3},
    )
    e2 = ledger.append(
        tenant_id="t-1",
        workflow_id="wf-100",
        event_type=LedgerEventType.WORKFLOW_COMPLETED,
        payload={"status": "COMMITTED"},
    )
    assert e1.seq == 1
    assert e1.prev_hash == GENESIS_PREV_HASH
    assert e2.seq == 2
    assert e2.prev_hash == e1.event_hash
    assert ledger.count() == 2

    proof = ledger.generate_inclusion_proof(2)
    assert verify_merkle_proof(proof)

    report_ok = ledger.verify_chain_integrity()
    assert report_ok.valid
    assert report_ok.events_checked == 2
    ledger.close()

    # Corrupt prev_hash on seq=2 directly via sqlite3
    conn = sqlite3.connect(db_file)
    conn.execute("UPDATE ledger_events SET prev_hash = ? WHERE seq = 2", ("0" * 64,))
    conn.commit()
    conn.close()

    reopened = EventLedger(db_path=db_file)
    report_bad = reopened.verify_chain_integrity()
    assert not report_bad.valid
    assert report_bad.corrupted_seq == 2
    assert "prev_hash" in (report_bad.failure_reason or "")
    reopened.close()
