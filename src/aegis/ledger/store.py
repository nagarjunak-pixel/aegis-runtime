"""SQLite WAL append-only cryptographic event ledger with full chain & signature auditing."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from aegis.ledger.crypto import (
    GENESIS_PREV_HASH,
    LedgerSigner,
    MerkleInclusionProof,
    MerkleTree,
    canonical_json,
    compute_event_hash,
)
from aegis.types import LedgerEventType, utc_now_iso


class LedgerEntry(BaseModel):
    """Immutable, cryptographically attested event in the execution journal."""

    model_config = ConfigDict(frozen=True)

    seq: int
    timestamp: str
    tenant_id: str
    workflow_id: str
    event_type: LedgerEventType
    payload: dict[str, Any]
    prev_hash: str
    event_hash: str
    signature: str
    public_key: str


class ChainVerificationReport(BaseModel):
    """Result of full cryptographic audit over the append-only ledger."""

    model_config = ConfigDict(frozen=True)

    valid: bool
    events_checked: int
    merkle_root: str
    corrupted_seq: int | None = None
    failure_reason: str | None = None


class EventLedger:
    """Durable SQLite WAL append-only ledger enforcing hash-chaining and Ed25519 attestation."""

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        signer: LedgerSigner | None = None,
    ) -> None:
        self._db_path = str(db_path)
        if self._db_path != ":memory:":
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._signer = signer or LedgerSigner()
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ledger_events (
                    seq INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    workflow_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    signature TEXT NOT NULL,
                    public_key TEXT NOT NULL
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ledger_workflow ON ledger_events(workflow_id, seq);"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ledger_tenant ON ledger_events(tenant_id, seq);"
            )
            self._conn.commit()

    @property
    def signer(self) -> LedgerSigner:
        return self._signer

    def append(
        self,
        *,
        tenant_id: str,
        workflow_id: str,
        event_type: LedgerEventType,
        payload: dict[str, Any],
        timestamp: str | None = None,
    ) -> LedgerEntry:
        """Atomically assign monotonic sequence, link prev_hash, sign, and commit to WAL."""
        with self._lock:
            row = self._conn.execute(
                "SELECT seq, event_hash FROM ledger_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if row is None:
                next_seq = 1
                prev_hash = GENESIS_PREV_HASH
            else:
                next_seq = int(row["seq"]) + 1
                prev_hash = str(row["event_hash"])

            ts = timestamp or utc_now_iso()
            normalized_payload: dict[str, Any] = json.loads(canonical_json(payload))
            event_hash = compute_event_hash(
                seq=next_seq,
                prev_hash=prev_hash,
                timestamp=ts,
                tenant_id=tenant_id,
                workflow_id=workflow_id,
                event_type=event_type.value,
                payload=normalized_payload,
            )
            signature = self._signer.sign_digest(event_hash)
            pub_key = self._signer.public_key_hex

            self._conn.execute(
                """
                INSERT INTO ledger_events (
                    seq, timestamp, tenant_id, workflow_id, event_type,
                    payload_json, prev_hash, event_hash, signature, public_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    next_seq,
                    ts,
                    tenant_id,
                    workflow_id,
                    event_type.value,
                    canonical_json(normalized_payload),
                    prev_hash,
                    event_hash,
                    signature,
                    pub_key,
                ),
            )
            self._conn.commit()

            return LedgerEntry(
                seq=next_seq,
                timestamp=ts,
                tenant_id=tenant_id,
                workflow_id=workflow_id,
                event_type=event_type,
                payload=normalized_payload,
                prev_hash=prev_hash,
                event_hash=event_hash,
                signature=signature,
                public_key=pub_key,
            )

    def list_events(
        self,
        *,
        workflow_id: str | None = None,
        tenant_id: str | None = None,
        up_to_seq: int | None = None,
        limit: int = 1000,
    ) -> list[LedgerEntry]:
        clauses: list[str] = []
        params: list[Any] = []
        if workflow_id is not None:
            clauses.append("workflow_id = ?")
            params.append(workflow_id)
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if up_to_seq is not None:
            clauses.append("seq <= ?")
            params.append(up_to_seq)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM ledger_events {where_sql} ORDER BY seq ASC LIMIT ?"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def verify_chain_integrity(self) -> ChainVerificationReport:
        """Audit every event hash, prev_hash link, sequence continuity, and Ed25519 signature."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM ledger_events ORDER BY seq ASC").fetchall()

        expected_seq = 1
        expected_prev_hash = GENESIS_PREV_HASH
        hashes: list[str] = []

        for r in rows:
            seq = int(r["seq"])
            if seq != expected_seq:
                return ChainVerificationReport(
                    valid=False,
                    events_checked=seq - 1,
                    merkle_root=MerkleTree(hashes).root_hex,
                    corrupted_seq=seq,
                    failure_reason=f"Sequence gap detected: expected {expected_seq}, found {seq}",
                )

            prev_hash = str(r["prev_hash"])
            if prev_hash != expected_prev_hash:
                return ChainVerificationReport(
                    valid=False,
                    events_checked=seq - 1,
                    merkle_root=MerkleTree(hashes).root_hex,
                    corrupted_seq=seq,
                    failure_reason=f"Broken hash chain at seq {seq}: prev_hash mismatch",
                )

            try:
                payload = json.loads(str(r["payload_json"]))
            except json.JSONDecodeError:
                return ChainVerificationReport(
                    valid=False,
                    events_checked=seq - 1,
                    merkle_root=MerkleTree(hashes).root_hex,
                    corrupted_seq=seq,
                    failure_reason=f"Corrupted payload JSON at seq {seq}",
                )

            recomputed = compute_event_hash(
                seq=seq,
                prev_hash=prev_hash,
                timestamp=str(r["timestamp"]),
                tenant_id=str(r["tenant_id"]),
                workflow_id=str(r["workflow_id"]),
                event_type=str(r["event_type"]),
                payload=payload,
            )
            stored_hash = str(r["event_hash"])
            if recomputed != stored_hash:
                return ChainVerificationReport(
                    valid=False,
                    events_checked=seq - 1,
                    merkle_root=MerkleTree(hashes).root_hex,
                    corrupted_seq=seq,
                    failure_reason=f"Payload/metadata tampering detected at seq {seq}: SHA-256 mismatch",
                )

            if not LedgerSigner.verify_digest(
                str(r["public_key"]), stored_hash, str(r["signature"])
            ):
                return ChainVerificationReport(
                    valid=False,
                    events_checked=seq - 1,
                    merkle_root=MerkleTree(hashes).root_hex,
                    corrupted_seq=seq,
                    failure_reason=f"Invalid Ed25519 cryptographic signature at seq {seq}",
                )

            hashes.append(stored_hash)
            expected_prev_hash = stored_hash
            expected_seq += 1

        tree = MerkleTree(hashes)
        return ChainVerificationReport(
            valid=True,
            events_checked=len(hashes),
            merkle_root=tree.root_hex,
            corrupted_seq=None,
            failure_reason=None,
        )

    def generate_inclusion_proof(self, seq: int) -> MerkleInclusionProof:
        """Generate an RFC-6962 Merkle inclusion proof for event `seq` (1-indexed)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, event_hash FROM ledger_events ORDER BY seq ASC"
            ).fetchall()
        hashes = [str(r["event_hash"]) for r in rows]
        seq_list = [int(r["seq"]) for r in rows]
        if seq not in seq_list:
            raise KeyError(f"Ledger sequence {seq} does not exist")
        idx = seq_list.index(seq)
        return MerkleTree(hashes).prove_inclusion(idx)

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS cnt FROM ledger_events").fetchone()
            return int(row["cnt"]) if row else 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> LedgerEntry:
        return LedgerEntry(
            seq=int(row["seq"]),
            timestamp=str(row["timestamp"]),
            tenant_id=str(row["tenant_id"]),
            workflow_id=str(row["workflow_id"]),
            event_type=LedgerEventType(str(row["event_type"])),
            payload=json.loads(str(row["payload_json"])),
            prev_hash=str(row["prev_hash"]),
            event_hash=str(row["event_hash"]),
            signature=str(row["signature"]),
            public_key=str(row["public_key"]),
        )
