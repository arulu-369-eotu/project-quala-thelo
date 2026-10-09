"""PROOF-369 external witness reference: monotonic signed checkpoints.

Deploy a witness on infrastructure controlled by an independent operator with
its own keys and SQLite state. A local process alone is NOT independent.
"""
from __future__ import annotations

from dataclasses import dataclass
import sqlite3
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .protocol import TrustError, canonical, digest, identifier, loads_strict
from .proof369 import GENESIS, verify_export, verify_checkpoint

WITNESS_DOMAIN = b"PROOF-369-WITNESS-v1\x00"
WITNESS_VERSION = "proof369-witness-v1"
KEY_FINGERPRINT_DOMAIN = b"PROOF-369-WITNESS-KEY-v1\x00"


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    import hashlib
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(KEY_FINGERPRINT_DOMAIN + raw).hexdigest()


def verify_witness_receipt(
    signed: Any, key: Ed25519PublicKey, expected_id: str,
    checkpoint: dict[str, Any],
) -> dict[str, Any]:
    """Verify signature, pinned witness identity, and exact checkpoint binding."""
    identifier(expected_id)
    if type(signed) is not dict or set(signed) != {"receipt", "signature"}:
        raise TrustError("invalid witness envelope")
    receipt = signed["receipt"]
    if type(receipt) is not dict or set(receipt) != {
        "version", "witness_id", "tenant", "sequence", "head",
        "checkpoint_sha256", "recorded_at", "previous_receipt_sha256",
    }:
        raise TrustError("invalid witness receipt schema")
    if receipt["version"] != WITNESS_VERSION or receipt["witness_id"] != expected_id:
        raise TrustError("witness version or identity mismatch")
    if (receipt["tenant"], receipt["sequence"], receipt["head"]) != (
        checkpoint["tenant"], checkpoint["sequence"], checkpoint["head"]
    ):
        raise TrustError("witness checkpoint mismatch")
    for field in ("checkpoint_sha256", "previous_receipt_sha256"):
        value = receipt[field]
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise TrustError("invalid witness hash")
    if type(receipt["recorded_at"]) is not int or receipt["recorded_at"] < 0:
        raise TrustError("invalid witness time")
    if receipt["checkpoint_sha256"] != digest(checkpoint):
        raise TrustError("untrusted checkpoint digest")
    signature = signed["signature"]
    if type(signature) is not str or len(signature) != 128:
        raise TrustError("invalid witness signature")
    try:
        key.verify(bytes.fromhex(signature), WITNESS_DOMAIN + canonical(receipt))
    except (InvalidSignature, ValueError) as exc:
        raise TrustError("invalid witness signature") from exc
    return receipt


class WitnessStore:
    """Persistent, independently deployable witness with anti-rollback memory."""

    def __init__(self, db_path: str | Path, witness_id: str, tenant: str,
                 checkpoint_key: Ed25519PublicKey, signing_key: Ed25519PrivateKey,
                 *, max_checkpoint_age: int = 86_400):
        self.witness_id = identifier(witness_id)
        self.tenant = identifier(tenant)
        if (not isinstance(checkpoint_key, Ed25519PublicKey) or
                not isinstance(signing_key, Ed25519PrivateKey)):
            raise TrustError("pinned Ed25519 trust root and witness signer required")
        if type(max_checkpoint_age) is not int or not 1 <= max_checkpoint_age <= 604_800:
            raise TrustError("invalid checkpoint age policy")
        self.checkpoint_key = checkpoint_key
        self.signing_key = signing_key
        self.max_checkpoint_age = max_checkpoint_age
        self.db = sqlite3.connect(str(db_path), isolation_level=None, timeout=5)
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS witness_receipts (
          tenant TEXT NOT NULL, witness_id TEXT NOT NULL,
          sequence INTEGER NOT NULL, head TEXT NOT NULL,
          checkpoint_sha256 TEXT NOT NULL, receipt BLOB NOT NULL,
          PRIMARY KEY(tenant,witness_id,sequence)
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS witness_identity (
          witness_id TEXT PRIMARY KEY, tenant TEXT NOT NULL,
          checkpoint_key_fingerprint TEXT NOT NULL,
          witness_key_fingerprint TEXT NOT NULL
        )""")
        self.db.execute(
            "INSERT OR IGNORE INTO witness_identity VALUES (?,?,?,?)",
            (self.witness_id, self.tenant,
             public_key_fingerprint(checkpoint_key),
             public_key_fingerprint(signing_key.public_key()))
        )
        identity = self.db.execute("SELECT tenant,checkpoint_key_fingerprint,witness_key_fingerprint "
                                   "FROM witness_identity WHERE witness_id=?",
                                   (self.witness_id,)).fetchone()
        if identity != (self.tenant, public_key_fingerprint(checkpoint_key),
                        public_key_fingerprint(signing_key.public_key())):
            raise TrustError("witness identity changed across restart")

    def __enter__(self) -> "WitnessStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self.db.close()

    def witness(self, evidence: dict[str, Any], *, now: int | None = None) -> dict[str, Any]:
        if type(evidence) is not dict or set(evidence) != {"records", "signed_checkpoint"}:
            raise TrustError("invalid evidence package")
        signed = evidence["signed_checkpoint"]
        rows = evidence["records"]
        if not verify_export(rows, signed, self.checkpoint_key):
            raise TrustError("PROOF-369 evidence failed verification")
        check = verify_checkpoint(signed, self.checkpoint_key)
        if check["tenant"] != self.tenant:
            raise TrustError("witness tenant mismatch")
        stamp = int(time.time()) if now is None else now
        if type(stamp) is not int or stamp < 0:
            raise TrustError("invalid time")
        if check["issued_at"] > stamp + 60 or stamp - check["issued_at"] > self.max_checkpoint_age:
            raise TrustError("stale or future checkpoint")
        target_digest = digest(check)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            prior = self.db.execute(
                "SELECT sequence,head,checkpoint_sha256,receipt "
                "FROM witness_receipts WHERE tenant=? AND witness_id=? "
                "ORDER BY sequence DESC LIMIT 1",
                (self.tenant, self.witness_id),
            ).fetchone()
            if prior is not None:
                old_seq, old_head, old_digest, old_receipt_json = prior
                if check["sequence"] == old_seq and check["head"] == old_head and target_digest == old_digest:
                    out = loads_strict(old_receipt_json)
                    self.db.execute("COMMIT")
                    return out
                if check["sequence"] <= old_seq:
                    raise TrustError("rollback or conflicting checkpoint rejected")
                if old_seq and (len(rows) < old_seq or rows[old_seq - 1]["hash"] != old_head):
                    raise TrustError("checkpoint fork or erased history detected")
                prev = digest(loads_strict(old_receipt_json))
            else:
                prev = GENESIS
            body = {
                "version": WITNESS_VERSION, "witness_id": self.witness_id,
                "tenant": self.tenant, "sequence": check["sequence"],
                "head": check["head"], "checkpoint_sha256": target_digest,
                "recorded_at": stamp, "previous_receipt_sha256": prev,
            }
            signed_receipt = {
                "receipt": body,
                "signature": self.signing_key.sign(WITNESS_DOMAIN + canonical(body)).hex(),
            }
            self.db.execute("INSERT INTO witness_receipts VALUES (?,?,?,?,?,?)",
                            (self.tenant, self.witness_id, check["sequence"],
                             check["head"], target_digest, canonical(signed_receipt)))
            self.db.execute("COMMIT")
            return signed_receipt
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
