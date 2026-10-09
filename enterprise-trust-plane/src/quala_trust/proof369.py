"""PROOF-369 v0.1: independently checkable measurement records.

This is a single-writer local prototype. Signatures authenticate a checkpoint
only under an independently trusted key. A local chain does NOT provide
independent anchoring, anti-equivocation or hardware-backed provenance.
"""
from __future__ import annotations

import hashlib
import sqlite3
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .protocol import TrustError, canonical, digest, identifier

GENESIS = "0" * 64
RECORD_DOMAIN = b"PROOF-369-RECORD-v1\x00"
CHECKPOINT_DOMAIN = b"PROOF-369-CHECKPOINT-v1\x00"
ALLOWED_OUTCOMES = frozenset({"PASS", "FAIL", "UNTESTED"})
ALLOWED_METRICS = frozenset({
    "test_count", "passed_count", "failed_count", "skipped_count",
    "duration_ms", "coverage_basis_points", "finding_count",
})


def validate_measurement(record: Any) -> dict[str, Any]:
    if type(record) is not dict or set(record) != {
        "version", "subject", "tenant", "control", "outcome",
        "source_sha256", "measured_at", "metrics"
    }:
        raise TrustError("invalid measurement schema")
    if record["version"] != "proof369-measurement-v1":
        raise TrustError("unsupported measurement version")
    for key in ("subject", "tenant", "control"):
        identifier(record[key])
    if record["outcome"] not in ALLOWED_OUTCOMES:
        raise TrustError("unsupported measurement outcome")
    value = record["source_sha256"]
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise TrustError("invalid source commitment")
    if type(record["measured_at"]) is not int or record["measured_at"] < 0:
        raise TrustError("invalid measurement timestamp")
    metrics = record["metrics"]
    if type(metrics) is not dict or not metrics or not set(metrics).issubset(ALLOWED_METRICS):
        raise TrustError("invalid measurable metrics")
    for v in metrics.values():
        if type(v) is not int or not 0 <= v <= 1_000_000_000:
            raise TrustError("metrics must be bounded nonnegative integers")
    if "coverage_basis_points" in metrics and metrics["coverage_basis_points"] > 10_000:
        raise TrustError("coverage exceeds 100 percent")
    if {"test_count", "passed_count", "failed_count", "skipped_count"} <= set(metrics):
        if metrics["passed_count"] + metrics["failed_count"] + metrics["skipped_count"] != metrics["test_count"]:
            raise TrustError("inconsistent test counts")
        if record["outcome"] == "PASS" and (metrics["failed_count"] or metrics["skipped_count"]):
            raise TrustError("PASS cannot conceal failed or skipped tests")
        if record["outcome"] == "PASS" and metrics["test_count"] == 0:
            raise TrustError("zero tests do not constitute a PASS")
    elif record["outcome"] == "PASS":
        raise TrustError("PASS requires all four test counts")
    canonical(record)
    return record


def row_hash(seq: int, previous: str, measurement: dict[str, Any]) -> str:
    if type(seq) is not int or seq < 1 or type(previous) is not str or len(previous) != 64:
        raise TrustError("invalid chain inputs")
    validate_measurement(measurement)
    return hashlib.sha256(RECORD_DOMAIN + canonical({
        "seq": seq, "previous": previous, "measurement": measurement
    })).hexdigest()


def checkpoint_body(tenant: str, sequence: int, head: str, issued_at: int) -> dict[str, Any]:
    identifier(tenant)
    if type(sequence) is not int or sequence < 0:
        raise TrustError("invalid checkpoint sequence")
    if type(head) is not str or len(head) != 64 or any(c not in "0123456789abcdef" for c in head):
        raise TrustError("invalid checkpoint hash")
    if type(issued_at) is not int or issued_at < 0:
        raise TrustError("invalid checkpoint time")
    return {"version": "proof369-checkpoint-v1", "tenant": tenant,
            "sequence": sequence, "head": head, "issued_at": issued_at}


def verify_checkpoint(signed: Any, public_key: Ed25519PublicKey) -> dict[str, Any]:
    if type(signed) is not dict or set(signed) != {"checkpoint", "signature"}:
        raise TrustError("invalid checkpoint envelope")
    body = signed["checkpoint"]
    if type(body) is not dict or set(body) != {"version", "tenant", "sequence", "head", "issued_at"}:
        raise TrustError("invalid checkpoint fields")
    expected = checkpoint_body(body["tenant"], body["sequence"],
                               body["head"], body["issued_at"])
    if body != expected or body["version"] != "proof369-checkpoint-v1":
        raise TrustError("unsupported checkpoint")
    sig = signed["signature"]
    if type(sig) is not str or len(sig) != 128:
        raise TrustError("invalid signature")
    try:
        public_key.verify(bytes.fromhex(sig), CHECKPOINT_DOMAIN + canonical(body))
    except (ValueError, InvalidSignature) as exc:
        raise TrustError("untrusted checkpoint") from exc
    return body


def verify_export(rows: Any, signed: Any, public_key: Ed25519PublicKey) -> bool:
    """Fail closed on omission, reordering, modification or checkpoint mismatch."""
    check = verify_checkpoint(signed, public_key)
    if type(rows) is not list or len(rows) != check["sequence"]:
        raise TrustError("missing or extra evidence records")
    previous = GENESIS
    for index, row in enumerate(rows, 1):
        if type(row) is not dict or set(row) != {"seq", "previous", "measurement", "hash"}:
            raise TrustError("invalid exported record")
        if type(row["seq"]) is not int or row["seq"] != index or row["previous"] != previous:
            raise TrustError("broken evidence ordering")
        if row["measurement"].get("tenant") != check["tenant"]:
            raise TrustError("evidence tenant mismatch")
        actual = row_hash(index, previous, row["measurement"])
        if row["hash"] != actual:
            raise TrustError("tampered evidence")
        previous = actual
    if previous != check["head"]:
        raise TrustError("checkpoint does not match evidence")
    return True


class EvidenceLedger:
    """Single-tenant SQLite writer with full-chain validation before append.

    Do not share this database with untrusted writers; a database administrator
    can rewrite history and re-sign if given the signing key.
    """

    def __init__(self, database: str, tenant: str, signer: Ed25519PrivateKey):
        self.tenant = identifier(tenant)
        if not isinstance(signer, Ed25519PrivateKey):
            raise TrustError("signing key required")
        self.signer = signer
        self.db = sqlite3.connect(database, isolation_level=None, timeout=5)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("""CREATE TABLE IF NOT EXISTS evidence (
            tenant TEXT NOT NULL, seq INTEGER NOT NULL, previous TEXT NOT NULL,
            payload BLOB NOT NULL, hash TEXT NOT NULL,
            PRIMARY KEY(tenant,seq))""")

    def close(self) -> None:
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _rows(self) -> list[dict[str, Any]]:
        from .protocol import loads_strict
        output = []
        for seq, previous, raw, value in self.db.execute(
            "SELECT seq,previous,payload,hash FROM evidence WHERE tenant=? ORDER BY seq",
            (self.tenant,)
        ):
            output.append({"seq": seq, "previous": previous,
                           "measurement": loads_strict(raw), "hash": value})
        return output

    def _validate(self, rows: list[dict[str, Any]]) -> str:
        previous = GENESIS
        for i, item in enumerate(rows, 1):
            if type(item["seq"]) is not int or item["seq"] != i or item["previous"] != previous:
                raise TrustError("ledger chain ordering corrupted")
            if item["measurement"].get("tenant") != self.tenant:
                raise TrustError("ledger tenant mismatch")
            expected = row_hash(i, previous, item["measurement"])
            if item["hash"] != expected:
                raise TrustError("ledger tampering detected")
            previous = expected
        return previous

    def append(self, measurement: dict[str, Any]) -> dict[str, Any]:
        validate_measurement(measurement)
        if measurement["tenant"] != self.tenant:
            raise TrustError("cross-tenant evidence forbidden")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            existing = self._rows()
            head = self._validate(existing)
            seq = len(existing) + 1
            hashed = row_hash(seq, head, measurement)
            self.db.execute("INSERT INTO evidence VALUES (?,?,?,?,?)",
                            (self.tenant, seq, head, canonical(measurement), hashed))
            self.db.execute("COMMIT")
            return {"seq": seq, "previous": head,
                    "measurement": measurement, "hash": hashed}
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def export(self, *, issued_at: int | None = None) -> dict[str, Any]:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            rows = self._rows()
            head = self._validate(rows)
            body = checkpoint_body(self.tenant, len(rows), head,
                                   int(time.time()) if issued_at is None else issued_at)
            signature = self.signer.sign(CHECKPOINT_DOMAIN + canonical(body)).hex()
            signed = {"checkpoint": body, "signature": signature}
            self.db.execute("COMMIT")
            return {"records": rows, "signed_checkpoint": signed}
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
