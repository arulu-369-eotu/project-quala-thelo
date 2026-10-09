"""SQLite-backed, one-time challenges and a locally tamper-evident decision log.

Integrity is *detectable*, not immutable against a database administrator.
Export signed head checkpoints to an independent system for rollback detection.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable

from .protocol import TrustError, canonical, identifier, _is_hex256, loads_strict

ZERO_HASH = "0" * 64
LEDGER_DOMAIN = b"QU'ALA-LEDGER-V1\x00"


def nonce_hash(nonce: str) -> str:
    if not _is_hex256(nonce):
        raise TrustError("invalid nonce encoding")
    return hashlib.sha256(b"QU'ALA-NONCE-V1\x00" + bytes.fromhex(nonce)).hexdigest()


def entry_hash(previous: str, event: dict[str, Any]) -> str:
    return hashlib.sha256(LEDGER_DOMAIN + bytes.fromhex(previous) + canonical(event)).hexdigest()


class TrustLedger:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self.db = sqlite3.connect(self.db_path, timeout=5.0, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS challenges(
                commitment TEXT PRIMARY KEY,
                tenant TEXT NOT NULL,
                audience TEXT NOT NULL,
                purpose TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1))
            );
            CREATE TABLE IF NOT EXISTS ledger(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                event_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS receipts(
                seq INTEGER PRIMARY KEY REFERENCES ledger(seq),
                receipt_json TEXT NOT NULL
            );
        """)
        columns = {r[1] for r in self.db.execute("PRAGMA table_info(challenges)")}
        if "policy_sha256" not in columns:
            self.db.execute("ALTER TABLE challenges ADD COLUMN policy_sha256 TEXT NOT NULL DEFAULT ''")
        if "issued_at" not in columns:
            self.db.execute("ALTER TABLE challenges ADD COLUMN issued_at INTEGER NOT NULL DEFAULT 0")

    def issue(self, *, tenant: str, audience: str, purpose: str,
              ttl_seconds: int = 120, now: int | None = None,
              policy_sha256: str = ZERO_HASH) -> dict[str, Any]:
        for name in (tenant, audience, purpose):
            identifier(name)
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 300:
            raise TrustError("challenge TTL out of bounds")
        instant = int(time.time()) if now is None else now
        if type(instant) is not int or instant < 0:
            raise TrustError("invalid time")
        if not _is_hex256(policy_sha256) or not self.verify_chain():
            raise TrustError("invalid policy pin or corrupt ledger")
        nonce = secrets.token_hex(32)
        until = instant + ttl_seconds
        self.db.execute("INSERT INTO challenges(commitment,tenant,audience,purpose,expires_at,consumed,policy_sha256,issued_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
                        (nonce_hash(nonce), tenant, audience, purpose, until, policy_sha256, instant))
        return {"tenant": tenant, "audience": audience, "purpose": purpose,
                "nonce": nonce, "expires_at": until}

    def consume_and_append(self, *, nonce: str, tenant: str, audience: str,
                           purpose: str, event: dict[str, Any], now: int,
                           finalize: Callable[[dict[str, Any]], dict[str, Any]] | None = None) -> dict[str, Any]:
        if type(now) is not int or now < 0:
            raise TrustError("invalid decision time")
        commitment = nonce_hash(nonce)
        try:
            self.db.execute("BEGIN IMMEDIATE")
            if not self.verify_chain():
                raise TrustError("corrupt ledger: authorization refused")
            row = self.db.execute(
                "SELECT tenant, audience, purpose, expires_at, consumed, policy_sha256, issued_at "
                "FROM challenges WHERE commitment=?", (commitment,)
            ).fetchone()
            if row is None or row[:3] != (tenant, audience, purpose):
                raise TrustError("challenge missing or bound to another scope")
            if row[4] != 0:
                raise TrustError("replayed challenge")
            if now < row[6] or now >= row[3]:
                raise TrustError("expired challenge")
            if event.get("policy_sha256") != row[5]:
                raise TrustError("challenge policy changed")
            self.db.execute("UPDATE challenges SET consumed=1 WHERE commitment=? AND consumed=0",
                            (commitment,))
            previous = self.db.execute(
                "SELECT entry_hash FROM ledger ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prior = previous[0] if previous else ZERO_HASH
            event = dict(event)
            event["nonce_commitment"] = commitment
            h = entry_hash(prior, event)
            cur = self.db.execute(
                "INSERT INTO ledger(previous_hash, entry_hash, event_json) VALUES (?, ?, ?)",
                (prior, h, canonical(event).decode("ascii")),
            )
            seq = cur.lastrowid
            record = {"seq": seq, "previous_hash": prior, "entry_hash": h, "event": event}
            if finalize is not None:
                receipt = finalize(record)
                self.db.execute("INSERT INTO receipts VALUES (?, ?)", (seq, canonical(receipt).decode("ascii")))
                record["signed_receipt"] = receipt
            self.db.commit()
            return record
        except Exception:
            self.db.rollback()
            raise

    def purge_expired_challenges(self, *, now: int | None = None) -> int:
        """Operational maintenance; expired challenges cannot authorize actions."""
        instant = int(time.time()) if now is None else now
        if type(instant) is not int or instant < 0:
            raise TrustError("invalid maintenance timestamp")
        cur = self.db.execute("DELETE FROM challenges WHERE expires_at <= ?", (instant,))
        return cur.rowcount

    def head(self) -> dict[str, Any]:
        row = self.db.execute(
            "SELECT seq, entry_hash FROM ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return {"seq": row[0], "sha256": row[1]} if row else {"seq": 0, "sha256": ZERO_HASH}

    def verify_chain(self, *, expected_head: dict[str, Any] | None = None) -> bool:
        previous = ZERO_HASH
        expected_seq = 1
        for seq, prev, observed, serialized in self.db.execute(
            "SELECT seq, previous_hash, entry_hash, event_json FROM ledger ORDER BY seq"
        ):
            try:
                event = loads_strict(serialized)
                valid = (type(event) is dict and canonical(event).decode("ascii") == serialized
                         and prev == previous and seq == expected_seq
                         and entry_hash(previous, event) == observed)
            except (ValueError, TypeError):
                valid = False
            if not valid:
                return False
            previous = observed
            expected_seq += 1
        if expected_head is not None and expected_head != self.head():
            return False
        return True

    def receipt(self, seq: int) -> dict[str, Any]:
        if type(seq) is not int or seq < 1:
            raise TrustError("invalid receipt sequence")
        row = self.db.execute("SELECT receipt_json FROM receipts WHERE seq=?", (seq,)).fetchone()
        if row is None:
            raise TrustError("receipt unavailable")
        return loads_strict(row[0])

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "TrustLedger":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
