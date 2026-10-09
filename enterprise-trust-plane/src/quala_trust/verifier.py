"""QUA'LA Trust Passport reference verifier (single-node prototype).

SQLite transactions atomically consume challenges. Production requires
reviewed durable trust-root provisioning, key custody and independent audit.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .protocol import (
    Policy, IssuerRegistry, TrustError, RECEIPT_DOMAIN, canonical,
    digest, identifier, sign_attestation, verify_attestation,
)


class PassportVerifier:
    def __init__(self, database: str | Path, registry: IssuerRegistry,
                 signing_key: Ed25519PrivateKey):
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise TypeError("a verifier signing key is required")
        self.registry = registry
        self.signing_key = signing_key
        self.db = sqlite3.connect(str(database), isolation_level=None, timeout=5)
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS challenges (
            nonce TEXT PRIMARY KEY,
            tenant TEXT NOT NULL,
            audience TEXT NOT NULL,
            purpose TEXT NOT NULL,
            expires INTEGER NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1))
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT NOT NULL,
            signature TEXT NOT NULL
        )""")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self) -> None:
        self.db.close()

    def challenge(self, tenant: str, audience: str, purpose: str,
                  *, now: int | None = None, ttl: int = 90) -> str:
        for value in (tenant, audience, purpose):
            identifier(value)
        if type(ttl) is not int or not 1 <= ttl <= 300:
            raise TrustError("invalid challenge lifetime")
        stamp = int(time.time()) if now is None else now
        if type(stamp) is not int or stamp < 0:
            raise TrustError("invalid time")
        nonce = os.urandom(32).hex()
        self.db.execute("INSERT INTO challenges VALUES (?,?,?,?,?,0)",
                        (nonce, tenant, audience, purpose, stamp + ttl))
        return nonce

    def verify(self, envelope: dict[str, Any], policy: Policy,
               *, now: int | None = None) -> dict[str, Any]:
        """Fail closed and atomically consume a challenge even on invalid claims.

        Parsing, policy checks and signing errors rollback the transaction;
        invalid signatures cannot consume someone else's challenge.
        """
        stamp = int(time.time()) if now is None else now
        if type(stamp) is not int or stamp < 0:
            raise TrustError("invalid time")
        if type(envelope) is not dict or type(envelope.get("payload")) is not dict:
            raise TrustError("invalid request")
        p = envelope["payload"]
        # Look up scoped trust root, then authenticate before reading nonce.
        try:
            key = self.registry.lookup(p["tenant"], p["issuer"], p["key_id"])
        except (KeyError, TypeError) as exc:
            raise TrustError("invalid issuer identification") from exc
        payload = verify_attestation(envelope, key)
        if (payload["tenant"], payload["audience"], payload["purpose"]) != (
            policy.tenant, policy.audience, policy.purpose
        ):
            raise TrustError("policy scope mismatch")
        if payload["issued_at"] > stamp + 10 or payload["expires_at"] <= stamp:
            raise TrustError("attestation expired or from future")
        if stamp - payload["issued_at"] > policy.max_age_seconds:
            raise TrustError("attestation exceeds policy maximum age")

        # BEGIN IMMEDIATE serializes writers across independent processes.
        self.db.execute("BEGIN IMMEDIATE")
        try:
            record = self.db.execute(
                "SELECT tenant,audience,purpose,expires,consumed "
                "FROM challenges WHERE nonce=?", (payload["nonce"],)
            ).fetchone()
            if (record is None or record[4] or record[3] <= stamp or
                    tuple(record[:3]) != (
                        policy.tenant, policy.audience, policy.purpose
                    )):
                raise TrustError("missing, expired, consumed or mismatched challenge")
            updated = self.db.execute(
                "UPDATE challenges SET consumed=1 WHERE nonce=? AND consumed=0",
                (payload["nonce"],)
            ).rowcount
            if updated != 1:
                raise TrustError("challenge already consumed")
            failures = policy.evaluate(payload["issuer"], payload["claims"])
            body = {
                "version": "quala-receipt-v1",
                "nonce": payload["nonce"],
                "policy_sha256": policy.sha256,
                "attestation_sha256": digest(payload),
                "tenant": policy.tenant,
                "audience": policy.audience,
                "purpose": policy.purpose,
                "evaluated_at": stamp,
                "decision": "DENY" if failures else "ALLOW",
                "reasons": failures,
            }
            signature = self.signing_key.sign(RECEIPT_DOMAIN + canonical(body)).hex()
            self.db.execute("INSERT INTO receipts(payload,signature) VALUES (?,?)",
                            (canonical(body).decode("ascii"), signature))
            self.db.execute("COMMIT")
            return {"receipt": body, "signature": signature}
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
