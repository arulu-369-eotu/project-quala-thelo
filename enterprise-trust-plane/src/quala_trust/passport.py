"""Reusable issuer credentials with holder possession and one-use presentations.

Credentials disclose signed control claims to the verifier, not source reports.
This format is not a W3C VC implementation and does not provide ZK disclosure.
"""
from __future__ import annotations

import re
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .engine import TrustPlane
from .protocol import (TrustError, canonical, digest, identifier, loads_strict,
                       validate_claims, _is_hex256)

PASSPORT_DOMAIN = b"QUALA-PASSPORT-V1\x00"
PRESENTATION_DOMAIN = b"QUALA-PRESENTATION-V1\x00"
PASSPORT_FIELDS = {"version", "passport_id", "subject", "issuer", "key_id",
                   "holder_key", "issued_at", "expires_at", "claims", "evidence_sha256"}
PRESENTATION_FIELDS = {"version", "passport_sha256", "nonce", "tenant", "audience",
                       "purpose", "issued_at", "expires_at"}


def instant(now: int | None) -> int:
    value = int(time.time()) if now is None else now
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        raise TrustError("invalid timestamp")
    return value


def lifetime(body: dict[str, Any], maximum: int) -> None:
    start, end = body["issued_at"], body["expires_at"]
    if type(start) is not int or type(end) is not int or start < 0 or not 1 <= end - start <= maximum:
        raise TrustError("invalid validity interval")


def passport_payload(body: Any) -> dict[str, Any]:
    if type(body) is not dict or set(body) != PASSPORT_FIELDS or body["version"] != "quala-passport-v1":
        raise TrustError("invalid passport schema")
    for name in ("passport_id", "subject", "issuer", "key_id"):
        identifier(body[name])
    if not _is_hex256(body["holder_key"]) or not _is_hex256(body["evidence_sha256"]):
        raise TrustError("invalid passport commitment or holder key")
    lifetime(body, 2592000)
    validate_claims(body["claims"])
    canonical(body)
    return body


def presentation_payload(body: Any) -> dict[str, Any]:
    if type(body) is not dict or set(body) != PRESENTATION_FIELDS or body["version"] != "quala-presentation-v1":
        raise TrustError("invalid presentation schema")
    for name in ("tenant", "audience", "purpose"):
        identifier(body[name])
    if not _is_hex256(body["passport_sha256"]) or not _is_hex256(body["nonce"]):
        raise TrustError("invalid presentation commitment")
    lifetime(body, 300)
    canonical(body)
    return body


def signed(body: dict[str, Any], domain: bytes, key: Ed25519PrivateKey) -> dict[str, Any]:
    snapshot = loads_strict(canonical(body))
    return {"payload": snapshot, "signature": key.sign(domain + canonical(snapshot)).hex()}


def authenticated(envelope: Any, domain: bytes, key: Ed25519PublicKey, validator) -> dict[str, Any]:
    if type(envelope) is not dict or set(envelope) != {"payload", "signature"}:
        raise TrustError("invalid signed credential envelope")
    body = validator(envelope["payload"])
    sig = envelope["signature"]
    if type(sig) is not str or re.fullmatch(r"[0-9a-f]{128}", sig) is None:
        raise TrustError("invalid credential signature encoding")
    try:
        key.verify(bytes.fromhex(sig), domain + canonical(body))
    except InvalidSignature as exc:
        raise TrustError("credential signature verification failed") from exc
    return body


def issue_passport(*, passport_id: str, subject: str, issuer: str, key_id: str,
                  holder_key: Ed25519PublicKey, claims: dict[str, Any], evidence_sha256: str,
                  signer: Ed25519PrivateKey, now: int | None = None,
                  lifetime_seconds: int = 86400) -> dict[str, Any]:
    at = instant(now)
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 2592000:
        raise TrustError("invalid passport lifetime")
    body = {"version": "quala-passport-v1", "passport_id": passport_id,
            "subject": subject, "issuer": issuer, "key_id": key_id,
            "holder_key": holder_key.public_bytes_raw().hex(), "claims": claims,
            "evidence_sha256": evidence_sha256, "issued_at": at,
            "expires_at": at + lifetime_seconds}
    passport_payload(body)
    return signed(body, PASSPORT_DOMAIN, signer)


def present_passport(passport: dict[str, Any], challenge: dict[str, Any], *,
                     holder_signer: Ed25519PrivateKey, now: int | None = None) -> dict[str, Any]:
    at = instant(now)
    if type(passport) is not dict or set(passport) != {"payload", "signature"}:
        raise TrustError("invalid passport envelope")
    body = passport_payload(passport["payload"])
    if holder_signer.public_key().public_bytes_raw().hex() != body["holder_key"]:
        raise TrustError("holder key mismatch")
    if type(challenge) is not dict or set(challenge) != {"tenant", "audience", "purpose", "nonce", "expires_at"}:
        raise TrustError("invalid challenge schema")
    end = challenge["expires_at"]
    if type(end) is not int or not at < end <= at + 300 or not body["issued_at"] <= at < body["expires_at"]:
        raise TrustError("expired passport or challenge")
    payload = {"version": "quala-presentation-v1", "passport_sha256": digest(passport),
               "nonce": challenge["nonce"], "tenant": challenge["tenant"],
               "audience": challenge["audience"], "purpose": challenge["purpose"],
               "issued_at": at, "expires_at": min(end, at + 60, body["expires_at"])}
    presentation_payload(payload)
    return {"passport": loads_strict(canonical(passport)),
            "presentation": signed(payload, PRESENTATION_DOMAIN, holder_signer)}


class PassportRevocations:
    """Operator-only persistent tombstones; no untrusted revocation endpoint."""

    def __init__(self, ledger):
        self.db = ledger.db
        self.db.execute("CREATE TABLE IF NOT EXISTS passport_revocations(issuer TEXT NOT NULL, passport_id TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(issuer,passport_id))")

    def revoke(self, issuer: str, passport_id: str, *, now: int | None = None) -> None:
        self.db.execute("INSERT OR IGNORE INTO passport_revocations VALUES(?,?,?)",
                        (identifier(issuer), identifier(passport_id), instant(now)))

    def check(self, issuer: str, passport_id: str) -> None:
        row = self.db.execute("SELECT 1 FROM passport_revocations WHERE issuer=? AND passport_id=?",
                              (issuer, passport_id)).fetchone()
        if row:
            raise TrustError("passport revoked")


class PassportTrustPlane(TrustPlane):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.revocations = PassportRevocations(self.ledger)

    def decide_passport(self, submitted: dict[str, Any], *, tenant: str, audience: str,
                        purpose: str, now: int | None = None) -> dict[str, Any]:
        at = instant(now)
        policy = self._policy(tenant, audience, purpose)
        envelope = loads_strict(canonical(submitted))
        if type(envelope) is not dict or set(envelope) != {"passport", "presentation"}:
            raise TrustError("invalid passport submission")
        passport = envelope["passport"]
        if type(passport) is not dict or type(passport.get("payload")) is not dict:
            raise TrustError("invalid passport envelope")
        candidate = passport["payload"]
        key = self.registry.lookup(tenant, candidate.get("issuer"), candidate.get("key_id"))
        credential = authenticated(passport, PASSPORT_DOMAIN, key, passport_payload)
        if not credential["issued_at"] <= at < credential["expires_at"]:
            raise TrustError("passport expired or not yet valid")
        if at - credential["issued_at"] > policy.max_credential_age_seconds:
            raise TrustError("passport exceeds policy freshness limit")
        self.revocations.check(credential["issuer"], credential["passport_id"])
        if policy.require_hardware_identity and not self.registry.hardware_verified(tenant, credential["issuer"], credential["key_id"], now=at):
            raise TrustError("hardware identity evidence unavailable or expired")
        holder = Ed25519PublicKey.from_public_bytes(bytes.fromhex(credential["holder_key"]))
        proof = authenticated(envelope["presentation"], PRESENTATION_DOMAIN, holder, presentation_payload)
        if (proof["tenant"], proof["audience"], proof["purpose"]) != (tenant, audience, purpose):
            raise TrustError("presentation scope mismatch")
        if proof["passport_sha256"] != digest(passport):
            raise TrustError("passport substitution")
        if not proof["issued_at"] <= at < proof["expires_at"] or at - proof["issued_at"] > policy.max_age_seconds:
            raise TrustError("presentation expired or not yet valid")
        reasons = policy.evaluate(credential["issuer"], credential["claims"])
        event = {"version": "quala-ledger-event-v1", "at": at, "tenant": tenant,
                 "audience": audience, "purpose": purpose, "issuer": credential["issuer"],
                 "key_id": credential["key_id"], "policy_id": policy.policy_id,
                 "policy_sha256": policy.sha256, "attestation_sha256": digest(envelope),
                 "evidence_sha256": credential["evidence_sha256"],
                 "decision": "DENY" if reasons else "ALLOW", "reason_codes": reasons,
                 "passport_id": credential["passport_id"], "subject": credential["subject"],
                 "passport_sha256": digest(passport), "presentation_sha256": digest(envelope["presentation"])}
        # Re-check revocation inside the same SQLite write transaction.
        def finalize(record):
            self.revocations.check(credential["issuer"], credential["passport_id"])
            return self._finalize(record, key, at)
        record = self.ledger.consume_and_append(nonce=proof["nonce"], tenant=tenant,
                    audience=audience, purpose=purpose, event=event, now=at, finalize=finalize)
        return record["signed_receipt"]
