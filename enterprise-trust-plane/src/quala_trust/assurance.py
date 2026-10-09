"""PROOF-369 signed checkpoint witnesses and bounded license entitlements.

Witnesses attest that they observed a checkpoint, not that its business claims
are true. Independent hosts and operators are a deployment requirement.
No blockchain, payment settlement, or autonomous royalty transfer is provided.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .ledger import ZERO_HASH
from .passport import instant, signed, authenticated, lifetime
from .protocol import TrustError, canonical, digest, identifier, loads_strict, _is_hex256, verify_receipt

CHECKPOINT_DOMAIN = b"PROOF369-CHECKPOINT-V1\x00"
WITNESS_DOMAIN = b"PROOF369-WITNESS-V1\x00"
ENTITLEMENT_DOMAIN = b"PROOF369-ENTITLEMENT-V1\x00"
CHECKPOINT_FIELDS = {"version", "network", "ledger_id", "verifier", "seq", "sha256",
                     "previous_seq", "previous_sha256", "issued_at", "expires_at"}


def checkpoint_payload(body: Any) -> dict[str, Any]:
    if type(body) is not dict or set(body) != CHECKPOINT_FIELDS or body["version"] != "proof369-checkpoint-v1":
        raise TrustError("invalid checkpoint schema")
    for name in ("network", "ledger_id", "verifier"):
        identifier(body[name])
    if type(body["seq"]) is not int or type(body["previous_seq"]) is not int or not 0 <= body["previous_seq"] < body["seq"]:
        raise TrustError("invalid checkpoint sequence")
    if not _is_hex256(body["sha256"]) or not _is_hex256(body["previous_sha256"]):
        raise TrustError("invalid checkpoint hash")
    if body["previous_seq"] == 0 and body["previous_sha256"] != ZERO_HASH:
        raise TrustError("invalid checkpoint origin")
    lifetime(body, 3600)
    canonical(body)
    return body


def create_checkpoint(ledger, *, network: str, ledger_id: str, verifier_id: str,
                      signer: Ed25519PrivateKey, previous_head: dict[str, Any] | None = None,
                      now: int | None = None, lifetime_seconds: int = 300) -> dict[str, Any]:
    at = instant(now)
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 3600:
        raise TrustError("invalid checkpoint lifetime")
    # One read transaction prevents mixing a validated prefix with another head.
    ledger.db.execute("BEGIN")
    try:
        if not ledger.verify_chain():
            raise TrustError("cannot checkpoint a corrupt ledger")
        head = ledger.head()
        previous = previous_head if previous_head is not None else {"seq": 0, "sha256": ZERO_HASH}
        if type(previous) is not dict or set(previous) != {"seq", "sha256"}:
            raise TrustError("invalid previous checkpoint")
        body = {"version": "proof369-checkpoint-v1", "network": network, "ledger_id": ledger_id,
                "verifier": verifier_id, "seq": head["seq"], "sha256": head["sha256"],
                "previous_seq": previous["seq"], "previous_sha256": previous["sha256"],
                "issued_at": at, "expires_at": at + lifetime_seconds}
        checkpoint_payload(body)
        result = signed(body, CHECKPOINT_DOMAIN, signer)
        ledger.db.commit()
        return result
    except BaseException:
        ledger.db.rollback()
        raise


def witness_payload(body: Any) -> dict[str, Any]:
    if type(body) is not dict or set(body) != {"version", "witness", "checkpoint_sha256", "observed_at"} or body["version"] != "proof369-witness-v1":
        raise TrustError("invalid witness receipt")
    identifier(body["witness"])
    if not _is_hex256(body["checkpoint_sha256"]) or type(body["observed_at"]) is not int or body["observed_at"] < 0:
        raise TrustError("invalid witness binding")
    canonical(body)
    return body


class Witness:
    """Use a separate database, identity, machine and administrative domain."""
    def __init__(self, db_path, *, witness_id: str, signer: Ed25519PrivateKey,
                 network: str, ledger_id: str, verifier_id: str,
                 trusted_verifier_key: Ed25519PublicKey):
        self.id, self.network, self.ledger_id, self.verifier_id = (
            identifier(x) for x in (witness_id, network, ledger_id, verifier_id))
        self._signer, self._verifier_key = signer, trusted_verifier_key
        self.db = sqlite3.connect(str(db_path), isolation_level=None, timeout=5)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS witness_identity(id INTEGER PRIMARY KEY CHECK(id=1), configuration TEXT NOT NULL)")
        configuration = canonical({"witness": self.id, "network": self.network,
                      "ledger_id": self.ledger_id, "verifier": self.verifier_id,
                      "witness_key": signer.public_key().public_bytes_raw().hex(),
                      "verifier_key": trusted_verifier_key.public_bytes_raw().hex()}).decode("ascii")
        self.db.execute("INSERT OR IGNORE INTO witness_identity VALUES(1,?)", (configuration,))
        if self.db.execute("SELECT configuration FROM witness_identity WHERE id=1").fetchone() != (configuration,):
            self.db.close()
            raise TrustError("witness database identity or scope changed")
        self.db.execute("CREATE TABLE IF NOT EXISTS witnessed(seq INTEGER PRIMARY KEY, sha256 TEXT NOT NULL, checkpoint_sha256 TEXT NOT NULL, receipt_json TEXT NOT NULL)")

    def observe(self, proposal: dict[str, Any], *, now: int | None = None) -> dict[str, Any]:
        at = instant(now)
        snapshot = loads_strict(canonical(proposal))
        body = authenticated(snapshot, CHECKPOINT_DOMAIN, self._verifier_key, checkpoint_payload)
        if (body["network"], body["ledger_id"], body["verifier"]) != (self.network, self.ledger_id, self.verifier_id):
            raise TrustError("checkpoint trust scope mismatch")
        if not body["issued_at"] <= at < body["expires_at"]:
            raise TrustError("checkpoint expired or not yet valid")
        commitment = digest(snapshot)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute("SELECT seq,sha256,checkpoint_sha256,receipt_json FROM witnessed ORDER BY seq DESC LIMIT 1").fetchone()
            if previous and body["seq"] == previous[0] and commitment == previous[2]:
                result = loads_strict(previous[3])
                self.db.commit()
                return result
            expected = (previous[0], previous[1]) if previous else (0, ZERO_HASH)
            if (body["previous_seq"], body["previous_sha256"]) != expected or body["seq"] <= expected[0]:
                raise TrustError("checkpoint rollback or fork rejected")
            receipt = signed({"version": "proof369-witness-v1", "witness": self.id,
                       "checkpoint_sha256": commitment, "observed_at": at}, WITNESS_DOMAIN, self._signer)
            self.db.execute("INSERT INTO witnessed VALUES(?,?,?,?)", (body["seq"], body["sha256"], commitment, canonical(receipt).decode("ascii")))
            self.db.commit()
            return receipt
        except BaseException:
            self.db.rollback()
            raise

    def close(self):
        self.db.close()


def verify_anchor(proposal: dict[str, Any], receipts: list[dict[str, Any]], *,
                  trusted_verifier_key: Ed25519PublicKey, witness_keys: dict[str, Ed25519PublicKey],
                  quorum: int, network: str, ledger_id: str, verifier_id: str,
                  expected_head: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    at = instant(now)
    proposal = loads_strict(canonical(proposal))
    receipts = loads_strict(canonical(receipts))
    witness_keys = dict(witness_keys)
    if type(quorum) is not int or not 1 <= quorum <= len(witness_keys) or len(witness_keys) > 32:
        raise TrustError("invalid witness quorum")
    # Multiple labels for the same signing key never count as independent votes.
    public_keys = [key.public_bytes_raw() for key in witness_keys.values()]
    if len(set(public_keys)) != len(public_keys):
        raise TrustError("duplicate witness trust key")
    if trusted_verifier_key.public_bytes_raw() in public_keys:
        raise TrustError("verifier cannot witness its own checkpoint")
    body = authenticated(proposal, CHECKPOINT_DOMAIN, trusted_verifier_key, checkpoint_payload)
    if (body["network"], body["ledger_id"], body["verifier"]) != (network, ledger_id, verifier_id):
        raise TrustError("anchor scope mismatch")
    if not body["issued_at"] <= at < body["expires_at"]:
        raise TrustError("anchor expired or not yet valid")
    if (type(expected_head) is not dict or type(expected_head.get("seq")) is not int
            or not _is_hex256(expected_head.get("sha256"))
            or expected_head != {"seq": body["seq"], "sha256": body["sha256"]}):
        raise TrustError("anchored head mismatch")
    if type(receipts) is not list or not 1 <= len(receipts) <= 32:
        raise TrustError("invalid witness receipt list")
    seen = set()
    for receipt in receipts:
        if type(receipt) is not dict or type(receipt.get("payload")) is not dict:
            raise TrustError("invalid witness envelope")
        name = identifier(receipt["payload"].get("witness"))
        key = witness_keys.get(name)
        if key is None or name in seen:
            raise TrustError("unknown or duplicate witness")
        witness = authenticated(receipt, WITNESS_DOMAIN, key, witness_payload)
        if witness["checkpoint_sha256"] != digest(proposal) or not body["issued_at"] <= witness["observed_at"] <= at:
            raise TrustError("witness checkpoint binding mismatch")
        seen.add(name)
    if len(seen) < quorum:
        raise TrustError("insufficient independent witness signatures")
    return body


def entitlement_payload(body: Any) -> dict[str, Any]:
    fields = {"version", "license_id", "licensor", "key_id", "tenant", "subject",
              "product", "capabilities", "issued_at", "expires_at", "agreement_sha256"}
    if type(body) is not dict or set(body) != fields or body["version"] != "proof369-entitlement-v1":
        raise TrustError("invalid entitlement schema")
    for name in ("license_id", "licensor", "key_id", "tenant", "subject", "product"):
        identifier(body[name])
    values = body["capabilities"]
    if type(values) is not list or not 1 <= len(values) <= 32 or any(type(v) is not str for v in values) or len(set(values)) != len(values):
        raise TrustError("invalid entitlement capabilities")
    for value in values:
        identifier(value)
    if not _is_hex256(body["agreement_sha256"]):
        raise TrustError("invalid agreement commitment")
    lifetime(body, 31622400)
    canonical(body)
    return body


def issue_entitlement(body: dict[str, Any], signer: Ed25519PrivateKey) -> dict[str, Any]:
    entitlement_payload(body)
    return signed(body, ENTITLEMENT_DOMAIN, signer)


class EntitlementVerifier:
    """Application entitlements, with durable operator revocations; no legal finding."""
    def __init__(self, ledger, registry):
        self.db, self.registry = ledger.db, registry
        self.db.execute("CREATE TABLE IF NOT EXISTS entitlement_revocations(licensor TEXT NOT NULL, license_id TEXT NOT NULL, PRIMARY KEY(licensor,license_id))")

    def revoke(self, licensor: str, license_id: str) -> None:
        self.db.execute("INSERT OR IGNORE INTO entitlement_revocations VALUES(?,?)", (identifier(licensor), identifier(license_id)))

    def verify(self, envelope: dict[str, Any], *, tenant: str, subject: str,
               product: str, capability: str, now: int | None = None) -> dict[str, Any]:
        at = instant(now)
        snapshot = loads_strict(canonical(envelope))
        if type(snapshot) is not dict or type(snapshot.get("payload")) is not dict:
            raise TrustError("invalid entitlement envelope")
        candidate = snapshot["payload"]
        # The registry supplied here must contain only approved licensing roots.
        key = self.registry.lookup(tenant, candidate.get("licensor"), candidate.get("key_id"))
        body = authenticated(snapshot, ENTITLEMENT_DOMAIN, key, entitlement_payload)
        if (body["tenant"], body["subject"], body["product"]) != (tenant, subject, product) or capability not in body["capabilities"]:
            raise TrustError("entitlement scope mismatch")
        if not body["issued_at"] <= at < body["expires_at"]:
            raise TrustError("entitlement expired or not yet valid")
        if self.db.execute("SELECT 1 FROM entitlement_revocations WHERE licensor=? AND license_id=?", (body["licensor"], body["license_id"])).fetchone():
            raise TrustError("entitlement revoked")
        return body


def licensed_receipt_access(*, receipt, entitlement, entitlement_verifier,
                           proposal, witness_receipts, trusted_verifier_key,
                           witness_keys, quorum, network, ledger_id, verifier_id,
                           tenant, subject, audience, purpose, policy_sha256,
                           product, capability, now: int | None = None):
    """Fail closed unless a fresh ALLOW receipt, anchor and license agree.

    This initial API requires the receipt to be the checkpoint's exact head.
    Older receipts need a future inclusion-proof implementation.
    """
    at = instant(now)
    receipt = loads_strict(canonical(receipt))
    entitlement = loads_strict(canonical(entitlement))
    proposal = loads_strict(canonical(proposal))
    witness_receipts = loads_strict(canonical(witness_receipts))
    verify_receipt(receipt, trusted_verifier_key)
    body = receipt["receipt"]
    if (body["tenant"], body.get("subject"), body["audience"], body["purpose"],
            body["verifier"], body["policy_sha256"]) != (tenant, subject, audience, purpose, verifier_id, policy_sha256):
        raise TrustError("licensed receipt scope mismatch")
    if body["decision"] != "ALLOW" or not 0 <= at - body["at"] <= 300:
        raise TrustError("licensed receipt denied or stale")
    verify_anchor(proposal, witness_receipts, trusted_verifier_key=trusted_verifier_key,
                  witness_keys=witness_keys, quorum=quorum, network=network,
                  ledger_id=ledger_id, verifier_id=verifier_id,
                  expected_head={"seq": body["ledger_seq"], "sha256": body["ledger_hash"]}, now=at)
    license_body = entitlement_verifier.verify(entitlement, tenant=tenant, subject=subject,
                   product=product, capability=capability, now=at)
    return {"authorized": True, "license_id": license_body["license_id"],
            "receipt_sha256": digest(receipt), "checkpoint_sha256": digest(proposal),
            "agreement_sha256": license_body["agreement_sha256"]}
