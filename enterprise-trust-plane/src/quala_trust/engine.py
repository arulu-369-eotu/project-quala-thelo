"""Fail-closed, policy-pinned, tenant-isolated challenge/response authorization."""
from __future__ import annotations

import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .ledger import TrustLedger
from .protocol import (
    RECEIPT_DOMAIN, IssuerRegistry, Policy, TrustError, canonical, digest,
    identifier, sign_attestation, verify_attestation,
    loads_strict,
)


class TrustPlane:
    def __init__(self, ledger: TrustLedger, registry: IssuerRegistry,
                 verifier_id: str, verifier_signing_key: Ed25519PrivateKey):
        self.ledger = ledger
        self.registry = registry
        self.verifier_id = identifier(verifier_id)
        if not isinstance(verifier_signing_key, Ed25519PrivateKey):
            raise TrustError("verifier signing key required")
        self._key = verifier_signing_key
        self._policies: dict[tuple[str, str, str], Policy] = {}

    def add_policy(self, policy: Policy) -> None:
        slot = (policy.tenant, policy.audience, policy.purpose)
        if slot in self._policies:
            raise TrustError("policy replacement requires explicit new verifier configuration")
        self._policies[slot] = policy

    def _policy(self, tenant: str, audience: str, purpose: str) -> Policy:
        for item in (tenant, audience, purpose):
            identifier(item)
        slot = (tenant, audience, purpose)
        if slot not in self._policies:
            raise TrustError("DENY: no exact-scope approved policy")
        return self._policies[slot]

    def challenge(self, *, tenant: str, audience: str, purpose: str,
                  ttl_seconds: int = 120, now: int | None = None) -> dict[str, Any]:
        policy = self._policy(tenant, audience, purpose)
        return self.ledger.issue(tenant=tenant, audience=audience,
                                 purpose=purpose, ttl_seconds=ttl_seconds, now=now,
                                 policy_sha256=policy.sha256)

    def decide(self, signed: dict[str, Any], *, tenant: str, audience: str,
               purpose: str, now: int | None = None) -> dict[str, Any]:
        """Return signed receipt only for authenticated, fresh, one-time challenges.

        Invalid signature/challenge/configuration raises TrustError: never allow.
        Valid evidence that misses business controls generates a DENY receipt.
        """
        instant = int(time.time()) if now is None else now
        if type(instant) is not int or instant < 0:
            raise TrustError("invalid decision time")
        policy = self._policy(tenant, audience, purpose)
        signed = loads_strict(canonical(signed))
        if type(signed) is not dict or type(signed.get("payload")) is not dict:
            raise TrustError("invalid attestation envelope")
        payload = signed["payload"]
        if (payload.get("tenant"), payload.get("audience"), payload.get("purpose")) != (
            tenant, audience, purpose
        ):
            raise TrustError("DENY: tenant, audience or purpose mismatch")
        key = self.registry.lookup(tenant, payload.get("issuer"), payload.get("key_id"))
        if policy.require_hardware_identity and not self.registry.hardware_verified(tenant, payload.get("issuer"), payload.get("key_id"), now=instant):
            raise TrustError("hardware identity evidence unavailable or expired")
        verified = verify_attestation(signed, key)
        if verified["issued_at"] > instant + 5:
            raise TrustError("attestation issued in the future")
        if instant < verified["issued_at"] - 5 or instant >= verified["expires_at"]:
            raise TrustError("attestation expired or not yet valid")
        if instant - verified["issued_at"] > policy.max_age_seconds:
            raise TrustError("attestation exceeds policy freshness limit")
        reasons = policy.evaluate(verified["issuer"], verified["claims"])
        outcome = "DENY" if reasons else "ALLOW"
        event = {
            "version": "quala-ledger-event-v1", "at": instant,
            "tenant": tenant, "audience": audience, "purpose": purpose,
            "issuer": verified["issuer"], "key_id": verified["key_id"],
            "policy_id": policy.policy_id, "policy_sha256": policy.sha256,
            "attestation_sha256": digest(verified),
            "evidence_sha256": verified["evidence_sha256"],
            "decision": outcome, "reason_codes": reasons,
        }
        record = self.ledger.consume_and_append(
            nonce=verified["nonce"], tenant=tenant, audience=audience,
            purpose=purpose, event=event, now=instant,
            finalize=lambda record: self._finalize(record, key, instant))
        return record["signed_receipt"]

    def _finalize(self, record, expected_key, at):
        event = record["event"]
        actual = self.registry.lookup(event["tenant"], event["issuer"], event["key_id"])
        if actual.public_bytes_raw() != expected_key.public_bytes_raw():
            raise TrustError("issuer identity changed during authorization")
        policy = self._policy(event["tenant"], event["audience"], event["purpose"])
        if policy.sha256 != event["policy_sha256"]:
            raise TrustError("policy changed during authorization")
        if policy.require_hardware_identity and not self.registry.hardware_verified(event["tenant"], event["issuer"], event["key_id"], now=at):
            raise TrustError("hardware identity unavailable during authorization")
        return self._sign_record(record)

    def _sign_record(self, record: dict[str, Any]) -> dict[str, Any]:
        body = {"version": "quala-receipt-v1", "verifier": self.verifier_id,
                "ledger_seq": record["seq"], "ledger_hash": record["entry_hash"],
                "previous_hash": record["previous_hash"],
                **{k: v for k, v in record["event"].items() if k != "version"}}
        signature = self._key.sign(RECEIPT_DOMAIN + canonical(body)).hex()
        return {"receipt": body, "signature": signature}


def issue_attestation(challenge: dict[str, Any], *, issuer: str,
                      key_id: str, claims: dict[str, Any], evidence_sha256: str,
                      signer: Ed25519PrivateKey, now: int | None = None,
                      lifetime_seconds: int = 60) -> dict[str, Any]:
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 300:
        raise TrustError("invalid attestation lifetime")
    instant = int(time.time()) if now is None else now
    if type(instant) is not int or instant < 0:
        raise TrustError("invalid attestation time")
    if type(challenge) is not dict or set(challenge) != {
        "tenant", "audience", "purpose", "nonce", "expires_at"
    }:
        raise TrustError("invalid challenge schema")
    expiration = challenge["expires_at"]
    if type(expiration) is not int or expiration <= instant:
        raise TrustError("expired challenge")
    payload = {"version": "quala-attestation-v1",
               "issuer": issuer, "key_id": key_id,
               "tenant": challenge["tenant"], "audience": challenge["audience"],
               "purpose": challenge["purpose"], "nonce": challenge["nonce"],
               "issued_at": instant, "expires_at": min(expiration, instant + lifetime_seconds),
               "claims": claims, "evidence_sha256": evidence_sha256}
    return sign_attestation(payload, signer)
