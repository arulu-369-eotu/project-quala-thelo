"""Portable tests: run with pip install -e '.[test]' inside enterprise-trust-plane."""
import hashlib
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from quala_trust.protocol import (
    IssuerRegistry, Policy, Rule, TrustError, sign_attestation, verify_receipt
)
from quala_trust.verifier import PassportVerifier


def setup(tmp_path):
    issuer_key = Ed25519PrivateKey.generate()
    verifier_key = Ed25519PrivateKey.generate()
    registry = IssuerRegistry()
    registry.enroll("bank1", "auditor", "key1", issuer_key.public_key())
    policy = Policy(
        "procurement", "bank1", "portal", "vendor-review",
        ("auditor",), (Rule("compliant", "eq", True),), 120
    )
    verifier = PassportVerifier(tmp_path / "state.sqlite3", registry, verifier_key)
    return issuer_key, verifier_key, registry, policy, verifier


def make_signed(key, nonce, now, claims=None):
    return sign_attestation({
        "version": "quala-attestation-v1",
        "issuer": "auditor", "key_id": "key1", "tenant": "bank1",
        "audience": "portal", "purpose": "vendor-review",
        "nonce": nonce, "issued_at": now, "expires_at": now + 60,
        "claims": {"compliant": True} if claims is None else claims,
        "evidence_sha256": hashlib.sha256(b"evidence").hexdigest(),
    }, key)


def test_authorize_once_then_deny_replay(tmp_path):
    key, vkey, _, policy, verifier = setup(tmp_path)
    now = int(time.time())
    nonce = verifier.challenge("bank1", "portal", "vendor-review", now=now)
    signed = make_signed(key, nonce, now)
    receipt = verifier.verify(signed, policy, now=now)
    assert receipt["receipt"]["decision"] == "ALLOW"
    assert verify_receipt(receipt, vkey.public_key())
    with pytest.raises(TrustError):
        verifier.verify(signed, policy, now=now)
    verifier.close()


def test_negative_policy_decision_is_signed(tmp_path):
    key, vkey, _, policy, verifier = setup(tmp_path)
    now = int(time.time())
    nonce = verifier.challenge("bank1", "portal", "vendor-review", now=now)
    denied = verifier.verify(make_signed(key, nonce, now, {"compliant": False}),
                             policy, now=now)
    assert denied["receipt"]["decision"] == "DENY"
    assert "CONTROL_FAILED:compliant" in denied["receipt"]["reasons"]
    assert verify_receipt(denied, vkey.public_key())
    verifier.close()


def test_tampering_and_cross_tenant_scope_fail_closed(tmp_path):
    key, _, _, policy, verifier = setup(tmp_path)
    now = int(time.time())
    nonce = verifier.challenge("bank1", "portal", "vendor-review", now=now)
    signed = make_signed(key, nonce, now)
    signed["payload"]["claims"]["compliant"] = False
    with pytest.raises(TrustError):
        verifier.verify(signed, policy, now=now)
    wrong_policy = Policy("other", "bank2", "portal", "vendor-review",
                          ("auditor",), (Rule("compliant", "eq", True),))
    with pytest.raises(TrustError):
        verifier.verify(make_signed(key, nonce, now), wrong_policy, now=now)
    verifier.close()


def test_expiry_and_durable_replay_across_restart(tmp_path):
    key, vkey, registry, policy, verifier = setup(tmp_path)
    now = int(time.time())
    nonce = verifier.challenge("bank1", "portal", "vendor-review", now=now)
    signed = make_signed(key, nonce, now)
    verifier.verify(signed, policy, now=now)
    verifier.close()
    again = PassportVerifier(tmp_path / "state.sqlite3", registry, vkey)
    with pytest.raises(TrustError):
        again.verify(signed, policy, now=now)
    nonce2 = again.challenge("bank1", "portal", "vendor-review", now=now, ttl=5)
    with pytest.raises(TrustError):
        again.verify(make_signed(key, nonce2, now), policy, now=now + 6)
    again.close()
