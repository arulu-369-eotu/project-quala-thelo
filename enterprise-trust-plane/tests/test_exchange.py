from __future__ import annotations

import copy
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from quala_trust import (
    IssuerRegistry, Policy, Rule, TrustError, TrustLedger, TrustPlane,
    canonical, example_policy, issue_attestation, verify_attestation, verify_receipt,
    loads_strict,
)

NOW = 1_780_000_000
APPROVED = {"model_evaluation_passed": True, "authorized_data_use": True,
            "human_oversight_enabled": True}


@pytest.fixture
def scene(tmp_path):
    issuer, verifier = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    registry = IssuerRegistry()
    registry.enroll("acme", "audit-1", "key-1", issuer.public_key())
    db = tmp_path / "audit.sqlite"
    ledger = TrustLedger(db)
    plane = TrustPlane(ledger, registry, "verifier-1", verifier)
    plane.add_policy(example_policy("ai", tenant="acme", audience="buy-side", issuer="audit-1"))

    def attest(claims=None, timestamp=NOW):
        challenge = plane.challenge(
            tenant="acme", audience="buy-side", purpose="ai-onboard",
            ttl_seconds=120, now=timestamp)
        return issue_attestation(challenge, issuer="audit-1", key_id="key-1",
                                 claims=APPROVED if claims is None else claims,
                                 evidence_sha256="a" * 64, signer=issuer, now=timestamp)

    def decide(signed, now=NOW):
        return plane.decide(signed, tenant="acme", audience="buy-side",
                            purpose="ai-onboard", now=now)

    yield issuer, verifier, registry, ledger, plane, attest, decide
    ledger.close()


def test_positive_path_signed_receipt_and_chain(scene):
    _, verifier, _, ledger, _, attest, decide = scene
    out = decide(attest())
    assert out["receipt"]["decision"] == "ALLOW"
    assert out["receipt"]["reason_codes"] == []
    assert out["receipt"]["attestation_sha256"]
    assert "claims" not in json.dumps(out)
    assert verify_receipt(out, verifier.public_key())
    assert ledger.verify_chain()
    assert ledger.head()["seq"] == 1


def test_replay_rejected_and_not_logged_twice(scene):
    *_, ledger, plane, attest, decide = scene
    signed = attest()
    assert decide(signed)["receipt"]["decision"] == "ALLOW"
    with pytest.raises(TrustError, match="replayed"):
        decide(signed)
    assert ledger.head()["seq"] == 1


def test_business_denial_burns_nonce_and_logs_reason(scene):
    *_, ledger, plane, attest, decide = scene
    signed = attest({**APPROVED, "human_oversight_enabled": False})
    r = decide(signed)
    assert r["receipt"]["decision"] == "DENY"
    assert r["receipt"]["reason_codes"] == ["CONTROL_FAILED:human_oversight_enabled"]
    with pytest.raises(TrustError, match="replayed"):
        decide(signed)
    assert ledger.verify_chain()


def test_signature_tamper_fails_without_consuming(scene):
    *_, attest, decide = scene
    authentic = attest()
    corrupted = copy.deepcopy(authentic)
    corrupted["payload"]["claims"]["model_evaluation_passed"] = False
    with pytest.raises(TrustError, match="signature verification"):
        decide(corrupted)
    assert decide(authentic)["receipt"]["decision"] == "ALLOW"


def test_scope_separation_and_freshness(scene):
    *_, attest, decide = scene
    signed = attest()
    with pytest.raises(TrustError, match="mismatch|no exact-scope"):
        scene[4].decide(signed, tenant="other", audience="buy-side", purpose="ai-onboard", now=NOW)
    with pytest.raises(TrustError, match="mismatch|no exact-scope"):
        scene[4].decide(signed, tenant="acme", audience="other", purpose="ai-onboard", now=NOW)
    with pytest.raises(TrustError, match="expired"):
        decide(signed, now=NOW + 61)
    assert decide(signed)["receipt"]["decision"] == "ALLOW"


def test_unknown_or_revoked_issuer_fails_closed(scene):
    _, _, registry, ledger, plane, attest, decide = scene
    signed = attest()
    registry.revoke("acme", "audit-1", "key-1")
    with pytest.raises(TrustError, match="revoked"):
        decide(signed)
    assert ledger.head()["seq"] == 0


def test_policy_replacement_and_duplicate_key_rejected(scene):
    issuer, _, registry, _, plane, *_ = scene
    with pytest.raises(TrustError, match="duplicate"):
        registry.enroll("acme", "audit-1", "key-1", issuer.public_key())
    with pytest.raises(TrustError, match="replacement"):
        plane.add_policy(example_policy("ai", tenant="acme", audience="buy-side", issuer="audit-1"))


def test_chain_tamper_detection(scene):
    _, _, _, ledger, _, attest, decide = scene
    decide(attest())
    checkpoint = ledger.head()
    assert ledger.verify_chain(expected_head=checkpoint)
    ledger.db.execute("UPDATE ledger SET event_json=? WHERE seq=1", ('{"decision":"ALLOW"}',))
    assert not ledger.verify_chain()


def test_rollback_detection_requires_external_checkpoint(scene):
    _, _, _, ledger, _, attest, decide = scene
    decide(attest())
    checkpoint = ledger.head()
    ledger.db.execute("DELETE FROM receipts")
    ledger.db.execute("DELETE FROM ledger")
    assert ledger.verify_chain()  # local hash chain cannot detect a complete rollback
    assert not ledger.verify_chain(expected_head=checkpoint)


def test_receipt_modification_or_wrong_key_detected(scene):
    _, verifier, _, _, _, attest, decide = scene
    receipt = decide(attest())
    modified = copy.deepcopy(receipt)
    modified["receipt"]["decision"] = "DENY"
    with pytest.raises(TrustError, match="verification failed|inconsistent receipt"):
        verify_receipt(modified, verifier.public_key())
    with pytest.raises(TrustError, match="verification failed"):
        verify_receipt(receipt, Ed25519PrivateKey.generate().public_key())


def test_noncanonical_inputs_fail_closed(scene):
    _, _, _, _, _, attest, decide = scene
    authentic = attest()
    for field, value in [("model_evaluation_passed", 1),
                         ("authorized_data_use", 1.0),
                         ("human_oversight_enabled", float("nan"))]:
        bad = copy.deepcopy(authentic)
        bad["payload"]["claims"][field] = value
        with pytest.raises(TrustError):
            decide(bad)
    invalid = copy.deepcopy(authentic)
    invalid["payload"]["extra"] = "unknown"
    with pytest.raises(TrustError):
        decide(invalid)
    assert decide(authentic)["receipt"]["decision"] == "ALLOW"


def test_no_policy_no_challenge(scene):
    _, _, _, _, plane, *_ = scene
    with pytest.raises(TrustError, match="no exact-scope"):
        plane.challenge(tenant="other", audience="buy-side", purpose="ai-onboard", now=NOW)


def test_types_and_bounds_enforced(scene):
    assert canonical({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    for value in (1.5, float("nan"), {"a": [1] * 129}):
        with pytest.raises(TrustError):
            canonical(value)
    with pytest.raises(TrustError):
        Rule("score", "gte", True)
    with pytest.raises(TrustError):
        Policy("p", "t", "a", "p", (), (Rule("a", "eq", True),))


def test_bad_issuer_allowlist_denies_even_with_valid_signature(scene):
    issuer = Ed25519PrivateKey.generate()
    registry = IssuerRegistry()
    registry.enroll("t", "signed", "k", issuer.public_key())
    with TrustLedger(":memory:") as ledger:
        plane = TrustPlane(ledger, registry, "verifier", Ed25519PrivateKey.generate())
        plane.add_policy(Policy("p", "t", "buyer", "quote", ("other",), (Rule("ok", "eq", True),)))
        challenge = plane.challenge(tenant="t", audience="buyer", purpose="quote", now=NOW)
        signed = issue_attestation(challenge, issuer="signed", key_id="k", claims={"ok": True},
                                   evidence_sha256="b" * 64, signer=issuer, now=NOW)
        receipt = plane.decide(signed, tenant="t", audience="buyer", purpose="quote", now=NOW)
        assert receipt["receipt"]["decision"] == "DENY"
        assert receipt["receipt"]["reason_codes"] == ["ISSUER_NOT_ALLOWED"]


def test_replay_between_separate_sqlite_connections(scene, tmp_path):
    issuer = Ed25519PrivateKey.generate()
    registry = IssuerRegistry()
    registry.enroll("acme", "issuer", "key", issuer.public_key())
    db = tmp_path / "shared.db"
    a, b = TrustLedger(db), TrustLedger(db)
    try:
        plane_a = TrustPlane(a, registry, "v", Ed25519PrivateKey.generate())
        plane_b = TrustPlane(b, registry, "v", Ed25519PrivateKey.generate())
        policy = Policy("p", "acme", "buyer", "bid", ("issuer",), (Rule("eligible", "eq", True),))
        plane_a.add_policy(policy)
        plane_b.add_policy(policy)
        challenge = plane_a.challenge(tenant="acme", audience="buyer", purpose="bid", now=NOW)
        att = issue_attestation(challenge, issuer="issuer", key_id="key", claims={"eligible": True},
                                evidence_sha256="c" * 64, signer=issuer, now=NOW)
        assert plane_b.decide(att, tenant="acme", audience="buyer", purpose="bid", now=NOW)["receipt"]["decision"] == "ALLOW"
        with pytest.raises(TrustError, match="replayed"):
            plane_a.decide(att, tenant="acme", audience="buyer", purpose="bid", now=NOW)
        assert a.head()["seq"] == 1
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("sector", ["banking", "healthcare", "energy", "manufacturing",
                                   "cloud", "ai", "retail", "logistics"])
def test_sector_packs_fail_closed_when_missing_evidence(sector):
    policy = example_policy(sector, tenant="t", audience="buyer", issuer="trusted")
    assert policy.evaluate("trusted", {})
    assert policy.sha256 == policy.sha256


def test_external_json_rejects_duplicates_nan_and_oversize():
    assert loads_strict('{"b":2,"a":1}') == {"a": 1, "b": 2}
    for payload in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}',
                    '"' + 'x' * 17_000 + '"'):
        with pytest.raises(TrustError):
            loads_strict(payload)


def test_challenge_purge_leaves_ledger_intact(scene):
    _, _, _, ledger, _, attest, decide = scene
    signed = attest()
    decide(signed)
    saved = ledger.head()
    assert ledger.purge_expired_challenges(now=NOW + 200) == 1
    assert ledger.verify_chain(expected_head=saved)
    with pytest.raises(TrustError):
        decide(signed, now=NOW + 200)
