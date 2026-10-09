from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest
from hypothesis import given, settings, strategies as st
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from quala_trust.assurance import (Witness, create_checkpoint, verify_anchor, issue_entitlement,
                                   EntitlementVerifier, licensed_receipt_access, CHECKPOINT_DOMAIN)
from quala_trust.identity import PersistentIssuerRegistry
from quala_trust.ledger import TrustLedger, ZERO_HASH
from quala_trust.passport import (PassportTrustPlane, PassportRevocations, issue_passport,
                                  present_passport, signed)
from quala_trust.protocol import (IssuerRegistry, Policy, Rule, TrustError, canonical, digest,
                                  loads_strict, RECEIPT_DOMAIN, verify_receipt)
from quala_trust.sectors import example_policy
from quala_trust.worker import policy_from_dict, private_file

NOW = 1780000000
CLAIMS = {"security_review_passed": True, "supplier_ownership_reviewed": True,
          "critical_patch_sla_days": 10, "kyc_controls_reviewed": True,
          "third_party_risk_score": 20, "incident_drill_days_ago": 10,
          "data_minimization_verified": True, "business_associate_terms_executed": True,
          "shipment_provenance_verified": True, "software_bill_of_materials_available": True,
          "supplier_traceability_percent": 99}


@pytest.fixture
def product(tmp_path):
    issuer, holder, verifier, licensor = [Ed25519PrivateKey.generate() for _ in range(4)]
    ledger = TrustLedger(tmp_path / "verifier.sqlite")
    registry = PersistentIssuerRegistry(ledger)
    registry.enroll("buyer", "auditor", "k1", issuer.public_key())
    licensing_roots = IssuerRegistry()
    licensing_roots.enroll("buyer", "licensor", "lk", licensor.public_key())
    plane = PassportTrustPlane(ledger, registry, "verifier", verifier)
    policies = {}
    for sector in ("procurement", "banking", "healthcare", "supply-chain"):
        p = example_policy(sector, tenant="buyer", audience=sector, issuer="auditor")
        plane.add_policy(p)
        policies[sector] = p
    passport = issue_passport(passport_id="passport-1", subject="vendor", issuer="auditor", key_id="k1",
                 holder_key=holder.public_key(), claims=CLAIMS, evidence_sha256="a"*64,
                 signer=issuer, now=NOW, lifetime_seconds=86400)
    yield {"issuer": issuer, "holder": holder, "verifier": verifier, "licensor": licensor,
           "ledger": ledger, "registry": registry, "licensing_roots": licensing_roots,
           "plane": plane, "policies": policies, "passport": passport, "tmp": tmp_path}
    ledger.close()


def submission(product, *, sector="procurement", now=NOW):
    c = product["plane"].challenge(tenant="buyer", audience=sector, purpose=f"{sector}-onboard", now=now)
    return present_passport(product["passport"], c, holder_signer=product["holder"], now=now)


def decide(product, envelope, *, sector="procurement", now=NOW):
    return product["plane"].decide_passport(envelope, tenant="buyer", audience=sector, purpose=f"{sector}-onboard", now=now)


def test_one_passport_reusable_across_four_priority_markets(product):
    for sector in product["policies"]:
        result = decide(product, submission(product, sector=sector), sector=sector)
        assert result["receipt"]["decision"] == "ALLOW"
        assert verify_receipt(result, product["verifier"].public_key())
        assert product["ledger"].receipt(result["receipt"]["ledger_seq"]) == result
        assert "claims" not in result["receipt"]
    assert product["ledger"].head()["seq"] == 4


def test_passport_replay_and_wrong_holder_fail(product):
    envelope = submission(product)
    with pytest.raises(TrustError, match="holder key"):
        present_passport(product["passport"], product["plane"].challenge(tenant="buyer", audience="procurement", purpose="procurement-onboard", now=NOW),
                         holder_signer=Ed25519PrivateKey.generate(), now=NOW)
    decide(product, envelope)
    with pytest.raises(TrustError, match="replayed"):
        decide(product, envelope)
    assert product["ledger"].head()["seq"] == 1


@pytest.mark.parametrize("field,value", [("claims", {**CLAIMS, "security_review_passed": False}),
                                          ("subject", "other-vendor"), ("evidence_sha256", "b"*64),
                                          ("holder_key", "b"*64), ("issuer", "other-auditor")])
def test_passport_control_identity_and_commitment_tamper_fail(product, field, value):
    envelope = submission(product)
    envelope["passport"]["payload"][field] = value
    with pytest.raises(TrustError):
        decide(product, envelope)
    assert product["ledger"].head()["seq"] == 0


@pytest.mark.parametrize("field,value", [("tenant", "other"), ("audience", "banking"),
                                          ("purpose", "other"), ("nonce", "b"*64)])
def test_presentation_signature_and_scope_binding(product, field, value):
    envelope = submission(product)
    envelope["presentation"]["payload"][field] = value
    with pytest.raises(TrustError):
        decide(product, envelope)


def test_legitimately_signed_presentation_cannot_substitute_a_passport(product):
    envelope = submission(product)
    other = issue_passport(passport_id="passport-2", subject="vendor", issuer="auditor", key_id="k1",
               holder_key=product["holder"].public_key(), claims=CLAIMS, evidence_sha256="a"*64,
               signer=product["issuer"], now=NOW)
    envelope["passport"] = other
    with pytest.raises(TrustError, match="substitution"):
        decide(product, envelope)


def test_passport_revocation_persists_across_instances(product):
    envelope = submission(product)
    product["plane"].revocations.revoke("auditor", "passport-1", now=NOW)
    with TrustLedger(product["tmp"] / "verifier.sqlite") as reopened:
        with pytest.raises(TrustError, match="revoked"):
            PassportRevocations(reopened).check("auditor", "passport-1")
    with pytest.raises(TrustError, match="revoked"):
        decide(product, envelope)


def test_passport_expiry_and_buyer_source_freshness_are_enforced(product):
    envelope = submission(product)
    with pytest.raises(TrustError, match="passport expired"):
        decide(product, envelope, now=NOW+86400)
    policy = Policy("fresh", "buyer", "fresh", "access", ("auditor",),
                    (Rule("security_review_passed", "eq", True),), max_credential_age_seconds=1)
    product["plane"].add_policy(policy)
    c = product["plane"].challenge(tenant="buyer", audience="fresh", purpose="access", now=NOW+2)
    proof = present_passport(product["passport"], c, holder_signer=product["holder"], now=NOW+2)
    with pytest.raises(TrustError, match="freshness"):
        product["plane"].decide_passport(proof, tenant="buyer", audience="fresh", purpose="access", now=NOW+2)


def test_issuer_revocation_persists_and_old_id_cannot_be_reenrolled(product):
    envelope = submission(product)
    product["registry"].revoke("buyer", "auditor", "k1")
    with TrustLedger(product["tmp"] / "verifier.sqlite") as reopened:
        roots = PersistentIssuerRegistry(reopened)
        with pytest.raises(TrustError, match="revoked"):
            roots.lookup("buyer", "auditor", "k1")
        with pytest.raises(TrustError, match="revoked"):
            roots.enroll("buyer", "auditor", "k1", product["issuer"].public_key())
    with pytest.raises(TrustError, match="revoked"):
        decide(product, envelope)


def test_hardware_required_policy_rejects_software_enrollment(product):
    p = Policy("hardware", "buyer", "hardware", "access", ("auditor",), (Rule("security_review_passed", "eq", True),), require_hardware_identity=True)
    product["plane"].add_policy(p)
    c = product["plane"].challenge(tenant="buyer", audience="hardware", purpose="access", now=NOW)
    envelope = present_passport(product["passport"], c, holder_signer=product["holder"], now=NOW)
    with pytest.raises(TrustError, match="hardware identity"):
        product["plane"].decide_passport(envelope, tenant="buyer", audience="hardware", purpose="access", now=NOW)
    with pytest.raises(TrustError, match="provider unavailable"):
        product["registry"].verify_hardware("buyer", "auditor", "k1", provider="tpm", evidence=b"self-assertion", challenge="a"*64, now=NOW)


def test_receipt_sign_failure_rolls_back_nonce_and_event(product, monkeypatch):
    envelope = submission(product)
    original = product["plane"]._sign_record
    def broken(_):
        raise RuntimeError("injected signer failure")
    monkeypatch.setattr(product["plane"], "_sign_record", broken)
    with pytest.raises(RuntimeError, match="injected"):
        decide(product, envelope)
    assert product["ledger"].head()["seq"] == 0
    monkeypatch.setattr(product["plane"], "_sign_record", original)
    assert decide(product, envelope)["receipt"]["decision"] == "ALLOW"


def test_corrupt_ledger_refuses_new_authorizations(product):
    decide(product, submission(product))
    other = submission(product)
    product["ledger"].db.execute("UPDATE ledger SET event_json='{}' WHERE seq=1")
    with pytest.raises(TrustError, match="corrupt ledger"):
        decide(product, other)
    with pytest.raises(TrustError, match="corrupt ledger"):
        submission(product)


def test_changed_policy_cannot_consume_earlier_challenge(product):
    envelope = submission(product)
    key = ("buyer", "procurement", "procurement-onboard")
    old = product["policies"]["procurement"]
    # New process/configuration scenario with the same outstanding challenge.
    product["plane"]._policies[key] = Policy(**{**old.__dict__, "policy_id": "revision-2"})
    with pytest.raises(TrustError, match="policy changed"):
        decide(product, envelope)


def test_concurrent_separate_connections_accept_nonce_exactly_once(product):
    envelope = submission(product)
    def attempt(_):
        with TrustLedger(product["tmp"] / "verifier.sqlite") as ledger:
            plane = PassportTrustPlane(ledger, PersistentIssuerRegistry(ledger), "verifier", product["verifier"])
            plane.add_policy(product["policies"]["procurement"])
            try:
                plane.decide_passport(envelope, tenant="buyer", audience="procurement", purpose="procurement-onboard", now=NOW)
                return "ALLOW"
            except TrustError:
                return "DENY"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, range(2)))
    assert sorted(results) == ["ALLOW", "DENY"]
    assert product["ledger"].head()["seq"] == 1


@pytest.mark.parametrize("bad", [[], ["x"], True, 1.5, float("nan"), {"x": "\ud800"}])
def test_invalid_signed_receipts_and_json_shapes_fail_closed(bad):
    with pytest.raises(TrustError):
        verify_receipt({"receipt": bad, "signature": "a"*128}, Ed25519PrivateKey.generate().public_key())


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=300))
def test_arbitrary_json_bytes_only_parse_or_reject(data):
    try:
        parsed = loads_strict(data)
    except TrustError:
        return
    assert loads_strict(canonical(parsed)) == parsed


@pytest.mark.parametrize("data", ['['*1200 + ']'*1200, '"\ud800"', '{"x":"\\ud800"}', '{"a":1,"a":2}', '{"a":NaN}'])
def test_pathological_json_rejected_as_trust_error(data):
    with pytest.raises(TrustError):
        loads_strict(data)


def test_frozen_policies_cannot_hide_mutable_lists_or_boolean_limits():
    for kwargs in ({"rules": [Rule("ok", "eq", True)]}, {"allowed_issuers": ["auditor"]},
                   {"max_age_seconds": True}, {"max_credential_age_seconds": True}):
        base = {"policy_id": "p", "tenant": "t", "audience": "a", "purpose": "p",
                "allowed_issuers": ("auditor",), "rules": (Rule("ok", "eq", True),)}
        with pytest.raises(TrustError):
            Policy(**{**base, **kwargs})


def anchored(product, receipt):
    checkpoint = create_checkpoint(product["ledger"], network="proof369", ledger_id="ledger-1",
                  verifier_id="verifier", signer=product["verifier"], now=NOW)
    witnesses, keys, receipts = [], {}, []
    for i in range(2):
        key = Ed25519PrivateKey.generate()
        name = f"witness-{i}"
        witness = Witness(product["tmp"]/f"witness-{i}.sqlite", witness_id=name, signer=key,
                           network="proof369", ledger_id="ledger-1", verifier_id="verifier",
                           trusted_verifier_key=product["verifier"].public_key())
        witnesses.append(witness)
        keys[name] = key.public_key()
        receipts.append(witness.observe(checkpoint, now=NOW))
    return checkpoint, witnesses, keys, receipts


def verify(product, checkpoint, keys, receipts, **changes):
    kwargs = {"trusted_verifier_key": product["verifier"].public_key(), "witness_keys": keys,
              "quorum": 2, "network": "proof369", "ledger_id": "ledger-1", "verifier_id": "verifier",
              "expected_head": product["ledger"].head(), "now": NOW}
    return verify_anchor(checkpoint, receipts, **{**kwargs, **changes})


def test_independent_witness_quorum_and_restart_fork_rejection(product):
    receipt = decide(product, submission(product))
    cp, witnesses, keys, observed = anchored(product, receipt)
    try:
        assert verify(product, cp, keys, observed)["sha256"] == product["ledger"].head()["sha256"]
        assert witnesses[0].observe(cp, now=NOW) == observed[0]
        fork = signed({**cp["payload"], "sha256": "b"*64}, CHECKPOINT_DOMAIN, product["verifier"])
        with pytest.raises(TrustError, match="fork"):
            witnesses[0].observe(fork, now=NOW)
    finally:
        for w in witnesses: w.close()


@pytest.mark.parametrize("case", ["duplicate", "insufficient", "wrong-head", "wrong-network", "expired", "bad-signature", "same-key"])
def test_anchor_rejects_quorum_manipulation_and_scope_errors(product, case):
    receipt = decide(product, submission(product))
    cp, witnesses, keys, observed = anchored(product, receipt)
    try:
        changes = {}
        if case == "duplicate": observed = [observed[0], observed[0]]
        if case == "insufficient": observed = observed[:1]
        if case == "wrong-head": changes["expected_head"] = {"seq": 1, "sha256": "b"*64}
        if case == "wrong-network": changes["network"] = "other"
        if case == "expired": changes["now"] = NOW+301
        if case == "bad-signature": observed[0]["signature"] = "a"*128
        if case == "same-key": keys["witness-1"] = keys["witness-0"]
        with pytest.raises(TrustError): verify(product, cp, keys, observed, **changes)
    finally:
        for w in witnesses: w.close()


def test_anchor_extension_and_old_checkpoint_rollback(product):
    first = decide(product, submission(product))
    cp, witnesses, keys, observed = anchored(product, first)
    head = product["ledger"].head()
    decide(product, submission(product))
    second = create_checkpoint(product["ledger"], network="proof369", ledger_id="ledger-1", verifier_id="verifier",
               signer=product["verifier"], previous_head=head, now=NOW)
    try:
        observations = [w.observe(second, now=NOW) for w in witnesses]
        assert verify(product, second, keys, observations)["seq"] == 2
        with pytest.raises(TrustError, match="rollback"):
            witnesses[0].observe(cp, now=NOW)
    finally:
        for w in witnesses: w.close()


def test_witness_restart_retains_scope_and_fork_protection(product):
    receipt = decide(product, submission(product))
    cp, witnesses, keys, observed = anchored(product, receipt)
    signer = witnesses[0]._signer
    for w in witnesses: w.close()
    reopened = Witness(product["tmp"]/"witness-0.sqlite", witness_id="witness-0", signer=signer,
             network="proof369", ledger_id="ledger-1", verifier_id="verifier",
             trusted_verifier_key=product["verifier"].public_key())
    try:
        assert reopened.observe(cp, now=NOW) == observed[0]
        fork = signed({**cp["payload"], "sha256": "b"*64}, CHECKPOINT_DOMAIN, product["verifier"])
        with pytest.raises(TrustError, match="fork"): reopened.observe(fork, now=NOW)
    finally:
        reopened.close()
    with pytest.raises(TrustError, match="scope changed"):
        Witness(product["tmp"]/"witness-0.sqlite", witness_id="witness-0", signer=signer,
                network="other", ledger_id="ledger-1", verifier_id="verifier",
                trusted_verifier_key=product["verifier"].public_key())


def test_anchor_cannot_count_the_verifier_as_a_witness(product):
    receipt = decide(product, submission(product))
    cp, witnesses, keys, observed = anchored(product, receipt)
    try:
        keys["witness-0"] = product["verifier"].public_key()
        with pytest.raises(TrustError, match="own checkpoint"):
            verify(product, cp, keys, observed)
    finally:
        for w in witnesses: w.close()


def entitlement(product):
    return issue_entitlement({"version": "proof369-entitlement-v1", "license_id": "L1", "licensor": "licensor",
            "key_id": "lk", "tenant": "buyer", "subject": "vendor", "product": "passport",
            "capabilities": ["verify"], "issued_at": NOW, "expires_at": NOW+3600,
            "agreement_sha256": "c"*64}, product["licensor"])


def test_license_gate_requires_receipt_anchor_policy_and_entitlement(product):
    receipt = decide(product, submission(product))
    cp, witnesses, keys, observed = anchored(product, receipt)
    licenses = EntitlementVerifier(product["ledger"], product["licensing_roots"])
    license_envelope = entitlement(product)
    kwargs = {"receipt": receipt, "entitlement": license_envelope, "entitlement_verifier": licenses,
              "proposal": cp, "witness_receipts": observed, "trusted_verifier_key": product["verifier"].public_key(),
              "witness_keys": keys, "quorum": 2, "network": "proof369", "ledger_id": "ledger-1", "verifier_id": "verifier",
              "tenant": "buyer", "subject": "vendor", "audience": "procurement", "purpose": "procurement-onboard",
              "policy_sha256": product["policies"]["procurement"].sha256, "product": "passport", "capability": "verify", "now": NOW}
    try:
        assert licensed_receipt_access(**kwargs)["authorized"] is True
        for change in ({"subject": "other"}, {"product": "other"}, {"capability": "admin"}, {"policy_sha256": "b"*64}, {"now": NOW+301}):
            with pytest.raises(TrustError): licensed_receipt_access(**{**kwargs, **change})
        licenses.revoke("licensor", "L1")
        with pytest.raises(TrustError, match="revoked"): licensed_receipt_access(**kwargs)
    finally:
        for w in witnesses: w.close()


def test_valid_signature_cannot_make_malformed_receipt_valid(product):
    receipt = decide(product, submission(product))
    for changes in ({"ledger_seq": True}, {"decision": "ALLOW", "reason_codes": ["failed"]}, {"ledger_hash": "oops"}):
        body = {**receipt["receipt"], **changes}
        envelope = {"receipt": body, "signature": product["verifier"].sign(RECEIPT_DOMAIN+canonical(body)).hex()}
        with pytest.raises(TrustError): verify_receipt(envelope, product["verifier"].public_key())


def test_separate_verifier_process_end_to_end_restart_and_denial(tmp_path):
    issuer, holder, verifier = [Ed25519PrivateKey.generate() for _ in range(3)]
    policy = example_policy("procurement", tenant="buyer", audience="procurement", issuer="auditor")
    key_file = tmp_path / "verifier.key"
    key_file.write_text(verifier.private_bytes_raw().hex()); key_file.chmod(0o600)
    config = {"version": "abraxas-worker-v1", "verifier_id": "verifier", "verifier_key_file": "verifier.key",
              "roots": [{"tenant": "buyer", "issuer": "auditor", "key_id": "k1", "public_key": issuer.public_key().public_bytes_raw().hex()}],
              "policies": [policy.as_dict()]}
    path = tmp_path / "config.json"; path.write_bytes(canonical(config)); path.chmod(0o600)
    command = [sys.executable, "-m", "quala_trust.worker", "--config", str(path), "--database", str(tmp_path/"worker.sqlite")]
    scope = {"tenant": "buyer", "audience": "procurement", "purpose": "procurement-onboard"}
    def rpc(process, request):
        process.stdin.write(canonical(request).decode()+"\n"); process.stdin.flush()
        return loads_strict(process.stdout.readline())
    def start():
        return subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    process = start()
    try:
        c = rpc(process, {"action": "challenge", **scope})["result"]
        passport = issue_passport(passport_id="p1", subject="vendor", issuer="auditor", key_id="k1", holder_key=holder.public_key(),
                     claims=CLAIMS, evidence_sha256="a"*64, signer=issuer)
        envelope = present_passport(passport, c, holder_signer=holder)
        request = {"action": "decide_passport", **scope, "submission": envelope}
        result = rpc(process, request)["result"]
        assert verify_receipt(result, verifier.public_key())
        assert rpc(process, {"action": "challenge", **scope, "now": 0}) == {"error": "DENY_INVALID_REQUEST"}
    finally:
        process.stdin.close(); process.wait(timeout=10)
    restarted = start()
    try:
        assert rpc(restarted, request) == {"error": "DENY_INVALID_REQUEST"}
    finally:
        restarted.stdin.close(); restarted.wait(timeout=10)
    assert process.returncode == restarted.returncode == 0


def test_worker_key_permissions_and_symlinks_rejected(tmp_path):
    path = tmp_path/"key"
    path.write_text(Ed25519PrivateKey.generate().private_bytes_raw().hex()); path.chmod(0o644)
    with pytest.raises(TrustError, match="private"): private_file(path)
    path.chmod(0o600)
    symlink = tmp_path/"link"; symlink.symlink_to(path)
    with pytest.raises(OSError): private_file(symlink)


def test_policy_wire_round_trip_and_unrecognized_config_rejection(product):
    original = product["policies"]["procurement"]
    assert policy_from_dict(original.as_dict()).sha256 == original.sha256
    with pytest.raises(TrustError): policy_from_dict({**original.as_dict(), "allow_any": True})
