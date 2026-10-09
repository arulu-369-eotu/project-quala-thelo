"""Adversarial unit tests. CLI responses here are MOCKED, not Sigstore proof.

A production attestation is accepted only after an actual installed gh CLI
validates the artifact and its GitHub/Sigstore cryptographic chain.
"""
import copy
import json
import subprocess

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from quala_trust.abraxas7 import (
    Abraxas7Verifier, AssurancePolicy, verify_assurance_receipt,
)
from quala_trust.github_ci import GitHubIdentity, verify_github_ci
from quala_trust.proof369 import EvidenceLedger
from quala_trust.protocol import TrustError, canonical
from quala_trust.witness import WitnessStore, verify_witness_receipt

SHA = "a" * 40
REPO = "arulu-369-eotu/project-quala-thelo"
WORKFLOW = REPO + "/.github/workflows/proof369-attested-ci.yml"
NOW = 1791555000


def make_report(path, *, failed=0, skipped=0, ref="refs/heads/main"):
    obj = {
        "schema": "proof369-github-ci-v1", "repository": REPO,
        "workflow": WORKFLOW, "ref": ref, "commit": SHA,
        "run_id": 12345, "run_attempt": 1, "timestamp": NOW,
        "suite": "quala-trust-passport",
        "tests": {
            "test_count": 6, "passed_count": 6 - failed - skipped,
            "failed_count": failed, "skipped_count": skipped, "duration_ms": 124,
        },
    }
    path.write_bytes(canonical(obj))
    return obj


def mock_sigstore_cli(args, timeout):
    assert args[0:3] == ["gh", "attestation", "verify"]
    assert ["--repo", REPO] == args[4:6]
    assert ["--signer-workflow", WORKFLOW] == args[6:8]
    assert ["--source-digest", SHA] == args[8:10]
    assert ["--source-ref", "refs/heads/main"] == args[10:12]
    return subprocess.CompletedProcess(args, 0, '[{"verified":"mock-only"}]', "")


def failing_cli(args, timeout):
    return subprocess.CompletedProcess(args, 1, "", "unverified")


def sample(tmp_path, *, failed=0, skipped=0):
    report_path = tmp_path / "ci.json"
    make_report(report_path, failed=failed, skipped=skipped)
    identity = GitHubIdentity(REPO, WORKFLOW, SHA)
    verified = verify_github_ci(report_path, identity, "bank1",
                                runner=mock_sigstore_cli)
    proof_key, akey = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    keys = {"witness-a": Ed25519PrivateKey.generate(),
            "witness-b": Ed25519PrivateKey.generate(),
            "witness-c": Ed25519PrivateKey.generate()}
    with EvidenceLedger(str(tmp_path / "proof.db"), "bank1", proof_key) as ledger:
        ledger.append(verified.measurement)
        evidence = ledger.export(issued_at=NOW)
    receipts = []
    for name, key in keys.items():
        with WitnessStore(tmp_path / (name + ".db"), name, "bank1",
                          proof_key.public_key(), key) as witness:
            receipts.append(witness.witness(evidence, now=NOW))
    policy = AssurancePolicy(
        "bank1", identity,
        {name: key.public_key() for name, key in keys.items()}, min_witnesses=2
    )
    verifier = Abraxas7Verifier("verifier-a", proof_key.public_key(), akey, policy)
    return report_path, verified, evidence, receipts, verifier, akey, keys, proof_key


def test_full_chain_accepts_signed_independent_quorum(tmp_path):
    path, verified, evidence, receipts, verifier, akey, keys, proof = sample(tmp_path)
    signed = verifier.admit(evidence, receipts[:2], path, audience="procurement", client_challenge=b"z"*32, now=NOW,
                            github_options={"runner": mock_sigstore_cli})
    verified_body = verify_assurance_receipt(signed, akey.public_key(), expected_audience="procurement", expected_challenge=b"z"*32)
    assert verified_body["decision"] == "ALLOW"
    assert verified_body["witness_ids"] == ["witness-a", "witness-b"]
    assert verified_body["github_artifact_sha256"] == verified.artifact_sha256


def test_attestation_command_failed_is_fail_closed(tmp_path):
    path, _, evidence, receipts, verifier, *_ = sample(tmp_path)
    with pytest.raises(TrustError):
        verifier.admit(evidence, receipts[:2], path, audience="procurement", client_challenge=b"z"*32, now=NOW,
                       github_options={"runner": failing_cli})


def test_wrong_artifact_digest_cannot_be_admitted(tmp_path):
    path, _, evidence, receipts, verifier, *_ = sample(tmp_path)
    changed = json.loads(path.read_text())
    changed["tests"]["duration_ms"] = 125
    path.write_bytes(canonical(changed))
    with pytest.raises(TrustError):
        verifier.admit(evidence, receipts[:2], path, audience="procurement", client_challenge=b"z"*32, now=NOW,
                       github_options={"runner": mock_sigstore_cli})


def test_incomplete_or_duplicate_witness_quorum_rejected(tmp_path):
    path, _, evidence, receipts, verifier, *_ = sample(tmp_path)
    with pytest.raises(TrustError):
        verifier.admit(evidence, receipts[:1], path, audience="procurement", client_challenge=b"z"*32, now=NOW,
                       github_options={"runner": mock_sigstore_cli})
    with pytest.raises(TrustError):
        verifier.admit(evidence, [receipts[0], receipts[0]], path, audience="procurement", client_challenge=b"z"*32, now=NOW,
                       github_options={"runner": mock_sigstore_cli})


def test_tampered_witness_and_chain_rejected(tmp_path):
    path, _, evidence, receipts, verifier, *_ = sample(tmp_path)
    damaged = copy.deepcopy(receipts[:2])
    damaged[1]["receipt"]["head"] = "f" * 64
    with pytest.raises(TrustError):
        verifier.admit(evidence, damaged, path, audience="procurement", client_challenge=b"z"*32, now=NOW,
                       github_options={"runner": mock_sigstore_cli})
    changed_evidence = copy.deepcopy(evidence)
    changed_evidence["records"][0]["measurement"]["metrics"]["duration_ms"] += 1
    with pytest.raises(TrustError):
        verifier.admit(changed_evidence, receipts[:2], path, audience="procurement", client_challenge=b"z"*32, now=NOW,
                       github_options={"runner": mock_sigstore_cli})


def test_unapproved_branch_and_duplicate_keys_fail(tmp_path):
    with pytest.raises(TrustError):
        AssurancePolicy("bank1", GitHubIdentity(REPO, WORKFLOW, SHA,
                       "refs/heads/develop"),
                       {"one": Ed25519PrivateKey.generate().public_key(),
                        "two": Ed25519PrivateKey.generate().public_key()})
    same = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(TrustError):
        AssurancePolicy("bank1", GitHubIdentity(REPO, WORKFLOW, SHA),
                       {"one": same, "two": same})


@pytest.mark.parametrize("failed,skipped", [(1, 0), (0, 1)])
def test_failing_or_skipped_ci_is_not_admitted(tmp_path, failed, skipped):
    path, _, evidence, receipts, verifier, *_ = sample(
        tmp_path, failed=failed, skipped=skipped)
    with pytest.raises(TrustError):
        verifier.admit(evidence, receipts[:2], path, audience="procurement", client_challenge=b"z"*32, now=NOW,
                       github_options={"runner": mock_sigstore_cli})


def test_witness_replay_is_idempotent_and_fork_fails(tmp_path):
    path, _, evidence, receipts, verifier, akey, keys, proof = sample(tmp_path)
    store = WitnessStore(tmp_path / "witness-a.db", "witness-a", "bank1",
                         proof.public_key(), keys["witness-a"])
    try:
        assert store.witness(evidence, now=NOW) == receipts[0]
        with EvidenceLedger(str(tmp_path / "fork.db"), "bank1", proof) as fork:
            altered = copy.deepcopy(evidence["records"][0]["measurement"])
            altered["metrics"]["duration_ms"] += 1
            fork.append(altered)
            alternate = fork.export(issued_at=NOW)
        with pytest.raises(TrustError):
            store.witness(alternate, now=NOW)
    finally:
        store.close()


def test_stale_checkpoint_is_rejected(tmp_path):
    path, _, evidence, receipts, verifier, *_ = sample(tmp_path)
    with pytest.raises(TrustError):
        verifier.admit(evidence, receipts[:2], path, audience="procurement", client_challenge=b"z"*32, now=NOW + 4000,
                       github_options={"runner": mock_sigstore_cli})


def test_rogue_witness_identity_rejected(tmp_path):
    path, _, evidence, receipts, verifier, *_ = sample(tmp_path)
    tampered = copy.deepcopy(receipts[:2])
    tampered[1]["receipt"]["witness_id"] = "witness-rogue"
    with pytest.raises(TrustError):
        verifier.admit(evidence, tampered, path, audience="procurement", client_challenge=b"z"*32, now=NOW,
                       github_options={"runner": mock_sigstore_cli})


def test_witness_detects_corrupted_own_database(tmp_path):
    path, _, evidence, receipts, verifier, akey, keys, proof = sample(tmp_path)
    store = WitnessStore(tmp_path / "witness-a.db", "witness-a", "bank1",
                         proof.public_key(), keys["witness-a"])
    try:
        store.db.execute(
            "UPDATE witness_receipts SET receipt=? WHERE tenant=? AND witness_id=?",
            ('{"receipt":{"version":"fake"},"signature":"00"}',
             "bank1", "witness-a")
        )
        with pytest.raises(TrustError):
            store.witness(evidence, now=NOW)
    finally:
        store.close()


def test_relying_party_challenge_and_audience_are_cryptographically_bound(tmp_path):
    path, _, evidence, receipts, verifier, akey, *_ = sample(tmp_path)
    signed = verifier.admit(
        evidence, receipts[:2], path, audience="procurement",
        client_challenge=b"z" * 32, now=NOW,
        github_options={"runner": mock_sigstore_cli},
    )
    with pytest.raises(TrustError):
        verify_assurance_receipt(
            signed, akey.public_key(), expected_audience="procurement",
            expected_challenge=b"x" * 32,
        )
    with pytest.raises(TrustError):
        verify_assurance_receipt(
            signed, akey.public_key(), expected_audience="healthcare",
            expected_challenge=b"z" * 32,
        )
    with pytest.raises(TrustError):
        verifier.admit(
            evidence, receipts[:2], path, audience="healthcare",
            client_challenge=b"z" * 32, now=NOW,
            github_options={"runner": mock_sigstore_cli},
        )
    with pytest.raises(TrustError):
        verifier.admit(
            evidence, receipts[:2], path, audience="procurement",
            client_challenge=b"x", now=NOW,
            github_options={"runner": mock_sigstore_cli},
        )
