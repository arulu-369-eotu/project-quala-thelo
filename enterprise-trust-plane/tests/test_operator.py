"""Exercise a real second Python process with independent witness disk state."""
import os
import subprocess
import sys
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from quala_trust.proof369 import EvidenceLedger
from quala_trust.protocol import canonical
from quala_trust.witness import verify_witness_receipt


def pem_keys(folder, name):
    private = Ed25519PrivateKey.generate()
    private_path = folder / (name + ".key")
    public_path = folder / (name + ".pem")
    private_path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
    os.chmod(private_path, 0o600)
    public_path.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    return private, private_path, public_path


def test_external_witness_process_and_replay(tmp_path):
    root, _, root_pub = pem_keys(tmp_path, "proof")
    witness, witness_priv, _ = pem_keys(tmp_path, "external")
    stamp = int(time.time())
    with EvidenceLedger(str(tmp_path / "proof.db"), "bank1", root) as ledger:
        ledger.append({
            "version": "proof369-measurement-v1", "subject": "ci",
            "tenant": "bank1", "control": "tests", "outcome": "PASS",
            "source_sha256": "a" * 64, "measured_at": stamp,
            "metrics": {
                "test_count": 2, "passed_count": 2, "failed_count": 0,
                "skipped_count": 0, "duration_ms": 100,
            },
        })
        proof_export = ledger.export(issued_at=stamp)
    exported = tmp_path / "evidence.json"
    exported.write_bytes(canonical(proof_export))
    outfile = tmp_path / "signed_witness.json"
    args = [
        sys.executable, "-m", "quala_trust.operator", "witness",
        "--id", "witness-east", "--tenant", "bank1",
        "--database", str(tmp_path / "external.db"),
        "--checkpoint-public", str(root_pub),
        "--witness-private", str(witness_priv),
        "--evidence", str(exported), "--out", str(outfile),
    ]
    process = subprocess.run(args, capture_output=True, text=True, timeout=15)
    assert process.returncode == 0, process.stderr
    from quala_trust.protocol import loads_strict
    receipt = loads_strict(outfile.read_bytes())
    verify_witness_receipt(receipt, witness.public_key(),
                           "witness-east", proof_export["signed_checkpoint"]["checkpoint"])
    # The operator protects previous evidence rather than silently overwriting.
    repeated = subprocess.run(args, capture_output=True, timeout=15)
    assert repeated.returncode != 0


def test_operator_rejects_publicly_readable_private_key(tmp_path):
    root, root_priv, root_pub = pem_keys(tmp_path, "proof")
    _, witness_priv, _ = pem_keys(tmp_path, "witness")
    os.chmod(witness_priv, 0o644)
    evidence = tmp_path / "evidence.json"
    with EvidenceLedger(str(tmp_path / "proof.db"), "bank1", root) as ledger:
        evidence.write_bytes(canonical(ledger.export()))
    process = subprocess.run([
        sys.executable, "-m", "quala_trust.operator", "witness",
        "--id", "external", "--tenant", "bank1",
        "--database", str(tmp_path / "independent.db"),
        "--checkpoint-public", str(root_pub),
        "--witness-private", str(witness_priv),
        "--evidence", str(evidence), "--out", str(tmp_path / "receipt.json"),
    ], capture_output=True, timeout=15)
    assert process.returncode == 2


def test_independent_abraxas_process_quorum_with_mocked_gh(tmp_path):
    """Process separation is real; gh's Sigstore verdict is mocked in this test."""
    import hashlib
    from quala_trust.witness import WitnessStore
    from quala_trust.abraxas7 import verify_assurance_receipt
    from quala_trust.protocol import loads_strict

    now = int(time.time())
    repo = "arulu-369-eotu/project-quala-thelo"
    report = {
        "schema": "proof369-github-ci-v1", "repository": repo,
        "workflow": repo + "/.github/workflows/proof369-attested-ci.yml",
        "ref": "refs/heads/main", "commit": "a" * 40,
        "run_id": 34567, "run_attempt": 1, "timestamp": now,
        "suite": "quala-trust-passport",
        "tests": {"test_count": 3, "passed_count": 3, "failed_count": 0,
                  "skipped_count": 0, "duration_ms": 100},
    }
    data = canonical(report)
    ci = tmp_path / "proof369-ci.json"
    ci.write_bytes(data)
    proof_signer, _, proof_pub = pem_keys(tmp_path, "proof2")
    abraxas_signer, abraxas_priv, _ = pem_keys(tmp_path, "abraxas")
    witness_keys = {}
    for identifier in ("east", "west"):
        witness_keys[identifier] = pem_keys(tmp_path, identifier)
    evidence_path = tmp_path / "export.json"
    with EvidenceLedger(str(tmp_path / "proof2.db"), "bank1", proof_signer) as ledger:
        ledger.append({
            "version": "proof369-measurement-v1", "subject": "github-ci",
            "tenant": "bank1", "control": "quala-passport-tests",
            "outcome": "PASS", "source_sha256": hashlib.sha256(data).hexdigest(),
            "measured_at": now, "metrics": report["tests"],
        })
        exported = ledger.export(issued_at=now)
    evidence_path.write_bytes(canonical(exported))
    receipt_paths = []
    for name, (signer, _, pub) in witness_keys.items():
        with WitnessStore(tmp_path / (name + ".db"), name, "bank1",
                          proof_signer.public_key(), signer) as w:
            signed = w.witness(exported, now=now)
        destination = tmp_path / (name + "-receipt.json")
        destination.write_bytes(canonical(signed))
        receipt_paths.append(destination)
    fake_gh = tmp_path / "mock-gh"
    fake_gh.write_text('#!/usr/bin/env python3\nprint(\'[{"mock":"not-cryptographic-proof"}]\')\n')
    os.chmod(fake_gh, 0o700)
    output = tmp_path / "admission.json"
    cmd = [
        sys.executable, "-m", "quala_trust.operator", "verify",
        "--id", "abraxas-test", "--tenant", "bank1",
        "--audience", "procurement", "--challenge-hex", "7a" * 32,
        "--repo", repo, "--source-sha", "a" * 40,
        "--checkpoint-public", str(proof_pub),
        "--verifier-private", str(abraxas_priv),
        "--witness-public", "east=" + str(witness_keys["east"][2]),
        "--witness-public", "west=" + str(witness_keys["west"][2]),
        "--witness-receipt", str(receipt_paths[0]),
        "--witness-receipt", str(receipt_paths[1]),
        "--evidence", str(evidence_path),
        "--ci-report", str(ci), "--gh-executable", str(fake_gh),
        "--out", str(output),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    verified = verify_assurance_receipt(
        loads_strict(output.read_bytes()), abraxas_signer.public_key(),
        expected_audience="procurement", expected_challenge=b"z" * 32
    )
    assert verified["decision"] == "ALLOW"
    assert verified["witness_ids"] == ["east", "west"]
