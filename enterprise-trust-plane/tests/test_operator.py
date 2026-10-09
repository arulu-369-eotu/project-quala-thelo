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
