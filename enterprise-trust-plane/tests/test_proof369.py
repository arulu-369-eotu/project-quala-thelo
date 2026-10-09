import copy
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from quala_trust.proof369 import EvidenceLedger, verify_export, validate_measurement
from quala_trust.protocol import TrustError


def measurement(tenant="bank1", outcome="PASS"):
    return {
        "version": "proof369-measurement-v1", "subject": "uql-ci",
        "tenant": tenant, "control": "tests", "outcome": outcome,
        "source_sha256": hashlib.sha256(b"pinned-git-commit").hexdigest(),
        "measured_at": 1791550000,
        "metrics": {"test_count": 5, "passed_count": 5 if outcome == "PASS" else 4,
                    "failed_count": 0 if outcome == "PASS" else 1, "skipped_count": 0,
                    "duration_ms": 300},
    }


def test_append_export_and_public_verification(tmp_path):
    signer = Ed25519PrivateKey.generate()
    with EvidenceLedger(str(tmp_path / "ledger.db"), "bank1", signer) as ledger:
        ledger.append(measurement())
        ledger.append(measurement(outcome="FAIL"))
        export = ledger.export(issued_at=1791550010)
    assert verify_export(export["records"], export["signed_checkpoint"], signer.public_key())


def test_detects_record_tampering_and_omission(tmp_path):
    signer = Ed25519PrivateKey.generate()
    with EvidenceLedger(str(tmp_path / "ledger.db"), "bank1", signer) as ledger:
        ledger.append(measurement())
        ledger.append(measurement())
        export = ledger.export()
    changed = copy.deepcopy(export["records"])
    changed[0]["measurement"]["metrics"]["duration_ms"] = 999
    with pytest.raises(TrustError):
        verify_export(changed, export["signed_checkpoint"], signer.public_key())
    with pytest.raises(TrustError):
        verify_export(export["records"][:1], export["signed_checkpoint"], signer.public_key())


def test_rejects_wrong_verifier_key_and_checkpoint_changes(tmp_path):
    signer = Ed25519PrivateKey.generate()
    with EvidenceLedger(str(tmp_path / "ledger.db"), "bank1", signer) as ledger:
        ledger.append(measurement())
        export = ledger.export()
    with pytest.raises(TrustError):
        verify_export(export["records"], export["signed_checkpoint"],
                      Ed25519PrivateKey.generate().public_key())
    changed = copy.deepcopy(export["signed_checkpoint"])
    changed["checkpoint"]["sequence"] = 0
    with pytest.raises(TrustError):
        verify_export(export["records"], changed, signer.public_key())


def test_invalid_metrics_and_cross_tenant_fail_closed(tmp_path):
    wrong = measurement()
    wrong["metrics"]["failed_count"] = 1
    with pytest.raises(TrustError):
        validate_measurement(wrong)
    signer = Ed25519PrivateKey.generate()
    with EvidenceLedger(str(tmp_path / "ledger.db"), "bank1", signer) as ledger:
        with pytest.raises(TrustError):
            ledger.append(measurement(tenant="bank2"))


def test_corruption_blocks_future_append(tmp_path):
    signer = Ed25519PrivateKey.generate()
    database = str(tmp_path / "ledger.db")
    with EvidenceLedger(database, "bank1", signer) as ledger:
        ledger.append(measurement())
        ledger.db.execute("UPDATE evidence SET hash=? WHERE tenant=?", ("f"*64, "bank1"))
        with pytest.raises(TrustError):
            ledger.append(measurement())


def test_restart_and_empty_checkpoint(tmp_path):
    signer = Ed25519PrivateKey.generate()
    database = str(tmp_path / "ledger.db")
    with EvidenceLedger(database, "bank1", signer) as ledger:
        empty = ledger.export()
        assert verify_export(empty["records"], empty["signed_checkpoint"], signer.public_key())
        ledger.append(measurement())
    with EvidenceLedger(database, "bank1", signer) as ledger:
        restored = ledger.export()
    assert len(restored["records"]) == 1
    assert verify_export(restored["records"], restored["signed_checkpoint"], signer.public_key())
