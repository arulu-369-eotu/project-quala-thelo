import copy
import hashlib
from pathlib import Path

import pytest

from uql_compiler.next.cli import main
from uql_compiler.next.evidence import (ALL_FILES, build_bundle, manifest_digest,
    verify_bundle, write_bundle)
from uql_compiler.next.identity import SEAL_SHA256
from uql_compiler.next.model import UQLError, canonical_bytes, strict_json

SOURCE = "uql 0.2; program Test { qubits 1; bits 1; x q[0]; measure q[0] -> c[0]; }"


def test_reproducible_bundle_pin_and_seal(tmp_path):
    assert build_bundle(SOURCE) == build_bundle(SOURCE)
    destination = tmp_path / "bundle"
    pin = write_bundle(SOURCE, destination)
    assert {p.name for p in destination.iterdir()} == ALL_FILES
    assert hashlib.sha256((destination / "seal.jpg").read_bytes()).hexdigest() == SEAL_SHA256
    report = verify_bundle(destination, expected_digest=pin)
    assert report["external_digest_pin"] == "MATCHED"
    assert report["publisher_identity"] == "UNVERIFIED"
    with pytest.raises(UQLError):
        verify_bundle(destination, expected_digest="0" * 64)
    with pytest.raises(UQLError):
        write_bundle(SOURCE, destination)


@pytest.mark.parametrize("name", ["program.uql", "program.ll", "program.qasm", "program.uir.json",
    "transforms.json", "claims.json", "seal.jpg", "passport.json"])
def test_modified_member_rejected(tmp_path, name):
    write_bundle(SOURCE, tmp_path / "bundle")
    p = tmp_path / "bundle" / name
    p.write_bytes(p.read_bytes() + b"tamper")
    with pytest.raises(UQLError):
        verify_bundle(p.parent)


def test_forged_claim_even_with_rehashed_manifest_rejected(tmp_path):
    root = tmp_path / "bundle"
    write_bundle(SOURCE, root)
    raw = strict_json((root / "claims.json").read_bytes())
    raw["claims"][3]["status"] = "PASS"
    content = canonical_bytes(raw)
    (root / "claims.json").write_bytes(content)
    manifest = strict_json((root / "manifest.json").read_bytes())
    manifest["files"]["claims.json"] = {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
    (root / "manifest.json").write_bytes(canonical_bytes(manifest))
    with pytest.raises(UQLError, match="rebuild mismatch"):
        verify_bundle(root)


@pytest.mark.parametrize("mode", ["extra", "missing", "symlink", "traversal", "bool_size", "bad_options"])
def test_reject_hostile_bundle(tmp_path, mode):
    root = tmp_path / "bundle"
    write_bundle(SOURCE, root)
    manifest_path = root / "manifest.json"
    manifest = strict_json(manifest_path.read_bytes())
    if mode == "extra":
        (root / "extra.txt").write_text("extra")
    elif mode == "missing":
        (root / "program.ll").unlink()
    elif mode == "symlink":
        original = root / "program.uql"
        other = tmp_path / "external.uql"
        other.write_bytes(original.read_bytes())
        original.unlink()
        original.symlink_to(other)
    else:
        if mode == "traversal":
            manifest["files"]["../external"] = manifest["files"].pop("program.ll")
        elif mode == "bool_size":
            manifest["files"]["program.ll"]["size"] = True
        elif mode == "bad_options":
            manifest["options"]["optimization"] = "false"
        manifest_path.write_bytes(canonical_bytes(manifest))
    with pytest.raises(UQLError):
        verify_bundle(root)


def test_no_optimization_and_cli(tmp_path, capsys):
    source_path = tmp_path / "program.uql"
    source_path.write_text(SOURCE)
    out = tmp_path / "bundle"
    assert main(["compile", str(source_path), "--out", str(out), "--no-optimize"]) == 0
    assert main(["verify", str(out)]) == 0
    assert main(["simulate", str(source_path)]) == 0
    assert main(["inspect", str(source_path)]) == 0
    assert main(["verify", str(out), "--expect", "bad"]) == 1
    assert '"status": "FAIL"' in capsys.readouterr().err
