"""Deterministic, unsigned UQL Evidence Bundles and a strict local verifier.

A digest authenticates nothing without a separately trusted pin or signature.
Verification rebuilds data; it never loads LLVM or executes submitted code.
"""
from __future__ import annotations

from fractions import Fraction
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from . import VERSION
from .emit import openqasm, qir
from .identity import seal_bytes, visual_identity
from .model import (MAX_SOURCE_BYTES, Operation, UQLError, canonical_bytes,
                    digest, exact_keys, strict_json)
from .parser import parse
from .passes import SELF_INVERSE, enforce_contract, optimize

PAYLOAD_FILES = frozenset({"program.uql", "ast.json", "program.uir.json", "program.qasm",
                           "program.ll", "transforms.json", "resources.json", "qbom.json",
                           "claims.json", "passport.json", "proof369.json", "identity.json", "seal.jpg"})
ALL_FILES = PAYLOAD_FILES | {"manifest.json"}
MAX_FILE_BYTES = 8_000_000
MAX_BUNDLE_BYTES = 32_000_000


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def compiler_identity():
    files = sorted(Path(__file__).parent.glob("*.py"))
    components = {p.name: sha256(p.read_bytes()) for p in files}
    return {"name": "uql-next", "version": VERSION,
            "source_digest": digest(components, "uql.compiler-source/0.2"),
            "signature": "UNVERIFIED"}


def validate_receipts(original, result, receipts):
    """Check each named identity and replay edits without invoking the optimizer."""
    current = original
    for receipt in receipts:
        if receipt["input_digest"] != current.ir_digest:
            raise UQLError("transform input digest mismatch")
        ops = list(current.operations)
        for change in receipt["changes"]:
            before = [Operation.from_dict(o) for o in change["before"]]
            after = [Operation.from_dict(o) for o in change["after"]]
            i = change["offset"]
            if type(i) is not int or i < 0 or ops[i:i + len(before)] != before:
                raise UQLError("transform edit does not match input")
            rule = change["rule"]
            valid = False
            if rule == "self-inverse-adjacent/1":
                valid = len(before) == 2 and before[0] == before[1] and before[0].gate in SELF_INVERSE and not after
            elif rule == "rz-zero/1":
                valid = len(before) == 1 and before[0].gate == "rz" and before[0].phase == 0 and not after
            elif rule == "rz-add-adjacent/1" and len(before) == 2:
                a, b = before
                if a.gate == b.gate == "rz" and a.qubits == b.qubits:
                    phase = a.phase + b.phase
                    valid = after == ([] if phase == Fraction(0) else [Operation("rz", a.qubits, phase)])
            if not valid:
                raise UQLError("invalid rewrite rule application")
            ops[i:i + len(before)] = after
        current = current.with_operations(ops)
        if receipt["output_digest"] != current.ir_digest:
            raise UQLError("transform output digest mismatch")
    if current != result:
        raise UQLError("transform chain does not reach compiled IR")


def build_bundle(source, *, optimization=True):
    if type(optimization) is not bool:
        raise UQLError("optimization must be boolean")
    original = parse(source)
    compiled, receipts = optimize(original) if optimization else (original, [])
    validate_receipts(original, compiled, receipts)
    resource_report = enforce_contract(compiled)
    identity = compiler_identity()
    source_hash = sha256(source.encode("utf-8"))
    claims = [
        {"id": "C001", "statement": "Local exact rewrite records replay to the compiled IR",
         "status": "PASS", "method": "bounded_named_rule_checker", "formal_proof": False},
        {"id": "C002", "statement": "OpenQASM lowering independently validated for this artifact", "status": "UNVERIFIED"},
        {"id": "C003", "statement": "QIR lowering independently validated for this artifact", "status": "UNVERIFIED"},
        {"id": "C004", "statement": "Hardware execution reproduces intended output", "status": "UNVERIFIED"},
    ]
    payload = {
        "program.uql": source.encode("utf-8"),
        "seal.jpg": seal_bytes(),
        "identity.json": canonical_bytes(visual_identity()),
        "ast.json": canonical_bytes(original.to_dict()),
        "program.uir.json": canonical_bytes(compiled.to_dict()),
        "program.qasm": openqasm(compiled).encode("ascii"),
        "program.ll": qir(compiled).encode("ascii"),
        "transforms.json": canonical_bytes({"schema": "uql.transforms/0.2", "receipts": receipts}),
        "resources.json": canonical_bytes(resource_report),
        "qbom.json": canonical_bytes({"schema": "uql.qbom/0.2", "compiler": identity,
            "source_sha256": source_hash, "dialect": "uql/0.2-terminal-qubit",
            "passes": [r["pass"] for r in receipts], "targets": ["openqasm/3.0", "qir/2.0-base"],
            "gate_set": sorted({o.gate for o in compiled.operations}),
            "digest_algorithm": "SHA-256", "signature_algorithm": None,
            "runtime_dependencies": [], "calibration": None, "noise_model": "none"}),
        "claims.json": canonical_bytes({"schema": "uql.claims/0.2", "claims": claims}),
        "passport.json": canonical_bytes({"schema": "uql.passport/0.2", "program": original.name,
            "source_sha256": source_hash, "visual_identity": visual_identity(), "ir_digest": compiled.ir_digest,
            "circuit_digest": compiled.circuit_digest, "compiler": identity,
            "verification_boundary": "local_exact_rewrites_and_reproducible_artifact_generation",
            "independent_reproduction": "NOT_PERFORMED", "backend_attestation": "UNVERIFIED"}),
        "proof369.json": canonical_bytes({"schema": "proof369.uql.local/0.1",
            "adapter_status": "DRAFT_LOCAL_FORMAT", "source_sha256": source_hash,
            "ir_digest": compiled.ir_digest, "circuit_digest": compiled.circuit_digest,
            "local_rule_replay": "PASS", "network_validation": "UNVERIFIED",
            "external_witness": "UNVERIFIED", "abraxas7_attestation": "UNVERIFIED"}),
    }
    manifest = {"schema": "uql.bundle/0.2", "compiler": identity,
                "options": {"optimization": optimization},
                "files": {name: {"sha256": sha256(content), "size": len(content)}
                          for name, content in sorted(payload.items())}}
    payload["manifest.json"] = canonical_bytes(manifest)
    if max(map(len, payload.values())) > MAX_FILE_BYTES or sum(map(len, payload.values())) > MAX_BUNDLE_BYTES:
        raise UQLError("generated bundle exceeds size limits")
    return payload


def manifest_digest(manifest_bytes):
    return digest(strict_json(manifest_bytes), "uql.bundle-manifest/0.2")


def write_bundle(source, destination, *, optimization=True):
    payload = build_bundle(source, optimization=optimization)
    target = Path(destination).absolute()
    if target.exists() or target.is_symlink():
        raise UQLError("output directory must not already exist")
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".uql-stage-", dir=target.parent))
    try:
        for name, content in payload.items():
            p = staging / name
            p.write_bytes(content)
            p.chmod(0o600)
        # mkdir reserves the target; concurrent creators cannot be overwritten.
        target.mkdir(mode=0o700)
        try:
            for p in staging.iterdir():
                p.rename(target / p.name)
        except BaseException:
            shutil.rmtree(target)
            raise
    finally:
        shutil.rmtree(staging)
    return manifest_digest(payload["manifest.json"])


def _read_files(directory):
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise UQLError("bundle must be a real directory")
    if {p.name for p in root.iterdir()} != ALL_FILES:
        raise UQLError("unexpected or missing bundle files")
    payload, total = {}, 0
    for name in sorted(ALL_FILES):
        p = root / name
        # Recheck the opened descriptor; O_NOFOLLOW rejects link substitution.
        if p.is_symlink() or not p.is_file():
            raise UQLError("bundle members must be regular files")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open(p, flags)
            with os.fdopen(fd, "rb") as handle:
                metadata = os.fstat(handle.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_BYTES:
                    raise UQLError("invalid bundle member type or size")
                content = handle.read(MAX_FILE_BYTES + 1)
        except OSError as exc:
            raise UQLError(f"cannot read bundle member: {name}") from exc
        total += len(content)
        if len(content) > MAX_FILE_BYTES or total > MAX_BUNDLE_BYTES:
            raise UQLError("bundle size limit exceeded")
        payload[name] = content
    return payload


def verify_payload(payload, *, expected_digest=None):
    """Verify a captured snapshot so callers need not reread it before use."""
    manifest = strict_json(payload["manifest.json"])
    exact_keys(manifest, {"schema", "compiler", "options", "files"}, "manifest")
    if manifest["schema"] != "uql.bundle/0.2":
        raise UQLError("unsupported bundle version")
    exact_keys(manifest["options"], {"optimization"}, "compiler options")
    if type(manifest["options"]["optimization"]) is not bool:
        raise UQLError("invalid optimization flag")
    exact_keys(manifest["files"], PAYLOAD_FILES, "bundle file list")
    actual_digest = manifest_digest(payload["manifest.json"])
    if expected_digest is not None:
        if type(expected_digest) is not str or not re.fullmatch(r"[a-f0-9]{64}", expected_digest):
            raise UQLError("invalid expected manifest digest")
        if actual_digest != expected_digest:
            raise UQLError("trusted manifest digest mismatch")
    for name in PAYLOAD_FILES:
        entry = manifest["files"][name]
        exact_keys(entry, {"sha256", "size"}, "file digest")
        if type(entry["size"]) is not int or entry["size"] != len(payload[name]) or entry["sha256"] != sha256(payload[name]):
            raise UQLError(f"bundle digest mismatch: {name}")
    source_bytes = payload["program.uql"]
    if len(source_bytes) > MAX_SOURCE_BYTES:
        raise UQLError("source size limit exceeded")
    try:
        source = source_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UQLError("invalid source encoding") from exc
    expected = build_bundle(source, optimization=manifest["options"]["optimization"])
    if payload != expected:
        mismatch = sorted(k for k in payload if payload[k] != expected[k])
        raise UQLError("local rebuild mismatch: " + ", ".join(mismatch))
    return {"status": "PASS", "boundary": "integrity_and_local_deterministic_rebuild",
            "manifest_digest": actual_digest,
            "external_digest_pin": "MATCHED" if expected_digest else "NOT_SUPPLIED",
            "publisher_identity": "UNVERIFIED", "independent_verification": "UNVERIFIED",
            "signature": "UNVERIFIED", "hardware_execution": "UNVERIFIED"}


def verify_bundle(directory, *, expected_digest=None):
    return verify_payload(_read_files(directory), expected_digest=expected_digest)
