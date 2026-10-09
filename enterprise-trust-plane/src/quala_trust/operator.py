"""Separate-process reference operator for witness and ABRAXAS 7.

Run on independent hosts, with preinstalled trust roots and separate
filesystems/keys. This CLI uses PEM test keys; production deployments must
replace file-backed signers with independently managed HSM/KMS signers.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .abraxas7 import Abraxas7Verifier, AssurancePolicy
from .github_ci import GitHubIdentity, verify_github_ci
from .proof369 import EvidenceLedger
from .protocol import TrustError, canonical
from .witness import WitnessStore

MAX_INPUT = 16_777_216


def read_document(path: str) -> Any:
    file = Path(path)
    if not file.is_file() or not 0 < file.stat().st_size <= MAX_INPUT:
        raise TrustError("input file missing or too large")
    def pairs(seq):
        out = {}
        for k, v in seq:
            if k in out:
                raise TrustError("duplicate JSON field")
            out[k] = v
        return out
    try:
        return json.loads(file.read_text(encoding="utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              TrustError("non-finite JSON number")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise TrustError("invalid JSON evidence") from exc


def private_key(path: str) -> Ed25519PrivateKey:
    file = Path(path)
    info = file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise TrustError("private key file must be regular and mode 0600")
    if os.name == "posix" and info.st_uid != os.getuid():
        raise TrustError("private key owner mismatch")
    if info.st_size > 16_384:
        raise TrustError("oversized PEM private key")
    result = serialization.load_pem_private_key(file.read_bytes(), password=None)
    if not isinstance(result, Ed25519PrivateKey):
        raise TrustError("Ed25519 signing key required")
    return result


def public_key(path: str) -> Ed25519PublicKey:
    file = Path(path)
    if not file.is_file() or file.stat().st_size > 16_384:
        raise TrustError("invalid PEM public key")
    result = serialization.load_pem_public_key(file.read_bytes())
    if not isinstance(result, Ed25519PublicKey):
        raise TrustError("Ed25519 trust root required")
    return result


def write_new(path: str, value: Any) -> None:
    """Refuse overwrites/symlinks and create reviewer-owned output mode 0600."""
    data = canonical(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def cli(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="PROOF-369 independent assurance operator")
    sub = p.add_subparsers(dest="command", required=True)
    witness = sub.add_parser("witness", help="Run on a separate witness operator host")
    witness.add_argument("--id", required=True)
    witness.add_argument("--tenant", required=True)
    witness.add_argument("--database", required=True)
    witness.add_argument("--checkpoint-public", required=True)
    witness.add_argument("--witness-private", required=True)
    witness.add_argument("--evidence", required=True)
    witness.add_argument("--out", required=True)
    ingest = sub.add_parser("ingest", help="Verify GitHub attestation before admitting a measured record")
    ingest.add_argument("--tenant", required=True)
    ingest.add_argument("--repo", required=True)
    ingest.add_argument("--source-sha", required=True)
    ingest.add_argument("--source-ref", default="refs/heads/main")
    ingest.add_argument("--database", required=True)
    ingest.add_argument("--proof-private", required=True)
    ingest.add_argument("--ci-report", required=True)
    ingest.add_argument("--gh-executable", default="gh")
    ingest.add_argument("--bundle")
    ingest.add_argument("--trusted-root")
    ingest.add_argument("--out", required=True)
    verify = sub.add_parser("verify", help="Run on a separate ABRAXAS verifier host")
    verify.add_argument("--id", required=True)
    verify.add_argument("--tenant", required=True)
    verify.add_argument("--audience", required=True)
    verify.add_argument("--challenge-hex", required=True,
                        help="64 hex characters from a relying-party 32-byte random challenge")
    verify.add_argument("--repo", required=True)
    verify.add_argument("--source-sha", required=True)
    verify.add_argument("--source-ref", default="refs/heads/main")
    verify.add_argument("--checkpoint-public", required=True)
    verify.add_argument("--verifier-private", required=True)
    verify.add_argument("--witness-public", action="append", required=True,
                        help="Pinned witness-id=/path/to/public.pem, repeat at least twice")
    verify.add_argument("--witness-receipt", action="append", required=True)
    verify.add_argument("--min-witnesses", type=int, default=2)
    verify.add_argument("--evidence", required=True)
    verify.add_argument("--ci-report", required=True)
    verify.add_argument("--gh-executable", default="gh")
    verify.add_argument("--bundle")
    verify.add_argument("--trusted-root")
    verify.add_argument("--out", required=True)
    a = p.parse_args(argv)
    if a.command == "witness":
        with WitnessStore(a.database, a.id, a.tenant,
                          public_key(a.checkpoint_public),
                          private_key(a.witness_private)) as store:
            receipt = store.witness(read_document(a.evidence))
        write_new(a.out, receipt)
        return 0
    if a.command == "ingest":
        if a.source_ref != "refs/heads/main":
            raise TrustError("admission of non-main CI is prohibited")
        identity = GitHubIdentity(a.repo,
            f"{a.repo}/.github/workflows/proof369-attested-ci.yml",
            a.source_sha, a.source_ref)
        proven = verify_github_ci(
            a.ci_report, identity, a.tenant,
            gh_executable=a.gh_executable, bundle_path=a.bundle,
            trusted_root_path=a.trusted_root,
        )
        with EvidenceLedger(a.database, a.tenant,
                            private_key(a.proof_private)) as ledger:
            ledger.append(proven.measurement)
            result = ledger.export()
        write_new(a.out, result)
        return 0
    keys = {}
    for item in a.witness_public:
        if "=" not in item:
            raise TrustError("expected witness-id=public-key-path")
        name, path = item.split("=", 1)
        if name in keys:
            raise TrustError("duplicate witness identity")
        keys[name] = public_key(path)
    identity = GitHubIdentity(
        a.repo, f"{a.repo}/.github/workflows/proof369-attested-ci.yml",
        a.source_sha, a.source_ref,
    )
    policy = AssurancePolicy(a.tenant, identity, keys, a.min_witnesses,
                             audience=a.audience)
    if len(a.challenge_hex) != 64 or any(c not in "0123456789abcdef" for c in a.challenge_hex):
        raise TrustError("invalid relying-party challenge encoding")
    verified = Abraxas7Verifier(
        a.id, public_key(a.checkpoint_public), private_key(a.verifier_private),
        policy,
    ).admit(
        read_document(a.evidence),
        [read_document(path) for path in a.witness_receipt],
        a.ci_report,
        audience=a.audience, client_challenge=bytes.fromhex(a.challenge_hex),
        github_options={
            "gh_executable": a.gh_executable,
            "bundle_path": a.bundle,
            "trusted_root_path": a.trusted_root,
        },
    )
    write_new(a.out, verified)
    return 0


def main() -> None:
    try:
        sys.exit(cli())
    except (TrustError, OSError, ValueError, TypeError) as exc:
        print(f"DENY: {exc.__class__.__name__}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
