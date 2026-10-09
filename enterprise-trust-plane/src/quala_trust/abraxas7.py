"""ABRAXAS 7 independent admission verifier (reference implementation).

The verifier refuses to issue ALLOW unless it can verify:
  1. a complete PROOF-369 signed evidence chain;
  2. the actual artifact's GitHub/Sigstore provenance through trusted gh CLI;
  3. a fresh CI PASS bound byte-for-byte to the signed chain; and
  4. a quorum of uniquely keyed, pinned external checkpoint witnesses.

A separate deployment/operator and hardware-protected signer are operational
requirements not provided by this library.
"""
from __future__ import annotations

from dataclasses import dataclass
import time
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .github_ci import GitHubIdentity, VerifiedGitHubEvidence, verify_github_ci
from .proof369 import verify_export, verify_checkpoint
from .protocol import TrustError, canonical, digest, identifier
from .witness import public_key_fingerprint, verify_witness_receipt

ABRAXAS_DOMAIN = b"ABRAXAS-7-ASSURANCE-v1\x00"
ABRAXAS_VERSION = "abraxas7-assurance-v1"


@dataclass(frozen=True)
class AssurancePolicy:
    tenant: str
    expected_github: GitHubIdentity
    witness_keys: Mapping[str, Ed25519PublicKey]
    min_witnesses: int = 2
    max_age_seconds: int = 3600

    def __post_init__(self) -> None:
        identifier(self.tenant)
        if type(self.min_witnesses) is not int or self.min_witnesses < 2:
            raise TrustError("ABRAXAS requires at least two witnesses")
        if type(self.max_age_seconds) is not int or not 1 <= self.max_age_seconds <= 86_400:
            raise TrustError("invalid assurance freshness")
        if len(self.witness_keys) < self.min_witnesses:
            raise TrustError("insufficient enrolled external witnesses")
        fingerprints = set()
        for witness_id, key in self.witness_keys.items():
            identifier(witness_id)
            if not isinstance(key, Ed25519PublicKey):
                raise TrustError("invalid witness public key")
            fingerprint = public_key_fingerprint(key)
            if fingerprint in fingerprints:
                raise TrustError("same signing key cannot count as two witnesses")
            fingerprints.add(fingerprint)
        if self.expected_github.source_ref != "refs/heads/main":
            # Feature-branch attestations are valid for testing but never
            # admissible under a high-assurance production policy.
            raise TrustError("production acceptance requires protected main ref")

    @property
    def sha256(self) -> str:
        return digest({
            "tenant": self.tenant,
            "repo": self.expected_github.repo,
            "signer_workflow": self.expected_github.signer_workflow,
            "source_sha": self.expected_github.source_sha,
            "source_ref": self.expected_github.source_ref,
            "witness_ids": sorted(self.witness_keys),
            "witness_fingerprints": sorted(
                public_key_fingerprint(k) for k in self.witness_keys.values()
            ),
            "min_witnesses": self.min_witnesses,
            "max_age_seconds": self.max_age_seconds,
        })


def verify_assurance_receipt(envelope: Any, key: Ed25519PublicKey) -> dict[str, Any]:
    if type(envelope) is not dict or set(envelope) != {"receipt", "signature"}:
        raise TrustError("invalid ABRAXAS envelope")
    body = envelope["receipt"]
    if type(body) is not dict or set(body) != {
        "version", "verifier_id", "decision", "tenant", "checkpoint_sha256",
        "policy_sha256", "github_artifact_sha256", "github_run_id",
        "source_sha", "source_ref", "witness_ids", "checked_at",
    } or body.get("version") != ABRAXAS_VERSION:
        raise TrustError("invalid ABRAXAS receipt")
    if body.get("decision") != "ALLOW":
        raise TrustError("invalid ABRAXAS admission decision")
    identifier(body["verifier_id"])
    identifier(body["tenant"])
    for field in ("checkpoint_sha256", "policy_sha256", "github_artifact_sha256"):
        value = body[field]
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise TrustError("invalid ABRAXAS digest")
    if type(body["github_run_id"]) is not int or body["github_run_id"] <= 0:
        raise TrustError("invalid ABRAXAS run ID")
    if type(body["checked_at"]) is not int or body["checked_at"] < 0:
        raise TrustError("invalid ABRAXAS time")
    if type(body["witness_ids"]) is not list or len(body["witness_ids"]) < 2:
        raise TrustError("missing ABRAXAS quorum")
    if len(set(body["witness_ids"])) != len(body["witness_ids"]):
        raise TrustError("duplicate ABRAXAS witness")
    sig = envelope["signature"]
    if type(sig) is not str or len(sig) != 128:
        raise TrustError("invalid ABRAXAS signature")
    try:
        key.verify(bytes.fromhex(sig), ABRAXAS_DOMAIN + canonical(body))
    except (ValueError, InvalidSignature) as exc:
        raise TrustError("ABRAXAS signature rejected") from exc
    return body


class Abraxas7Verifier:
    def __init__(self, verifier_id: str, proof_key: Ed25519PublicKey,
                 signing_key: Ed25519PrivateKey, policy: AssurancePolicy):
        self.verifier_id = identifier(verifier_id)
        if not isinstance(proof_key, Ed25519PublicKey):
            raise TrustError("PROOF-369 root must be pinned")
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise TrustError("ABRAXAS signer is required")
        self.proof_key = proof_key
        self.signing_key = signing_key
        self.policy = policy

    def admit(
        self, evidence: dict[str, Any], witness_receipts: list[dict[str, Any]],
        ci_report_path: str | Path, *, now: int | None = None,
        github_options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        stamp = int(time.time()) if now is None else now
        if type(stamp) is not int or stamp < 0:
            raise TrustError("invalid verifier time")
        if type(evidence) is not dict or set(evidence) != {"records", "signed_checkpoint"}:
            raise TrustError("invalid evidence bundle")
        rows = evidence["records"]
        signed = evidence["signed_checkpoint"]
        verify_export(rows, signed, self.proof_key)
        checkpoint = verify_checkpoint(signed, self.proof_key)
        if checkpoint["tenant"] != self.policy.tenant:
            raise TrustError("tenant trust boundary violated")
        if checkpoint["issued_at"] > stamp + 60 or (
            stamp - checkpoint["issued_at"] > self.policy.max_age_seconds
        ):
            raise TrustError("PROOF checkpoint too old or future-dated")

        if type(witness_receipts) is not list:
            raise TrustError("invalid witness list")
        valid = {}
        for signed_witness in witness_receipts:
            if type(signed_witness) is not dict or type(signed_witness.get("receipt")) is not dict:
                raise TrustError("malformed witness response")
            witness_id = signed_witness["receipt"].get("witness_id")
            if type(witness_id) is not str or witness_id not in self.policy.witness_keys:
                raise TrustError("untrusted witness")
            if witness_id in valid:
                raise TrustError("duplicate witness receipt")
            body = verify_witness_receipt(
                signed_witness, self.policy.witness_keys[witness_id],
                witness_id, checkpoint,
            )
            if (body["recorded_at"] < checkpoint["issued_at"] - 60 or
                    body["recorded_at"] > stamp + 60 or
                    stamp - body["recorded_at"] > self.policy.max_age_seconds):
                raise TrustError("stale or future witness")
            valid[witness_id] = body
        if len(valid) < self.policy.min_witnesses:
            raise TrustError("external witness quorum not met")

        verified: VerifiedGitHubEvidence = verify_github_ci(
            ci_report_path, self.policy.expected_github, self.policy.tenant,
            **(github_options or {}),
        )
        if (verified.measurement["measured_at"] > checkpoint["issued_at"] + 60 or
                verified.measurement["measured_at"] > stamp + 60 or
                stamp - verified.measurement["measured_at"] > self.policy.max_age_seconds):
            raise TrustError("GitHub CI measurement stale or future-dated")
        matches = [
            row["measurement"] for row in rows
            if row["measurement"]["subject"] == "github-ci" and
            row["measurement"]["control"] == "quala-passport-tests"
        ]
        if len(matches) != 1 or matches[0] != verified.measurement:
            raise TrustError("GitHub CI artifact not bound to committed evidence")
        if verified.measurement["outcome"] != "PASS":
            raise TrustError("CI failures or skipped tests prohibit admission")
        body = {
            "version": ABRAXAS_VERSION, "verifier_id": self.verifier_id,
            "decision": "ALLOW", "tenant": self.policy.tenant,
            "checkpoint_sha256": digest(checkpoint),
            "policy_sha256": self.policy.sha256,
            "github_artifact_sha256": verified.artifact_sha256,
            "github_run_id": verified.run_id,
            "source_sha": verified.source_sha, "source_ref": verified.source_ref,
            "witness_ids": sorted(valid), "checked_at": stamp,
        }
        return {
            "receipt": body,
            "signature": self.signing_key.sign(ABRAXAS_DOMAIN + canonical(body)).hex(),
        }
