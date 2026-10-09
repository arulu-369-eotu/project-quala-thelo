"""PROOF-369 authenticated GitHub CI evidence adapter.

Security boundary: the GitHub CLI performs Sigstore/SLSA signature, signer,
repository, source-commit and branch checks. This adapter DOES NOT treat an
unsigned GitHub API response, a JWT decoded without validation, or a local
'PASS' field as cryptographic proof. Install and pin a trusted gh executable.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable

from .protocol import TrustError, canonical, loads_strict
from .proof369 import validate_measurement

_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
_REPORT_VERSION = "proof369-github-ci-v1"
_MAX_REPORT = 1_048_576
_MAX_CLI_OUTPUT = 2_097_152


@dataclass(frozen=True)
class GitHubIdentity:
    repo: str
    signer_workflow: str
    source_sha: str
    source_ref: str = "refs/heads/main"

    def __post_init__(self) -> None:
        parts = self.repo.split("/")
        if len(parts) != 2 or not all(_NAME.fullmatch(p) for p in parts):
            raise TrustError("invalid expected GitHub repository")
        if self.signer_workflow != f"{self.repo}/.github/workflows/proof369-attested-ci.yml":
            raise TrustError("signer workflow must be the pinned PROOF-369 workflow")
        if not _SHA40.fullmatch(self.source_sha):
            raise TrustError("expected source commit must be 40 lowercase hex characters")
        if not self.source_ref.startswith("refs/heads/"):
            raise TrustError("expected source must be a branch")
        branch = self.source_ref.removeprefix("refs/heads/")
        if not branch or len(branch) > 150 or any(
            not _NAME.fullmatch(part) for part in branch.split("/")
        ):
            raise TrustError("invalid approved source branch")


@dataclass(frozen=True)
class VerifiedGitHubEvidence:
    measurement: dict[str, Any]
    artifact_sha256: str
    run_id: int
    source_sha: str
    repo: str
    source_ref: str


def _load_report(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.stat().st_size > _MAX_REPORT:
        raise TrustError("missing or oversized CI report")
    data = path.read_bytes()
    doc = loads_strict(data)
    if type(doc) is not dict or set(doc) != {
        "schema", "repository", "workflow", "ref", "commit",
        "run_id", "run_attempt", "timestamp", "suite", "tests",
    } or doc["schema"] != _REPORT_VERSION:
        raise TrustError("invalid CI report schema")
    tests = doc["tests"]
    if type(tests) is not dict or set(tests) != {
        "test_count", "passed_count", "failed_count", "skipped_count",
        "duration_ms",
    }:
        raise TrustError("invalid CI test metric fields")
    if type(doc["run_id"]) is not int or doc["run_id"] <= 0:
        raise TrustError("invalid CI run")
    if type(doc["run_attempt"]) is not int or not 1 <= doc["run_attempt"] <= 100:
        raise TrustError("invalid CI attempt")
    if doc["suite"] != "quala-trust-passport":
        raise TrustError("untrusted test suite name")
    return doc, hashlib.sha256(data).hexdigest()


def _run_gh(args: list[str], timeout: int):
    return subprocess.run(args, capture_output=True, text=True, check=False,
                          timeout=timeout, shell=False)


def verify_github_ci(
    report_path: str | Path,
    identity: GitHubIdentity,
    tenant: str,
    *,
    bundle_path: str | Path | None = None,
    trusted_root_path: str | Path | None = None,
    gh_executable: str = "gh",
    timeout: int = 45,
    runner: Callable[..., Any] = _run_gh,
) -> VerifiedGitHubEvidence:
    """Verify genuine GitHub provenance via gh; fail closed on any CLI failure.

    A mock runner is injectable exclusively to test the adapter's fail-closed
    behavior; mock success is not third-party attestation evidence.
    """
    from .protocol import identifier
    identifier(tenant)
    if type(timeout) is not int or not 1 <= timeout <= 120:
        raise TrustError("invalid verification timeout")
    if type(gh_executable) is not str or not gh_executable:
        raise TrustError("trusted gh executable path required")
    path = Path(report_path)
    report, artifact_digest = _load_report(path)
    if (report["repository"] != identity.repo or
        report["workflow"] != identity.signer_workflow or
        report["ref"] != identity.source_ref or
        report["commit"] != identity.source_sha):
        raise TrustError("CI identity or source not approved")
    metrics = report["tests"]
    outcome = "PASS" if (
        metrics["test_count"] > 0 and
        metrics["passed_count"] == metrics["test_count"] and
        metrics["failed_count"] == metrics["skipped_count"] == 0
    ) else "FAIL"
    measurement = {
        "version": "proof369-measurement-v1",
        "subject": "github-ci",
        "tenant": tenant,
        "control": "quala-passport-tests",
        "outcome": outcome,
        "source_sha256": artifact_digest,
        "measured_at": report["timestamp"],
        "metrics": metrics,
    }
    validate_measurement(measurement)
    command = [
        gh_executable, "attestation", "verify", str(path),
        "--repo", identity.repo, "--signer-workflow", identity.signer_workflow,
        "--source-digest", identity.source_sha,
        "--source-ref", identity.source_ref, "--format", "json",
    ]
    if bundle_path is not None:
        if not Path(bundle_path).is_file():
            raise TrustError("required attestation bundle not found")
        command.extend(["--bundle", str(bundle_path)])
    if trusted_root_path is not None:
        if bundle_path is None or not Path(trusted_root_path).is_file():
            raise TrustError("offline trust root requires local bundle")
        command.extend(["--custom-trusted-root", str(trusted_root_path)])
    try:
        result = runner(command, timeout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise TrustError("GitHub signature verifier unavailable") from exc
    if result.returncode != 0 or not isinstance(result.stdout, str):
        raise TrustError("GitHub attestation verification failed")
    if not 0 < len(result.stdout) <= _MAX_CLI_OUTPUT:
        raise TrustError("empty or oversized attestation result")
    try:
        verdict = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise TrustError("malformed GitHub verifier response") from exc
    if not isinstance(verdict, list) or not verdict:
        raise TrustError("GitHub verifier returned no attestations")
    # gh already validates Sigstore identities and artifact digest. Require
    # a nonempty response rather than silently trusting empty CLI output.
    return VerifiedGitHubEvidence(measurement, artifact_digest,
                                  report["run_id"], identity.source_sha,
                                  identity.repo, identity.source_ref)
