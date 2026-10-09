"""Create a deterministic PROOF-369 CI artifact from pytest JUnit XML.

Runs only in the GitHub workflow. Metadata in this file is not trusted until
GitHub/Sigstore attestation verification enforces repository/workflow/ref/SHA.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import time
import xml.etree.ElementTree as ET

from quala_trust.protocol import canonical


def generate_report(junit: str | Path, environment: dict[str, str],
                    *, timestamp: int | None = None) -> dict:
    path = Path(junit)
    if not path.is_file() or path.stat().st_size > 2_000_000:
        raise ValueError("missing or oversized test result")
    root = ET.parse(path).getroot()
    if root.tag not in ("testsuite", "testsuites"):
        raise ValueError("not JUnit XML")
    cases = root.findall(".//testcase")
    if not cases:
        raise ValueError("zero test cases cannot create assurance evidence")
    failed = sum(bool(x.find("failure") is not None or x.find("error") is not None) for x in cases)
    skipped = sum(x.find("skipped") is not None for x in cases)
    if failed + skipped > len(cases):
        raise ValueError("invalid JUnit counts")
    duration = 0.0
    for case in cases:
        value = float(case.get("time", "0"))
        if not 0 <= value <= 1_000_000:
            raise ValueError("invalid JUnit duration")
        duration += value
    repo = environment["GITHUB_REPOSITORY"]
    sha = environment["GITHUB_SHA"]
    ref = environment["GITHUB_REF"]
    run_id = int(environment["GITHUB_RUN_ID"])
    attempt = int(environment.get("GITHUB_RUN_ATTEMPT", "1"))
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+", repo):
        raise ValueError("invalid repository")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("invalid commit")
    if not ref.startswith("refs/heads/"):
        raise ValueError("only branch workflows supported")
    if run_id <= 0 or not 1 <= attempt <= 100:
        raise ValueError("invalid GitHub run identity")
    return {
        "schema": "proof369-github-ci-v1", "repository": repo,
        "workflow": f"{repo}/.github/workflows/proof369-attested-ci.yml",
        "ref": ref, "commit": sha, "run_id": run_id,
        "run_attempt": attempt,
        "timestamp": int(time.time()) if timestamp is None else timestamp,
        "suite": "quala-trust-passport",
        "tests": {
            "test_count": len(cases),
            "passed_count": len(cases) - failed - skipped,
            "failed_count": failed, "skipped_count": skipped,
            "duration_ms": round(duration * 1000),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate GitHub CI evidence for PROOF-369")
    parser.add_argument("--junit", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = generate_report(args.junit, dict(os.environ))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical(report))


if __name__ == "__main__":
    main()
