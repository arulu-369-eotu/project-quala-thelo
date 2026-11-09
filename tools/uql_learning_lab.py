#!/usr/bin/env python3
"""Local learning experiments over the public UQL Python API.

Uses synthetic data only. Reports are self-reported observations, not signed
attestations, security certifications, or a new license grant.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import json
import math
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "uql-learning-lab/1"
DOMAIN = b"UQL-PUBLIC-LEARNING-LAB-v1\x00"
MAX_REPORT_BYTES = 262_144
REPOSITORY = "https://github.com/arulu-369-eotu/project-quala-thelo"
SOURCE_PATHS = (
    "citadel-core/uql_compiler/__init__.py",
    "citadel-core/uql_compiler/architecture.py",
    "citadel-core/uql_compiler/crypto.py",
    "citadel-core/uql_compiler/dd.py",
    "citadel-core/uql_compiler/memory.py",
    "citadel-core/uql_compiler/native_crypto.py",
    "citadel-core/uql_compiler/qec.py",
    "tools/uql_learning_lab.py",
)
CHECKS = ("declarations", "memory", "coherence", "surface", "dd", "crypto")
DEPENDENCIES = ("uql-omniversal-compiler", "qiskit", "cirq-core", "cryptography")
MODEL = "exp(-idle_us/min(t1_us,t2_us))"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(report: dict) -> str:
    return hashlib.sha256(DOMAIN + canonical(report)).hexdigest()


def _number(value: object, *, positive: bool = False) -> float:
    if type(value) not in (int, float):
        raise ValueError("model inputs must be numbers, not strings or booleans")
    if not 0 <= value <= 1_000_000 or not math.isfinite(value):
        raise ValueError("times must be finite and between 0 and 1000000 microseconds")
    if positive and value == 0:
        raise ValueError("coherence times must be positive")
    return float(value)


def validate_inputs(inputs: object) -> dict:
    fields = {"t1_us", "t2_us", "compare_t2_us", "idle_us", "distance"}
    if not isinstance(inputs, dict) or set(inputs) != fields:
        raise ValueError("invalid experiment input fields")
    out = {key: _number(inputs[key], positive=True) for key in ("t1_us", "t2_us")}
    other = inputs["compare_t2_us"]
    out["compare_t2_us"] = None if other is None else _number(other, positive=True)
    times = inputs["idle_us"]
    if not isinstance(times, list) or not 1 <= len(times) <= 64:
        raise ValueError("provide 1 to 64 idle times")
    out["idle_us"] = [_number(value) for value in times]
    distance = inputs["distance"]
    if type(distance) is not int or distance not in (3, 5, 7, 9):
        raise ValueError("distance must be one of 3, 5, 7, 9")
    out["distance"] = distance
    return out


def public_sources(root: Path = ROOT) -> dict[str, str]:
    """Read only this explicit public-source allowlist; never traverse a tree."""
    root = root.resolve()
    sources = {}
    for relative in SOURCE_PATHS:
        path = root / relative
        if not path.is_file() or path.resolve() != root / relative:
            raise ValueError("an allowlisted public source is missing or is a symlink")
        sources[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return sources


def _revision() -> str:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                capture_output=True, text=True, timeout=2, check=True)
        value = result.stdout.strip()
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
            return value
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def _runtime() -> dict:
    versions = {}
    for name in DEPENDENCIES:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = "not-installed"
    return {"python": platform.python_version(), "platform": platform.system(),
            "packages": versions}


def _declarations() -> dict:
    api = importlib.import_module("uql_compiler.architecture")
    architecture = api.ArchitectureDeclaration(
        name="Beginner local exercise", version="1", mechanisms=(), security_properties=())
    manifest = api.CompilerManifest(architecture)
    unknown = manifest.is_verified("unrun-example")
    if unknown:
        raise ValueError("an unrun example was marked verified")
    return {"unknown_mechanism_verified": unknown}


def _memory() -> dict:
    api = importlib.import_module("uql_compiler.memory")
    with api.LockedBuffer(b"DEMO") as buffer:
        status = buffer.status
        buffer.wipe()
        wiped = bytes(buffer.view()) == b"\x00" * 4
        if not wiped:
            raise ValueError("synthetic buffer did not wipe")
        return {"bytes": len(buffer), "wiped": wiped, "locked": status.locked,
                "dump_excluded": status.dump_excluded}


def _coherence(inputs: dict) -> dict:
    api = importlib.import_module("uql_compiler.dd")
    scenarios = []
    pairs = [("reference", inputs["t2_us"])]
    if inputs["compare_t2_us"] is not None:
        pairs.append(("comparison", inputs["compare_t2_us"]))
    for name, t2 in pairs:
        model = api.CoherenceModel(inputs["t1_us"], t2)
        scenarios.append({"name": name, "effective_coherence_us": model.effective_coherence_us,
                          "survival": [model.survival_fraction(t) for t in inputs["idle_us"]]})
    return {"model": MODEL, "scenarios": scenarios}


def _surface(inputs: dict) -> dict:
    api = importlib.import_module("uql_compiler.qec")
    code = api.SurfaceCode(inputs["distance"])
    code.validate()
    return {"parameters": list(code.parameters), "ancillas": code.num_ancillas}


def _dd(inputs: dict) -> dict:
    api = importlib.import_module("uql_compiler.dd")
    qiskit = importlib.import_module("qiskit")
    circuit = qiskit.QuantumCircuit(1)
    circuit.h(0)
    circuit.delay(2000, 0, unit="dt")
    circuit.h(0)
    output = api.apply_dynamical_decoupling(
        circuit, api.CoherenceModel(inputs["t1_us"], inputs["t2_us"]))
    pulses = int(output.count_ops().get("x", 0))
    if pulses < 2:
        raise ValueError("expected refocusing pulses were absent")
    return {"x_pulses": pulses}


def _probe(function, *args) -> dict:
    try:
        return {"status": "passed", "details": function(*args)}
    except Exception as exc:
        # A class name aids diagnosis without publishing tracebacks, paths, or data.
        return {"status": "blocked", "details": {"error_type": type(exc).__name__}}


def build_report(inputs: dict) -> dict:
    inputs = validate_inputs(inputs)
    sources = public_sources()
    results = {
        "declarations": _probe(_declarations),
        "memory": _probe(_memory),
        "coherence": _probe(_coherence, inputs),
        "surface": _probe(_surface, inputs),
        "dd": _probe(_dd, inputs),
        "crypto": {"status": "not_run", "details": {"reason": "outside_learning_lab"}},
    }
    # Detect modifications during the run rather than attributing mixed sources.
    if public_sources() != sources:
        raise ValueError("public sources changed during the experiment")
    report = {"schema": SCHEMA, "provenance": {"repository": REPOSITORY,
              "git_revision": _revision(), "sources": sources}, "runtime": _runtime(),
              "inputs": inputs, "results": results}
    return {"report": report, "sha256": digest(report)}


def _keys(value: object, fields: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("report fields do not match the supported format")


def _text(value: object, maximum: int = 100) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise ValueError("invalid report text")


def _validate_results(results: object, inputs: dict) -> None:
    _keys(results, set(CHECKS))
    for name in CHECKS:
        result = results[name]
        _keys(result, {"status", "details"})
        status, details = result["status"], result["details"]
        if name == "crypto":
            if result != {"status": "not_run", "details": {"reason": "outside_learning_lab"}}:
                raise ValueError("the lab cannot claim cryptographic validation")
            continue
        if status == "blocked":
            _keys(details, {"error_type"})
            _text(details["error_type"])
            continue
        if status != "passed":
            raise ValueError("invalid check status")
        if name == "declarations":
            _keys(details, {"unknown_mechanism_verified"})
            if details["unknown_mechanism_verified"] is not False:
                raise ValueError("unrun declarations cannot count as verified")
        elif name == "memory":
            _keys(details, {"bytes", "wiped", "locked", "dump_excluded"})
            if type(details["bytes"]) is not int or details["bytes"] != 4 or details["wiped"] is not True:
                raise ValueError("invalid synthetic memory observation")
            if any(type(details[key]) is not bool for key in ("locked", "dump_excluded")):
                raise ValueError("invalid memory capability flags")
        elif name == "coherence":
            _keys(details, {"model", "scenarios"})
            pairs = [("reference", inputs["t2_us"])]
            if inputs["compare_t2_us"] is not None:
                pairs.append(("comparison", inputs["compare_t2_us"]))
            scenarios = details["scenarios"]
            if details["model"] != MODEL or not isinstance(scenarios, list) or len(scenarios) != len(pairs):
                raise ValueError("invalid model scenarios")
            for scenario, (label, t2) in zip(scenarios, pairs):
                _keys(scenario, {"name", "effective_coherence_us", "survival"})
                effective = min(inputs["t1_us"], t2)
                if scenario["name"] != label or _number(scenario["effective_coherence_us"], positive=True) != effective:
                    raise ValueError("model coherence does not match its inputs")
                survival = scenario["survival"]
                if not isinstance(survival, list) or len(survival) != len(inputs["idle_us"]):
                    raise ValueError("invalid model curve")
                for idle, observed in zip(inputs["idle_us"], survival):
                    value = _number(observed)
                    if value > 1 or not math.isclose(value, math.exp(-idle / effective), rel_tol=1e-12, abs_tol=1e-15):
                        raise ValueError("model curve does not match its inputs")
        elif name == "surface":
            _keys(details, {"parameters", "ancillas"})
            distance = inputs["distance"]
            parameters = details["parameters"]
            if (not isinstance(parameters, list) or any(type(v) is not int for v in parameters)
                    or parameters != [distance * distance, 1, distance]
                    or type(details["ancillas"]) is not int or details["ancillas"] != distance * distance - 1):
                raise ValueError("surface counts do not match the selected distance")
        elif name == "dd":
            _keys(details, {"x_pulses"})
            if type(details["x_pulses"]) is not int or not 2 <= details["x_pulses"] <= 100:
                raise ValueError("invalid DD pulse observation")


def verify(envelope: object, *, match_sources: bool = True) -> dict:
    _keys(envelope, {"report", "sha256"})
    report, expected = envelope["report"], envelope["sha256"]
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("invalid integrity digest")
    _keys(report, {"schema", "provenance", "runtime", "inputs", "results"})
    if report["schema"] != SCHEMA:
        raise ValueError("unsupported report schema")
    inputs = validate_inputs(report["inputs"])
    provenance = report["provenance"]
    _keys(provenance, {"repository", "git_revision", "sources"})
    if provenance["repository"] != REPOSITORY:
        raise ValueError("unexpected source repository")
    revision = provenance["git_revision"]
    if not isinstance(revision, str) or (revision != "unknown" and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision)):
        raise ValueError("invalid source revision")
    sources = provenance["sources"]
    _keys(sources, set(SOURCE_PATHS))
    if any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v) for v in sources.values()):
        raise ValueError("invalid public-source fingerprint")
    runtime = report["runtime"]
    _keys(runtime, {"python", "platform", "packages"})
    _text(runtime["python"])
    _text(runtime["platform"])
    _keys(runtime["packages"], set(DEPENDENCIES))
    for value in runtime["packages"].values():
        _text(value)
    _validate_results(report["results"], inputs)
    if digest(report) != expected:
        raise ValueError("report integrity digest does not match")
    if match_sources and sources != public_sources():
        raise ValueError("report fingerprints do not match this checkout's public sources")
    return report


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON fields are not accepted")
        value[key] = item
    return value


def _invalid_constant(value: str):
    raise ValueError("non-finite JSON numbers are not accepted")


def load_report(path: Path) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("report exceeds the 256 KiB limit")
    return json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant)


def summary(report: dict) -> None:
    print("UQL Learning Lab: local synthetic experiments")
    for name in CHECKS:
        result = report["results"][name]
        suffix = ""
        if result["status"] == "blocked":
            suffix = " (" + result["details"]["error_type"] + ")"
        print(f"{name}: {result['status']}{suffix}")
    result = report["results"]["coherence"]
    if result["status"] == "passed":
        print("Coherence comparison: mathematical model, not hardware measurements")
        scenarios = result["details"]["scenarios"]
        for index, idle in enumerate(report["inputs"]["idle_us"]):
            values = ", ".join(f"{s['name']}={s['survival'][index]:.6f}" for s in scenarios)
            print(f"idle {idle:g} us: {values}")
    print("A passed check covers only its named exercise; crypto is not exercised.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run local synthetic exercises")
    run.add_argument("--t1-us", type=float, default=100.0)
    run.add_argument("--t2-us", type=float, default=80.0)
    run.add_argument("--compare-t2-us", type=float)
    run.add_argument("--idle-us", nargs="+", type=float, default=[0, 10, 40, 80, 160])
    run.add_argument("--distance", type=int, choices=(3, 5, 7, 9), default=3)
    run.add_argument("--output", type=Path, help="create a new JSON report; never overwrite")
    check = commands.add_parser("verify", help="check format, consistency, digest and source fingerprints")
    check.add_argument("report", type=Path)
    check.add_argument("--replay", action="store_true", help="rerun the public exercises and compare observations")
    check.add_argument("--require-pass", action="append", choices=CHECKS, default=[],
                       help="exit with failure unless this exercise passed; may be repeated")
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            envelope = build_report({"t1_us": args.t1_us, "t2_us": args.t2_us,
                "compare_t2_us": args.compare_t2_us, "idle_us": args.idle_us, "distance": args.distance})
            verify(envelope)
            if args.output is not None:
                # Exclusive creation also refuses an existing symlink or regular file.
                with args.output.open("x", encoding="utf-8") as output:
                    output.write(json.dumps(envelope, indent=2, sort_keys=True, allow_nan=False) + "\n")
                print("Created JSON experiment report.")
            summary(envelope["report"])
        else:
            report = verify(load_report(args.report))
            if args.replay:
                replay = build_report(report["inputs"])["report"]
                if replay["results"] != report["results"]:
                    raise ValueError("replayed observations differ; inspect environment and capability changes")
                print("Replay: observations match.")
            for name in args.require_pass:
                if report["results"][name]["status"] != "passed":
                    raise ValueError(f"required exercise did not pass: {name}")
            print("Report format, consistency, SHA-256 digest and public-source fingerprints match.")
            print("Trust scope: self-reported evidence; no signature or independent attestation.")
        return 0
    except (OSError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(f"UQL Learning Lab rejected the operation: {detail}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
