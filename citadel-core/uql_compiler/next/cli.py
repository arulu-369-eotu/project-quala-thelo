"""Explicit local compile, verify, inspect, and differential commands."""
import argparse
import json
from pathlib import Path
import sys

from . import VERSION
from .compare import compare as compare_programs
from .evidence import ALL_FILES, _read_files, verify_bundle, verify_payload, write_bundle
from .model import MAX_SOURCE_BYTES, Program, UQLError, strict_json
from .parser import parse
from .passes import resources
from .simulate import differential, probabilities


def read_source(path):
    with Path(path).open("rb") as handle:
        content = handle.read(MAX_SOURCE_BYTES + 1)
    if len(content) > MAX_SOURCE_BYTES:
        raise UQLError("source exceeds size limit")
    return content.decode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="uql", description="UQL NEXT local reference compiler")
    parser.add_argument("--version", action="version", version=f"uql-next {VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)
    compile_cmd = commands.add_parser("compile")
    compile_cmd.add_argument("source")
    compile_cmd.add_argument("--out", required=True)
    compile_cmd.add_argument("--no-optimize", action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("bundle")
    verify.add_argument("--expect", help="manifest digest from a separately trusted channel")
    inspect_cmd = commands.add_parser("inspect")
    inspect_cmd.add_argument("source")
    simulate = commands.add_parser("simulate")
    simulate.add_argument("source")
    compare = commands.add_parser("differential")
    compare.add_argument("bundle")
    compare.add_argument("--backend", action="append", choices=["qiskit", "cirq"])
    compare.add_argument("--tolerance", type=float, default=1e-10)
    compare.add_argument("--expect")
    relation = commands.add_parser("compare")
    relation.add_argument("left")
    relation.add_argument("right")
    relation.add_argument("--relation", choices=["premeasurement_unitary", "zero_input_distribution"],
                          default="premeasurement_unitary")
    relation.add_argument("--tolerance", type=float, default=1e-10)
    args = parser.parse_args(argv)
    try:
        if args.command == "compile":
            pin = write_bundle(read_source(args.source), args.out, optimization=not args.no_optimize)
            result = {"status": "BUILT", "manifest_digest": pin, "files": len(ALL_FILES),
                      "verification": "local_rule_replay", "publisher_identity": "UNVERIFIED"}
        elif args.command == "verify":
            result = verify_bundle(args.bundle, expected_digest=args.expect)
        elif args.command == "inspect":
            program = parse(read_source(args.source))
            result = {"ir_digest": program.ir_digest, "circuit_digest": program.circuit_digest,
                      "resources": resources(program)}
        elif args.command == "simulate":
            result = {"probabilities": probabilities(parse(read_source(args.source))),
                      "boundary": "ideal_zero_input_terminal_measurements"}
        elif args.command == "compare":
            result = compare_programs(parse(read_source(args.left)), parse(read_source(args.right)),
                                      relation=args.relation, tolerance=args.tolerance)
        else:
            payload = _read_files(args.bundle)
            verified = verify_payload(payload, expected_digest=args.expect)
            program = Program.from_dict(strict_json(payload["program.uir.json"]))
            result = differential(program, payload["program.qasm"].decode("ascii"),
                                  tuple(args.backend or ["qiskit", "cirq"]), args.tolerance)
            result["manifest_digest"] = verified["manifest_digest"]
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
        return 1 if result.get("status") == "FAIL" else 0
    except (UQLError, OSError, UnicodeError, RecursionError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}), file=sys.stderr)
        return 1
