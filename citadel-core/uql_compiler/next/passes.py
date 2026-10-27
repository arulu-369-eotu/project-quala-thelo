"""Two exact, local rewrite rules with replayable edit records."""
from collections import Counter
from fractions import Fraction

from .model import Operation, Program, UQLError
from . import VERSION

SELF_INVERSE = {"h", "x", "y", "z", "cx", "cz"}


def optimize(program: Program):
    out, changes = [], []
    for op in program.operations:
        if out and op.gate in SELF_INVERSE and out[-1] == op:
            previous = out.pop()
            changes.append({"rule": "self-inverse-adjacent/1", "offset": len(out),
                            "before": [previous.to_dict(), op.to_dict()], "after": []})
        elif out and op.gate == "rz" and out[-1].gate == "rz" and out[-1].qubits == op.qubits:
            previous = out[-1]
            phase = previous.phase + op.phase
            # A valid input must still compile if exact rational growth exceeds the IR bound.
            try:
                merged = Operation("rz", op.qubits, phase)
            except UQLError:
                out.append(op)
                continue
            out.pop()
            after = [] if phase == 0 else [merged]
            changes.append({"rule": "rz-add-adjacent/1", "offset": len(out),
                            "before": [previous.to_dict(), op.to_dict()],
                            "after": [o.to_dict() for o in after]})
            out.extend(after)
        elif op.gate == "rz" and op.phase == Fraction(0):
            changes.append({"rule": "rz-zero/1", "offset": len(out),
                            "before": [op.to_dict()], "after": []})
        else:
            out.append(op)
    result = program.with_operations(out)
    receipt = {"schema": "uql.transform/0.2", "pass": "local-exact-rewrites/1",
               "compiler": f"uql-next/{VERSION}", "input_digest": program.ir_digest,
               "output_digest": result.ir_digest, "changes": changes,
               "validation": "deterministic_local_rule_replay", "independent_verification": "UNVERIFIED"}
    return result, [receipt]


def resources(program):
    layers = [0] * program.qubits
    counts = Counter()
    for op in program.operations:
        layer = 1 + max(layers[q] for q in op.qubits)
        for q in op.qubits:
            layers[q] = layer
        counts[op.gate] += 1
    return {"schema": "uql.resources/0.2", "qubits": program.qubits, "bits": program.bits,
            "gates": sum(n for k, n in counts.items() if k != "measure"),
            "two_qubit_gates": sum(counts[k] for k in ("cx", "cz")),
            "measurements": counts["measure"], "depth": max(layers),
            "gate_counts": dict(sorted(counts.items())),
            "depth_model": "unit_duration_per_operation_including_measurements",
            "physical_qubits": None, "fidelity": None, "execution_time": None}


def enforce_contract(program):
    unsupported = set(program.trust) - {"reproducible"}
    if unsupported:
        raise UQLError("unavailable trust capability: " + ", ".join(sorted(unsupported)))
    report = resources(program)
    for key, limit in program.requirements:
        if report[key] > limit:
            raise UQLError(f"resource constraint failed: {key}={report[key]} > {limit}")
    return report
