"""Validated, immutable AST/IR and versioned canonical identities.

The canonical encoding is a restricted UQL JSON encoding, not RFC 8785.
Circuit identity is deliberately narrower than general semantic equivalence.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from fractions import Fraction
import hashlib
import json
import re

MAX_SOURCE_BYTES = 1_000_000
MAX_OPERATIONS = 10_000
MAX_REGISTERS = 4096
MAX_PHASE_INTEGER = 10**12
GATE_ARITY = {"h": 1, "x": 1, "y": 1, "z": 1, "s": 1, "t": 1,
              "rz": 1, "cx": 2, "cz": 2, "measure": 1}
RESOURCE_KEYS = {"qubits", "gates", "depth", "two_qubit_gates"}
TRUST_KEYS = {"reproducible", "signed_compiler", "attested_backend", "independent_verifier"}


class UQLError(ValueError):
    """Invalid, unsupported, or unverifiable UQL input."""


def integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise UQLError(f"{label} must be an integer in [{low}, {high}]")
    return value


def canonical_bytes(value) -> bytes:
    """ASCII keys, integers/strings/bools/null, no floats, one trailing LF."""
    def check(v):
        if v is None or type(v) in (str, bool, int):
            return
        if isinstance(v, list):
            for item in v:
                check(item)
            return
        if isinstance(v, dict) and all(type(k) is str and k.isascii() for k in v):
            for item in v.values():
                check(item)
            return
        raise UQLError("noncanonical JSON type or key")
    check(value)
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def digest(value, domain="uql.ir/0.2") -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + canonical_bytes(value)).hexdigest()


def strict_json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise UQLError(f"duplicate JSON key: {key}")
            out[key] = value
        return out
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(UQLError("nonfinite JSON")))
    except (ValueError, TypeError, RecursionError) as exc:
        raise UQLError(f"invalid JSON: {exc}") from exc


def exact_keys(value, keys, label):
    if type(value) is not dict or set(value) != set(keys):
        raise UQLError(f"invalid {label} fields")


@dataclass(frozen=True)
class Operation:
    gate: str
    qubits: tuple[int, ...]
    phase: Fraction | None = None  # exact radians = phase * pi
    bit: int | None = None

    def __post_init__(self):
        if type(self.gate) is not str or self.gate not in GATE_ARITY:
            raise UQLError("unsupported gate")
        if type(self.qubits) is not tuple or len(self.qubits) != GATE_ARITY[self.gate]:
            raise UQLError("invalid gate arity")
        for q in self.qubits:
            integer(q, 0, MAX_REGISTERS - 1, "qubit index")
        if len(set(self.qubits)) != len(self.qubits):
            raise UQLError("gate operands must be distinct")
        if self.gate == "rz":
            if type(self.phase) is not Fraction:
                raise UQLError("rz requires an exact rational multiple of pi")
            integer(self.phase.numerator, -MAX_PHASE_INTEGER, MAX_PHASE_INTEGER, "phase numerator")
            integer(self.phase.denominator, 1, MAX_PHASE_INTEGER, "phase denominator")
        elif self.phase is not None:
            raise UQLError("unexpected gate phase")
        if self.gate == "measure":
            integer(self.bit, 0, MAX_REGISTERS - 1, "classical index")
        elif self.bit is not None:
            raise UQLError("only measurements can write a bit")

    def to_dict(self):
        out = {"gate": self.gate, "qubits": list(self.qubits)}
        if self.phase is not None:
            out["phase"] = {"numerator": self.phase.numerator, "denominator": self.phase.denominator}
        if self.bit is not None:
            out["bit"] = self.bit
        return out

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict:
            raise UQLError("operation must be an object")
        gate = value.get("gate")
        if type(gate) is not str or gate not in GATE_ARITY:
            raise UQLError("unsupported gate")
        exact_keys(value, {"gate", "qubits"} | ({"phase"} if gate == "rz" else set()) |
                   ({"bit"} if gate == "measure" else set()), "operation")
        if type(value["qubits"]) is not list:
            raise UQLError("qubits must be an array")
        phase = None
        if gate == "rz":
            p = value["phase"]
            exact_keys(p, {"numerator", "denominator"}, "phase")
            n = integer(p["numerator"], -MAX_PHASE_INTEGER, MAX_PHASE_INTEGER, "phase numerator")
            d = integer(p["denominator"], 1, MAX_PHASE_INTEGER, "phase denominator")
            phase = Fraction(n, d)
            if (phase.numerator, phase.denominator) != (n, d):
                raise UQLError("IR phase must be reduced")
        return cls(gate, tuple(value["qubits"]), phase, value.get("bit"))


@dataclass(frozen=True)
class Program:
    name: str
    qubits: int
    bits: int
    operations: tuple[Operation, ...]
    requirements: tuple[tuple[str, int], ...] = ()
    trust: tuple[str, ...] = ()

    def __post_init__(self):
        if type(self.name) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", self.name):
            raise UQLError("invalid program name")
        integer(self.qubits, 1, MAX_REGISTERS, "qubit count")
        integer(self.bits, 1, self.qubits, "bit count")
        if type(self.operations) is not tuple or not 1 <= len(self.operations) <= MAX_OPERATIONS:
            raise UQLError("invalid operation count")
        measured, written = set(), set()
        terminal = False
        for op in self.operations:
            if type(op) is not Operation:
                raise UQLError("invalid operation object")
            if any(q >= self.qubits for q in op.qubits):
                raise UQLError("qubit index out of bounds")
            if op.gate == "measure":
                terminal = True
                if op.qubits[0] in measured or op.bit in written or op.bit >= self.bits:
                    raise UQLError("duplicate or out-of-bounds measurement")
                measured.add(op.qubits[0])
                written.add(op.bit)
            elif terminal:
                raise UQLError("all measurements must be terminal")
        if written != set(range(self.bits)):
            raise UQLError("every classical bit must be measured exactly once")
        if type(self.requirements) is not tuple:
            raise UQLError("invalid resource requirements")
        seen = set()
        for item in self.requirements:
            if type(item) is not tuple or len(item) != 2:
                raise UQLError("invalid requirement")
            key, value = item
            if key not in RESOURCE_KEYS or key in seen:
                raise UQLError("unsupported or duplicate resource requirement")
            integer(value, 0, MAX_OPERATIONS * 2, "resource limit")
            seen.add(key)
        if type(self.trust) is not tuple or any(type(t) is not str or t not in TRUST_KEYS for t in self.trust):
            raise UQLError("invalid trust requirement")
        if len(set(self.trust)) != len(self.trust):
            raise UQLError("duplicate trust requirement")

    def to_dict(self):
        return {"schema": "uql.ir/0.2", "name": self.name, "qubits": self.qubits,
                "bits": self.bits, "operations": [o.to_dict() for o in self.operations],
                "requirements": dict(self.requirements), "trust": sorted(self.trust)}

    @classmethod
    def from_dict(cls, value):
        exact_keys(value, {"schema", "name", "qubits", "bits", "operations", "requirements", "trust"}, "IR")
        if value["schema"] != "uql.ir/0.2":
            raise UQLError("unsupported IR version")
        if type(value["operations"]) is not list or len(value["operations"]) > MAX_OPERATIONS:
            raise UQLError("invalid operation array")
        if type(value["requirements"]) is not dict or type(value["trust"]) is not list:
            raise UQLError("invalid contract")
        return cls(value["name"], value["qubits"], value["bits"],
                   tuple(Operation.from_dict(o) for o in value["operations"]),
                   tuple(sorted(value["requirements"].items())), tuple(value["trust"]))

    def with_operations(self, ops):
        return replace(self, operations=tuple(ops))

    @property
    def ir_digest(self):
        return digest(self.to_dict())

    @property
    def circuit_digest(self):
        return digest({"qubits": self.qubits, "bits": self.bits,
                       "operations": [o.to_dict() for o in self.operations]}, "uql.circuit/0.2")
