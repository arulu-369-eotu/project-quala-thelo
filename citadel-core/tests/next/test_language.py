from fractions import Fraction
from pathlib import Path
import random
import subprocess
import sys

import pytest

from uql_compiler.next.model import (Operation, Program, UQLError, canonical_bytes,
                                     strict_json)
from uql_compiler.next.parser import parse
from uql_compiler.next.passes import enforce_contract, optimize, resources
from uql_compiler.next.evidence import validate_receipts
from uql_compiler.next.simulate import probabilities, statevector

ROOT = Path(__file__).resolve().parents[2]


def source(body="h q[0];", qubits=1, bits=1, contract=""):
    measurements = " ".join(f"measure q[{b}] -> c[{b}];" for b in range(bits))
    return f"uql 0.2; program Test {{ qubits {qubits}; bits {bits}; {contract} {body} {measurements} }}"


@pytest.mark.parametrize("angle,value", [("pi", Fraction(1)), ("-pi/4", Fraction(-1, 4)),
    ("6*pi/8", Fraction(3, 4)), ("+2*pi", Fraction(2)), ("0", Fraction(0)),
    ("-0*pi/2", Fraction(0))])
def test_exact_phases(angle, value):
    assert parse(source(f"rz({angle}) q[0];")).operations[0].phase == value


@pytest.mark.parametrize("change", [
    lambda s: s.replace("0.2", "0.3"),
    lambda s: s + "garbage",
    lambda s: s.replace("h q[0];", "reset q[0];"),
    lambda s: s.replace("h q[0];", "h q[1];"),
    lambda s: s.replace("h q[0];", "cx q[0], q[0];"),
    lambda s: s.replace("h q[0];", "rz(1/2) q[0];"),
    lambda s: s.replace("h q[0];", "rz(pi/0) q[0];"),
    lambda s: s.replace("h q[0];", "rz(pi/1000000000001) q[0];"),
    lambda s: s.replace("h q[0];", "include evil;"),
    lambda s: s.replace("h q[0];", "h q[0]; @"),
    lambda s: s.replace("h q[0];", "h q[-1];"),
    lambda s: s.replace("qubits 1", "qubits 0"),
    lambda s: s.replace("bits 1", "bits 2"),
    lambda s: s.replace("bits 1", "bits 0"),
    lambda s: s.replace("measure q[0] -> c[0];", ""),
    lambda s: s.replace("measure q[0] -> c[0];", "measure q[0] -> c[0]; h q[0];"),
    lambda s: s.replace("measure q[0] -> c[0];", "measure q[0] -> c[0]; measure q[0] -> c[0];"),
    lambda s: s.replace("measure q[0] -> c[0];", "measure q[0] -> c[1];"),
    lambda s: s.replace("h q[0];", "parallel { h q[0]; }"),
    lambda s: s.replace("h q[0];", "__import__('os');"),
])
def test_reject_unsupported_and_malformed_source(change):
    with pytest.raises(UQLError):
        parse(change(source()))


def test_digest_domains_and_policies():
    original = parse(source())
    formatted = parse("// comment\n" + source().replace(" ", "\n"))
    renamed = parse(source().replace("Test", "Other"))
    policy = parse(source(contract="require depth <= 8;"))
    assert original.ir_digest == formatted.ir_digest
    assert original.circuit_digest == renamed.circuit_digest == policy.circuit_digest
    assert original.ir_digest != renamed.ir_digest != policy.ir_digest
    assert original.ir_digest != original.circuit_digest
    assert Program.from_dict(strict_json(canonical_bytes(original.to_dict()))) == original


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(extra=True), lambda d: d.update(qubits=True),
    lambda d: d.update(bits=0), lambda d: d.update(schema="uql.ir/9"),
    lambda d: d["operations"][0].update(gate="evil"),
    lambda d: d["operations"][0].update(qubits=[True]),
    lambda d: d["operations"][0].update(phase={"numerator": 1, "denominator": 2}),
    lambda d: d["requirements"].update(fidelity=1),
    lambda d: d.update(trust=["unknown"]),
])
def test_ir_validation(mutation):
    d = parse(source()).to_dict()
    mutation(d)
    with pytest.raises(UQLError):
        Program.from_dict(d)


def test_nonreduced_phase_rejected():
    d = parse(source("rz(pi/2) q[0];")).to_dict()
    d["operations"][0]["phase"] = {"numerator": 2, "denominator": 4}
    with pytest.raises(UQLError):
        Program.from_dict(d)


def test_json_ambiguity_rejected():
    for raw in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}']:
        with pytest.raises(UQLError):
            strict_json(raw)
    with pytest.raises(UQLError):
        canonical_bytes({"float": 0.5})


def test_resources_and_failed_contracts():
    p = parse(source("h q[0]; h q[1]; cx q[0], q[1];", 2, 2))
    assert resources(p)["depth"] == 3
    assert resources(p)["gates"] == 3
    assert resources(p)["two_qubit_gates"] == 1
    for contract in ("require depth <= 0;", "trust signed_compiler;", "trust attested_backend;",
                     "trust independent_verifier;"):
        with pytest.raises(UQLError):
            enforce_contract(parse(source(contract=contract)))
    for contract in ("require gates <= 2; require gates <= 4;", "trust reproducible; trust reproducible;"):
        with pytest.raises(UQLError):
            parse(source(contract=contract))


def test_receipts_replayed_and_mutations_rejected():
    p = parse(source("h q[0]; rz(0) q[0]; h q[0]; rz(pi/4) q[0]; rz(-pi/4) q[0];"))
    out, receipt = optimize(p)
    assert len(out.operations) == 1
    validate_receipts(p, out, receipt)
    receipt[0]["changes"][0]["rule"] = "untrusted-rule"
    with pytest.raises(UQLError):
        validate_receipts(p, out, receipt)


def test_global_phase_is_preserved():
    p = parse(source("rz(pi) q[0]; rz(pi) q[0];"))
    out, _ = optimize(p)
    assert out.operations[0].phase == 2
    assert statevector(out)[0] == pytest.approx(-1)


@pytest.mark.parametrize("seed", range(12))
def test_optimizer_preserves_all_basis_amplitudes_small_circuits(seed):
    rng = random.Random(seed)
    ops = []
    for _ in range(20):
        gate = rng.choice(["h", "x", "y", "z", "s", "t", "rz", "cx", "cz"])
        qs = tuple(rng.sample(range(3), 2 if gate in ("cx", "cz") else 1))
        op = Operation(gate, qs, Fraction(rng.randrange(-4, 5), 4) if gate == "rz" else None)
        ops.append(op)
        if gate in ("h", "x", "y", "z", "cx", "cz"):
            ops.append(op)
    measure = tuple(Operation("measure", (i,), bit=i) for i in range(3))
    p = Program("Random", 3, 3, tuple(ops) + measure)
    out, receipts = optimize(p)
    validate_receipts(p, out, receipts)
    for basis in range(8):
        prep = [Operation("x", (i,)) for i in range(3) if (basis >> i) & 1]
        a = statevector(p.with_operations(prep + list(p.operations)))
        b = statevector(out.with_operations(prep + list(out.operations)))
        assert a == pytest.approx(b, abs=1e-12)


def test_asymmetric_measurement_order():
    p = parse("uql 0.2; program Order { qubits 3; bits 2; x q[0]; "
              "measure q[0] -> c[1]; measure q[2] -> c[0]; }")
    assert probabilities(p)["10"] == pytest.approx(1)


def test_core_runs_without_site_packages():
    script = "from uql_compiler.next.parser import parse; print(parse(" + repr(source()) + ").qubits)"
    result = subprocess.run([sys.executable, "-S", "-c", script], cwd=ROOT,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "1"


def test_conformance_corpus():
    for p in (ROOT / "conformance" / "valid").glob("*.uql"):
        parse(p.read_text())
    for p in (ROOT / "conformance" / "invalid").glob("*.uql"):
        with pytest.raises(UQLError):
            parse(p.read_text())
