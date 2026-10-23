from fractions import Fraction
from pathlib import Path
import random
import re

import pytest

from uql_compiler.next.emit import openqasm, qir
from uql_compiler.next.model import Operation, Program, UQLError
from uql_compiler.next.parser import parse
from uql_compiler.next.simulate import differential


def random_program(seed):
    rng = random.Random(seed)
    ops = []
    for _ in range(20):
        gate = rng.choice(["h", "x", "y", "z", "s", "t", "rz", "cx", "cz"])
        qs = tuple(rng.sample(range(3), 2 if gate in ("cx", "cz") else 1))
        ops.append(Operation(gate, qs, Fraction(rng.randrange(-3, 4), 4) if gate == "rz" else None))
    ops.extend([Operation("measure", (0,), bit=1), Operation("measure", (2,), bit=0)])
    return Program("Random", 3, 2, tuple(ops))


@pytest.mark.parametrize("seed", range(10))
def test_qasm_qiskit_and_cirq_numerical_agreement(seed):
    pytest.importorskip("qiskit")
    pytest.importorskip("qiskit_qasm3_import")
    pytest.importorskip("cirq")
    program = random_program(seed)
    assert differential(program, openqasm(program))["status"] == "PASS"


@pytest.mark.parametrize("seed", range(5))
def test_qir_llvm_validation(seed):
    llvm = pytest.importorskip("llvmlite.binding")
    llvm.parse_assembly(qir(random_program(seed))).verify()


def test_qir_runtime_phase_and_classical_mapping():
    runner = pytest.importorskip("qirrunner")
    program = parse("uql 0.2; program Runtime { qubits 3; bits 2; h q[0]; rz(pi) q[0]; "
                    "h q[0]; s q[0]; t q[0]; y q[2]; x q[2]; z q[2]; "
                    "cz q[0], q[2]; cx q[0], q[2]; x q[2]; "
                    "measure q[0] -> c[1]; measure q[2] -> c[0]; }")
    output = []
    runner.run_bytes(qir(program).encode(), shots=8, rng_seed=369, output_fn=output.append)
    raw = "".join(str(o) for o in output)
    results = re.findall(r"OUTPUT\tRESULT\t([01])", raw)
    assert results == ["1", "0"] * 8


def test_qir_bell_distribution():
    runner = pytest.importorskip("qirrunner")
    program = parse("uql 0.2; program Bell { qubits 2; bits 2; h q[0]; cx q[0], q[1]; "
                    "measure q[0] -> c[0]; measure q[1] -> c[1]; }")
    output = []
    runner.run_bytes(qir(program).encode(), shots=256, rng_seed=369, output_fn=output.append)
    results = re.findall(r"OUTPUT\tRESULT\t([01])", "".join(map(str, output)))
    shots = ["".join(results[i:i+2]) for i in range(0, len(results), 2)]
    assert len(shots) == 256
    assert set(shots) == {"00", "11"}
    assert 80 < shots.count("00") < 176


def test_differential_invalid_tolerance():
    program = random_program(0)
    for tolerance in (float("nan"), float("inf"), 0.0, -0.1):
        with pytest.raises(UQLError):
            differential(program, openqasm(program), tolerance=tolerance)
