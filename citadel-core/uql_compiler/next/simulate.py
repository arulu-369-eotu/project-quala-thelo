"""Bounded ideal simulation and optional numerical comparisons.

Output strings are c[bits-1]...c[0]. State indices use q[0] as the low bit.
Only zero-initialized programs in the 0.2 subset are supported. These tests do
not establish equivalence for arbitrary inputs, noise, channels, or hardware.
"""
import cmath
import importlib.metadata
import math

from .model import UQLError, integer

MAX_SIM_QUBITS = 10
MAX_SIM_WORK = 2_000_000


def check_size(program):
    if program.qubits > MAX_SIM_QUBITS or (1 << program.qubits) * len(program.operations) > MAX_SIM_WORK:
        raise UQLError("simulation work limit exceeded")


def statevector(program, *, basis=0):
    check_size(program)
    state = [0j] * (1 << program.qubits)
    integer(basis, 0, len(state) - 1, "initial basis state")
    state[basis] = 1 + 0j
    for op in program.operations:
        if op.gate == "measure":
            continue
        q = op.qubits[0]
        if op.gate in ("cx", "cz"):
            control, target = op.qubits
            for i in range(len(state)):
                if not (i >> control) & 1:
                    continue
                if op.gate == "cx" and not (i >> target) & 1:
                    j = i | (1 << target)
                    state[i], state[j] = state[j], state[i]
                elif op.gate == "cz" and (i >> target) & 1:
                    state[i] *= -1
            continue
        if op.gate == "h":
            scale = 1 / math.sqrt(2)
            matrix = ((scale, scale), (scale, -scale))
        elif op.gate == "x":
            matrix = ((0, 1), (1, 0))
        elif op.gate == "y":
            matrix = ((0, -1j), (1j, 0))
        elif op.gate == "z":
            matrix = ((1, 0), (0, -1))
        elif op.gate in ("s", "t"):
            matrix = ((1, 0), (0, cmath.exp(1j * math.pi / (2 if op.gate == "s" else 4))))
        elif op.gate == "rz":
            theta = float(op.phase) * math.pi
            matrix = ((cmath.exp(-0.5j * theta), 0), (0, cmath.exp(0.5j * theta)))
        else:
            raise UQLError("unsupported simulation gate")
        for i in range(len(state)):
            if not (i >> q) & 1:
                j = i | (1 << q)
                a, b = state[i], state[j]
                state[i] = matrix[0][0] * a + matrix[0][1] * b
                state[j] = matrix[1][0] * a + matrix[1][1] * b
    return state


def distribution(program, state):
    out = {format(i, f"0{program.bits}b"): 0.0 for i in range(1 << program.bits)}
    mapping = [(o.qubits[0], o.bit) for o in program.operations if o.gate == "measure"]
    for i, amplitude in enumerate(state):
        result = sum(((i >> q) & 1) << bit for q, bit in mapping)
        out[format(result, f"0{program.bits}b")] += float(abs(amplitude)**2)
    return out


def probabilities(program):
    return distribution(program, statevector(program))


def differential(program, qasm, backends=("qiskit", "cirq"), tolerance=1e-10):
    check_size(program)
    if not math.isfinite(tolerance) or not 0 < tolerance <= 1e-6:
        raise UQLError("tolerance must be finite and in (0, 1e-6]")
    if not backends or len(set(backends)) != len(backends) or set(backends) - {"qiskit", "cirq"}:
        raise UQLError("choose unique supported backends: qiskit, cirq")
    expected = probabilities(program)
    reports = []
    for backend in backends:
        try:
            if backend == "qiskit":
                from qiskit import qasm3
                from qiskit.quantum_info import Statevector
                circuit = qasm3.loads(qasm).remove_final_measurements(inplace=False)
                state = Statevector.from_instruction(circuit).data
                version = importlib.metadata.version("qiskit")
                input_kind = "emitted_openqasm3"
            else:
                import cirq
                qubits = cirq.LineQubit.range(program.qubits)
                circuit = cirq.Circuit()
                for op in program.operations:
                    if op.gate == "measure":
                        continue
                    qs = [qubits[i] for i in op.qubits]
                    gates = {"h": cirq.H, "x": cirq.X, "y": cirq.Y, "z": cirq.Z,
                             "s": cirq.S, "t": cirq.T, "cx": cirq.CNOT, "cz": cirq.CZ}
                    gate = cirq.rz(float(op.phase) * math.pi) if op.gate == "rz" else gates[op.gate]
                    circuit.append(gate(*qs))
                import numpy as np
                state = cirq.Simulator(dtype=np.complex128).simulate(
                    circuit, qubit_order=list(reversed(qubits))).final_state_vector
                version = importlib.metadata.version("cirq-core")
                input_kind = "validated_uql_ir"
        except ImportError as exc:
            raise UQLError(f"missing optional {backend} dependency: {exc}") from exc
        observed = distribution(program, state)
        distance = sum(abs(expected[k] - observed[k]) for k in expected) / 2
        reports.append({"backend": backend, "version": version, "input": input_kind,
                        "total_variation_distance": distance,
                        "status": "PASS" if distance <= tolerance else "FAIL"})
    return {"schema": "uql.differential/0.2", "circuit_digest": program.circuit_digest,
            "boundary": "ideal_zero_input_terminal_computational_basis_distribution",
            "tolerance": tolerance, "reference": expected, "backends": reports,
            "status": "PASS" if all(r["status"] == "PASS" for r in reports) else "FAIL",
            "independent_implementation_reproduction": "UNVERIFIED"}
