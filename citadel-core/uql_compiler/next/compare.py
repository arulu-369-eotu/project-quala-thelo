"""Observation-scoped numerical comparison with explicit discrepancy records.

This is a small-circuit experiment, not a general quantum equivalence prover.
Unitary comparisons retain global phase. Such a discrepancy is a matrix
witness; it is not necessarily observable without a coherent control context.
"""
import math

from .model import UQLError
from .simulate import probabilities, statevector


def compare(left, right, *, relation="premeasurement_unitary", tolerance=1e-10):
    if relation not in {"premeasurement_unitary", "zero_input_distribution"}:
        raise UQLError("unsupported comparison relation")
    if not math.isfinite(tolerance) or not 0 < tolerance <= 1e-6:
        raise UQLError("invalid comparison tolerance")
    if left.qubits != right.qubits or left.bits != right.bits:
        raise UQLError("comparison register widths must match")
    if left.qubits > 4 or (1 << (2 * left.qubits)) * (len(left.operations) + len(right.operations)) > 2_000_000:
        raise UQLError("comparison work limit exceeded")
    result = {"schema": "uql.comparison/0.2", "relation": relation, "tolerance": tolerance,
              "left_ir_digest": left.ir_digest, "right_ir_digest": right.ir_digest,
              "method": "bounded_numerical_reference_simulation", "formal_proof": False,
              "independent_verification": "UNVERIFIED", "witness": None}
    if relation == "zero_input_distribution":
        a, b = probabilities(left), probabilities(right)
        distance = sum(abs(a[k] - b[k]) for k in a) / 2
        result.update(total_variation_distance=distance, status="PASS" if distance <= tolerance else "FAIL",
                      boundary="zero_input_terminal_measurements_with_classical_mapping")
        if distance > tolerance:
            key = max(a, key=lambda k: abs(a[k] - b[k]))
            result["witness"] = {"kind": "output_probability_discrepancy", "input": "0" * left.qubits,
                                 "output": key, "left_probability": a[key], "right_probability": b[key]}
        return result
    largest, witness = 0.0, None
    for basis in range(1 << left.qubits):
        a = statevector(left, basis=basis)
        b = statevector(right, basis=basis)
        for row, (x, y) in enumerate(zip(a, b)):
            difference = abs(x - y)
            if difference > largest:
                largest = difference
                witness = {"kind": "matrix_entry_discrepancy", "input_basis": basis, "output_basis": row,
                           "left_amplitude": [x.real, x.imag], "right_amplitude": [y.real, y.imag],
                           "coherent_control_may_be_required_to_observe_global_phase": True}
    result.update(maximum_entry_error=largest, status="PASS" if largest <= tolerance else "FAIL",
                  boundary="all_basis_premeasurement_amplitudes_global_phase_retained",
                  terminal_measurement_mapping="outside_this_relation")
    if largest > tolerance:
        result["witness"] = witness
    return result
