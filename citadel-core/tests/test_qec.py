import pytest

pytest.importorskip("cirq")

from uql_compiler.qec import SurfaceCode


def test_surface_code_has_logical_boundaries_and_syndrome_rounds():
    code = SurfaceCode(3)
    assert len(code.logical_x()) == 3
    assert len(code.logical_z()) == 3
    circuit = code.build_circuit(rounds=2)
    assert len(circuit) > 0
    assert any("r1" in str(op) for op in circuit.all_operations())
