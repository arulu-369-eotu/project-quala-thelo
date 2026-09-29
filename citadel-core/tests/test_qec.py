import pytest

pytest.importorskip("cirq")

from uql_compiler.qec import SurfaceCode


def test_surface_code_is_single_logical_qubit():
    code = SurfaceCode(3)
    code.validate()
    assert code.parameters == (9, 1, 3)
    assert len(code.x_checks) == 4
    assert len(code.z_checks) == 4
    assert sorted(check.weight for check in code.stabilizers) == [2, 2, 2, 2, 4, 4, 4, 4]


def test_surface_code_extracts_repeated_syndromes():
    code = SurfaceCode(3)
    circuit = code.build_circuit(rounds=3)
    keys = code.syndrome_keys(3)
    assert len(keys) == 24
    assert all(key in str(circuit) for key in keys)
