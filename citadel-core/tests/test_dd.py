import pytest

pytest.importorskip("qiskit")

from qiskit import QuantumCircuit
from uql_compiler.dd import CoherenceModel, apply_dynamical_decoupling


def test_dd_inserts_x_sequence():
    qc = QuantumCircuit(1)
    qc.h(0)
    qc.delay(2000, 0, unit="dt")
    qc.h(0)
    out = apply_dynamical_decoupling(qc, CoherenceModel(100.0, 80.0))
    assert out.count_ops().get("x", 0) >= 2
