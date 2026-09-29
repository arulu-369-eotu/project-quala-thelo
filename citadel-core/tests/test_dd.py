import pytest

pytest.importorskip("qiskit")

from qiskit import QuantumCircuit
from uql_compiler.dd import CoherenceModel, apply_dynamical_decoupling, uhrig_spacings


def test_udd_spacings_normalize():
    spacing = uhrig_spacings(2)
    assert len(spacing) == 3
    assert sum(spacing) == pytest.approx(1.0)


def test_dd_inserts_timed_sequence():
    qc = QuantumCircuit(1)
    qc.h(0)
    qc.delay(2000, 0, unit="dt")
    qc.h(0)
    out = apply_dynamical_decoupling(qc, CoherenceModel(100.0, 80.0))
    assert out.count_ops().get("x", 0) >= 2
