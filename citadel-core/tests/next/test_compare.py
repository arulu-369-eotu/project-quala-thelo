import pytest

from uql_compiler.next.compare import compare
from uql_compiler.next.model import UQLError
from uql_compiler.next.parser import parse


def program(body):
    return parse(f"uql 0.2; program Compare {{ qubits 1; bits 1; {body} measure q[0] -> c[0]; }}")


def test_relation_changes_verdict_and_phase_witness():
    left, right = program(""), program("rz(2*pi) q[0];")
    assert compare(left, right, relation="zero_input_distribution")["status"] == "PASS"
    report = compare(left, right)
    assert report["status"] == "FAIL"
    assert report["witness"]["kind"] == "matrix_entry_discrepancy"
    assert report["maximum_entry_error"] == pytest.approx(2)


def test_probability_witness_and_unitary_check():
    left, right = program(""), program("x q[0];")
    report = compare(left, right, relation="zero_input_distribution")
    assert report["status"] == "FAIL"
    assert report["witness"]["kind"] == "output_probability_discrepancy"
    assert compare(left, program("h q[0]; h q[0];"))["status"] == "PASS"


def test_bad_relation_rejected():
    with pytest.raises(UQLError):
        compare(program(""), program(""), relation="universal_equivalence")
