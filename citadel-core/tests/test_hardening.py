import copy
import ctypes
import hashlib
from itertools import combinations
import math
import os
from pathlib import Path

import cirq
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from qiskit import QuantumCircuit
from qiskit.quantum_info import Operator

from uql_compiler import native_crypto as n
from uql_compiler.crypto import HybridCiphertext, HybridKeyExchange, HybridRecipient
from uql_compiler.dd import CoherenceModel, DDConfig, apply_dynamical_decoupling
from uql_compiler.memory import LockedBuffer
from uql_compiler.qec import SurfaceCode


def test_full_transcript_is_bounded_and_matches_independent_definition():
    bundle, ciphertext, context = b"a" * 1600, b"b" * 1600, b"c" * 4096
    framed = b"".join(len(x).to_bytes(8, "big") + x for x in (bundle, ciphertext, context))
    expected = n.KDF_DOMAIN + hashlib.sha512(n.KDF_DOMAIN + b"transcript\x00" + framed).digest()
    assert n.transcript_info(bundle, ciphertext, context) == expected
    assert len(expected) < 1024
    for b, c, x in ((b"z" + bundle[1:], ciphertext, context), (bundle, b"z" + ciphertext[1:], context), (bundle, ciphertext, context[:-1])):
        assert n.transcript_info(b, c, x) != expected


def test_native_hkdf_matches_independent_sha512_implementation():
    # Public synthetic fixtures; these are not production secrets.
    x, k, info = bytes(range(32)), bytes(range(32, 64)), b"public-test-info"
    expected = HKDF(algorithm=hashes.SHA512(), length=64, salt=None, info=info).derive(x + k)
    with n.NativeSecret.allocate(32) as xs, n.NativeSecret.allocate(32) as ks, n.NativeSecret.allocate() as ref:
        ctypes.memmove(xs.pointer, x, 32)
        ctypes.memmove(ks.pointer, k, 32)
        ctypes.memmove(ref.pointer, expected, 64)
        with n._hkdf(xs, ks, info) as result:
            assert result.same_as(ref)


def test_maximum_context_key_agreement_and_ciphertext_tamper():
    with HybridRecipient.generate() as r:
        ct, a = HybridKeyExchange.encapsulate_bundle(r.public_bundle(), context=b"x" * 4096)
        with a, r.decapsulate(ct, context=b"x" * 4096) as b:
            assert a.same_as(b)
            mutated = HybridCiphertext(ct.data[:-1] + bytes([ct.data[-1] ^ 1]))
            with r.decapsulate(mutated, context=b"x" * 4096) as bad:
                assert not a.same_as(bad)  # ML-KEM implicit rejection is not an authentication error.


@pytest.mark.parametrize("context", [b"x" * 4097, "text", bytearray(b"a"), None])
def test_bad_context_rejected_before_native_calls(context):
    with pytest.raises(ValueError):
        n.encapsulate(b"a" * 1600, context)


@pytest.mark.parametrize("data", [b"", b"a" * 1599, b"a" * 1601, bytearray(1600), 1600])
def test_ciphertext_strict_type_and_length(data):
    with pytest.raises(ValueError):
        HybridCiphertext.parse(data)


def test_low_order_x25519_key_rejected():
    with HybridRecipient.generate() as r:
        with pytest.raises(RuntimeError, match="X25519"):
            n.encapsulate(b"\x00" * 32 + r.mlkem_public_bytes)


def test_closed_and_copied_native_handles_are_safe():
    s, k = n.NativeSecret.allocate(), n.NativeKeyPair.generate()
    for obj in (s, k):
        with pytest.raises(TypeError):
            copy.copy(obj)
        with pytest.raises(TypeError):
            copy.deepcopy(obj)
        obj.close()
        obj.close()
    assert not s.same_as(s)
    with pytest.raises(RuntimeError, match="closed"):
        _ = s.pointer
    with pytest.raises(RuntimeError, match="closed"):
        k.public_bundle()
    with pytest.raises(RuntimeError, match="closed"):
        n.decapsulate(k, b"a" * 1600)
    with pytest.raises(TypeError):
        n.NativeSecret(123)
    with pytest.raises(TypeError):
        n.NativeKeyPair(123, 456)


def test_faulted_hkdf_closes_all_owned_working_pages(monkeypatch):
    with n.NativeSecret.allocate(32) as x, n.NativeSecret.allocate(32) as k:
        created = []
        original = n.NativeSecret.allocate
        def allocate(size=64):
            result = original(size)
            created.append(result)
            return result
        monkeypatch.setattr(n.NativeSecret, "allocate", allocate)
        monkeypatch.setattr(n, "KD", lambda *_: 0)
        with pytest.raises(RuntimeError, match="HKDF derive"):
            n._hkdf(x, k, b"fixture")
        assert len(created) == 2 and all(s._closed for s in created)


@pytest.mark.parametrize("stage", ["mlock", "madvise"])
def test_kernel_lock_failure_rejects_allocation(monkeypatch, stage):
    monkeypatch.setattr(n.C, stage, lambda *_: -1)
    with pytest.raises(RuntimeError):
        n.NativeSecret.allocate()


def test_close_cleanses_before_unmapping(monkeypatch):
    s = n.NativeSecret.allocate()
    ctypes.memmove(s.pointer, b"public-fixture", 14)
    original = n.CLEANSE
    checked = []
    def cleanse(p, size):
        original(p, size)
        checked.append(ctypes.string_at(p, size) == b"\x00" * size)
    monkeypatch.setattr(n, "CLEANSE", cleanse)
    s.close()
    assert checked == [True]


def test_owned_secret_page_is_not_inherited_by_fork():
    with n.NativeSecret.allocate() as secret:
        address = secret.pointer
        child = os.fork()
        if child == 0:
            try:
                present = any(int(line.split()[0].split('-')[0],16) <= address < int(line.split()[0].split('-')[1],16)
                              for line in Path('/proc/self/maps').read_text().splitlines())
                try:
                    _ = secret.pointer
                except RuntimeError:
                    rejected = True
                else:
                    rejected = False
                os._exit(0 if rejected and not present else 1)
            except BaseException:
                os._exit(2)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0


def test_locked_buffer_cannot_be_repopulated_after_close():
    buf = LockedBuffer(b"fixture")
    buf.close()
    with pytest.raises(ValueError, match="closed"):
        buf.write(b"rewrite")
    with pytest.raises(ValueError, match="closed"):
        buf.view()


def gf2_rank(rows):
    basis = {}
    for row in rows:
        while row:
            pivot = row.bit_length() - 1
            if pivot in basis:
                row ^= basis[pivot]
            else:
                basis[pivot] = row
                break
    return len(basis)


@pytest.mark.parametrize("distance", [3, 5, 7, 9])
def test_surface_code_rank_and_logical_commutation(distance):
    code = SurfaceCode(distance)
    code.validate()
    masks = [sum(1 << (r * distance + c) for r, c in s.data) for s in code.stabilizers]
    assert gf2_rank(masks[:len(code.x_checks)]) + gf2_rank(masks[len(code.x_checks):]) == distance**2 - 1


def test_distance_three_has_no_weight_one_or_two_pure_logical_errors():
    code = SurfaceCode(3)
    for checks, opposite in ((code.x_checks, code.z_checks), (code.z_checks, code.x_checks)):
        rows = [sum(1 << (3*r+c) for r, c in s.data) for s in checks]
        other = [sum(1 << (3*r+c) for r, c in s.data) for s in opposite]
        span = {0}
        for row in rows:
            span |= {x ^ row for x in tuple(span)}
        for weight in (1, 2):
            for bits in combinations(range(9), weight):
                error = sum(1 << x for x in bits)
                if all((error & x).bit_count() % 2 == 0 for x in other):
                    assert error in span


def test_repeated_syndrome_is_stable_and_detects_data_error():
    code = SurfaceCode(3)
    circuit = code.build_circuit(rounds=2)
    measurements = cirq.CliffordSimulator(seed=369).run(circuit, repetitions=8).measurements
    for i, check in enumerate(code.stabilizers):
        assert (measurements[f"{check.kind}_{i}_r0"] == measurements[f"{check.kind}_{i}_r1"]).all()
    first = code.build_circuit()
    second = cirq.Circuit()
    for op in first.all_operations():
        if cirq.is_measurement(op):
            op = cirq.with_measurement_key_mapping(op, {cirq.measurement_key_name(op): cirq.measurement_key_name(op).replace("r0", "r1")})
        second.append(op)
    errored = first + cirq.Circuit(cirq.X(cirq.GridQubit(1, 1))) + second
    m = cirq.CliffordSimulator(seed=369).run(errored, repetitions=8).measurements
    for i, check in enumerate(code.stabilizers):
        delta = m[f"{check.kind}_{i}_r0"] ^ m[f"{check.kind}_{i}_r1"]
        expected = int(check.kind == "Z" and (1, 1) in check.data)
        assert (delta == expected).all()


@pytest.mark.parametrize("bad", [True, 2, 4, 33, 3.0])
def test_surface_distance_strict_and_bounded(bad):
    with pytest.raises(ValueError):
        SurfaceCode(bad)


def test_dd_preserves_ideal_unitary_and_short_window_budget():
    for idle, expected in ((2000, 2), (400, 0)):
        qc = QuantumCircuit(1)
        qc.h(0); qc.delay(idle, 0, unit="dt"); qc.h(0)
        out = apply_dynamical_decoupling(qc, CoherenceModel(100, 80))
        assert out.count_ops().get("x", 0) == expected
        assert Operator(out).equiv(Operator(qc))


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf, True, 0, -1])
def test_dd_rejects_nonfinite_or_invalid_times(bad):
    with pytest.raises(ValueError):
        CoherenceModel(bad, 80)
    with pytest.raises(ValueError):
        DDConfig(dt_ns=bad)
