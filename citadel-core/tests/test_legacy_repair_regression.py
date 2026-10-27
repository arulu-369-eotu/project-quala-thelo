"""Behavioral regressions for the PR #2 / UQL NEXT repair reconciliation."""
import ctypes
import hashlib

import numpy as np
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from qiskit import QuantumCircuit
from qiskit.quantum_info import Operator
from qiskit.transpiler import InstructionDurations

from uql_compiler import native_crypto as native
from uql_compiler.crypto import HybridKeyExchange, HybridRecipient, HybridCiphertext
from uql_compiler.dd import CoherenceModel, DDConfig, apply_dynamical_decoupling
from uql_compiler.qec import SurfaceCode


def test_mlkem_failure_frees_x25519(monkeypatch):
    freed = []
    monkeypatch.setattr(native, 'Q', lambda *args: 123)
    monkeypatch.setattr(native, 'PF', freed.append)
    def unavailable():
        raise RuntimeError('ML-KEM unavailable')
    monkeypatch.setattr(native, '_new_mlkem_key', unavailable)
    with pytest.raises(RuntimeError, match='ML-KEM unavailable'):
        native.NativeKeyPair.generate()
    assert freed == [123]


def test_transcript_v2_matches_independent_hkdf_and_wipes_on_failure(monkeypatch):
    # Synthetic known-answer material only; no live secret is exported.
    x = ctypes.create_string_buffer(bytes(range(32)), 32)
    k = ctypes.create_string_buffer(bytes(range(32, 64)), 32)
    transcript = b'public-transcript' * 200
    info = b'UQL-HYBRID-X25519-MLKEM1024-v2\x00' + hashlib.sha512(
        b'UQL-HYBRID-TRANSCRIPT-v2\x00' + len(transcript).to_bytes(4, 'big') + transcript
    ).digest()
    expected = HKDF(algorithm=hashes.SHA512(), length=64, salt=None, info=info).derive(bytes(range(64)))
    with native._hkdf(x, k, transcript) as secret:
        assert ctypes.string_at(secret.pointer, 64) == expected
    captured = []
    def failing_kdf(ctx, output, size, params):
        captured.append(params[2].data)
        return 0
    monkeypatch.setattr(native, 'KD', failing_kdf)
    # Inspect the wipe while the ctypes buffer is still alive in _hkdf's finally.
    real_memset = native.C.memset
    wiped = []
    def observe_memset(ptr, value, size):
        result = real_memset(ptr, value, size)
        if captured and ptr is not None:
            address = ctypes.cast(ptr, ctypes.c_void_p).value
            if address == captured[0] and size == 64:
                wiped.append(ctypes.string_at(ptr, size))
        return result
    monkeypatch.setattr(native.C, 'memset', observe_memset)
    with pytest.raises(RuntimeError, match='HKDF'):
        native._hkdf(x, k, transcript)
    assert wiped == [b'\x00' * 64]


def test_hybrid_rejects_bad_context_and_ciphertext_changes_key():
    with native.NativeKeyPair.generate() as kp:
        recipient = HybridRecipient(kp)
        ct, sent = HybridKeyExchange.encapsulate_bundle(recipient.public_bundle())
        changed = bytearray(ct.serialize())
        changed[-1] ^= 1
        with sent, recipient.decapsulate(HybridCiphertext(bytes(changed))) as altered:
            assert not sent.same_as(altered)
        for context in (b'x' * 4097, 'not-bytes'):
            with pytest.raises(ValueError):
                recipient.decapsulate(ct, context=context)
        with pytest.raises(ValueError):
            HybridKeyExchange.encapsulate_bundle(b'x' * 1599)
        with pytest.raises(ValueError):
            HybridCiphertext.parse(b'x' * 1599)


@pytest.mark.parametrize('idle,ratio,x_duration,expected', [
    (399, 2.0, 100, 0), (400, 2.0, 100, 2),
    (799, 4.0, 100, 0), (800, 4.0, 100, 2),
    (100, 1.0, 100, 0),
])
def test_dd_respects_calibrated_idle_ratio_and_preserves_unitary(idle, ratio, x_duration, expected):
    qc = QuantumCircuit(1)
    qc.h(0)
    qc.delay(idle, 0, unit='dt')
    qc.h(0)
    durations = InstructionDurations([('h', None, 80), ('x', None, x_duration)], dt=1e-9)
    out = apply_dynamical_decoupling(qc, CoherenceModel(100, 80),
        config=DDConfig(min_idle_ratio=ratio), durations=durations)
    assert out.count_ops().get('x', 0) == expected
    assert np.allclose(Operator(out).data, Operator(qc).data)
    # h + idle + h must retain the complete scheduled duration.
    assert sum(int(item.operation.duration) if item.operation.name == 'delay'
               else durations.get(item.operation.name, 0, 'dt') for item in out.data) == idle + 160


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


@pytest.mark.parametrize('distance', [3, 5, 7, 9])
def test_surface_code_commutation_rank_and_logical_operators(distance):
    code = SurfaceCode(distance)
    code.validate()
    coords = set(code.data_coords)
    assert all(set(c.data) <= coords and len(set(c.data)) == c.weight for c in code.stabilizers)
    assert all(c.weight in (2, 4) for c in code.stabilizers)
    rows = []
    for check in code.stabilizers:
        offset = 0 if check.kind == 'X' else distance ** 2
        rows.append(sum(1 << (r * distance + c + offset) for r, c in check.data))
    assert gf2_rank(rows) == distance ** 2 - 1
    lx, lz = set(code.logical_x()), set(code.logical_z())
    assert len(lx & lz) % 2 == 1
    assert all(len(lx & set(c.data)) % 2 == 0 for c in code.z_checks)
    assert all(len(lz & set(c.data)) % 2 == 0 for c in code.x_checks)
    # Logical strings are outside the stabilizer group.
    for logical, offset in ((lx, 0), (lz, distance ** 2)):
        row = sum(1 << (r * distance + c + offset) for r, c in logical)
        assert gf2_rank(rows + [row]) == distance ** 2
