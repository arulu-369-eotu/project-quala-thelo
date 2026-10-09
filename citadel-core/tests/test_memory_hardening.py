import pytest
from uql_compiler.memory import LockedBuffer

def test_mapped_memory_wipes_and_closes():
    secret = LockedBuffer(b"abcdef")
    v = secret.view()
    assert bytes(v) == b"abcdef"
    secret.wipe()
    assert bytes(v) == b"\x00" * 6
    v.release()
    secret.close()
    with pytest.raises(ValueError):
        secret.view()

def test_buffer_export_refuses_unsafe_close():
    secret = LockedBuffer(b"abcdef")
    view = secret.view()
    try:
        with pytest.raises(RuntimeError):
            secret.close()
        assert bytes(view) == b"\x00" * 6
    finally:
        view.release()
        secret.close()

def test_write_preserves_length_and_closed_write_rejected():
    secret = LockedBuffer(b"1234")
    try:
        secret.write(b"5678")
        assert bytes(secret.view()) == b"5678"
        with pytest.raises(ValueError):
            secret.write(b"abc")
    finally:
        secret.close()
    with pytest.raises(ValueError):
        secret.write(b"nope")
