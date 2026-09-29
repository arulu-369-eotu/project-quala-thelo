from uql_compiler.memory import LockedBuffer


def test_wipe_and_length():
    with LockedBuffer(b"secret") as buf:
        assert len(buf) == 6
        buf.wipe()
        assert bytes(buf.view()) == b"\x00" * 6


def test_require_lock_reports_capability():
    buf = LockedBuffer(b"secret")
    try:
        assert isinstance(buf.status.locked, bool)
    finally:
        buf.close()
