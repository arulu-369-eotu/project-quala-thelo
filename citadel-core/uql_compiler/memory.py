"""Best-effort OS-backed secret-memory protection.

Python objects can be copied by the interpreter, allocator, tracing tools, or
native extensions. Therefore this module deliberately reports capability
rather than promising absolute cold-boot protection. It locks the backing
bytearray where the operating system permits it and can exclude Linux pages
from core dumps.
Retained memoryviews remain writable; callers must release them before close.
"""

from __future__ import annotations

import ctypes
import mmap
import os
import platform
from dataclasses import dataclass


@dataclass(frozen=True)
class MemoryLockStatus:
    locked: bool
    dump_excluded: bool
    platform: str
    detail: str


class LockedBuffer:
    def __init__(self, initial: bytes | bytearray = b"", *, require_lock: bool = False):
        self._buf = bytearray(initial)
        self._closed = False
        self._locked = False
        self._dump_excluded = False
        self._status = self._lock()
        if require_lock and not self._status.locked:
            self.close()
            raise OSError(f"OS memory locking unavailable: {self._status.detail}")

    @property
    def status(self) -> MemoryLockStatus:
        return self._status

    def __len__(self) -> int:
        return len(self._buf)

    def __enter__(self) -> "LockedBuffer":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self):
        if hasattr(self, "_closed"):
            self.close()

    def view(self) -> memoryview:
        if self._closed:
            raise ValueError("secret buffer is closed")
        if not self._buf:
            raise ValueError("empty secret buffer has no writable address")
        return memoryview(self._buf)

    def write(self, data: bytes | bytearray) -> None:
        if self._closed:
            raise ValueError("secret buffer is closed")
        if len(data) != len(self._buf):
            raise ValueError("write must preserve buffer length")
        self._buf[:] = data

    def wipe(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0

    def close(self) -> None:
        if self._closed:
            return
        self.wipe()
        if self._locked and self._buf:
            _munlock(self._buf)
        self._locked = False
        self._closed = True
        self._status = MemoryLockStatus(
            locked=False,
            dump_excluded=self._dump_excluded,
            platform=platform.system(),
            detail="buffer wiped and unlocked",
        )

    def _lock(self) -> MemoryLockStatus:
        if not self._buf:
            return MemoryLockStatus(False, False, platform.system(), "empty buffer")
        try:
            _mlock(self._buf)
            self._locked = True
            self._dump_excluded = _exclude_from_dump(self._buf)
            return MemoryLockStatus(
                True,
                self._dump_excluded,
                platform.system(),
                "OS memory lock active",
            )
        except (OSError, AttributeError, NotImplementedError) as exc:
            return MemoryLockStatus(False, False, platform.system(), str(exc))


def _buffer_address(buf: bytearray) -> int:
    return ctypes.addressof(ctypes.c_char.from_buffer(buf))


def _mlock(buf: bytearray) -> None:
    address = _buffer_address(buf)
    length = len(buf)
    system = platform.system()
    if system == "Windows":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        if not kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(length)):
            raise OSError(ctypes.get_last_error(), "VirtualLock failed")
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(length)) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))


def _munlock(buf: bytearray) -> None:
    address = _buffer_address(buf)
    length = len(buf)
    system = platform.system()
    if system == "Windows":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.VirtualUnlock(ctypes.c_void_p(address), ctypes.c_size_t(length))
        return
    libc = ctypes.CDLL(None, use_errno=True)
    libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(length))


def _exclude_from_dump(buf: bytearray) -> bool:
    if platform.system() != "Linux":
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    madv_dontdump = 16
    page = mmap.PAGESIZE
    address = _buffer_address(buf)
    start = address - (address % page)
    end = address + len(buf)
    length = end - start
    result = libc.madvise(
        ctypes.c_void_p(start),
        ctypes.c_size_t(length),
        ctypes.c_int(madv_dontdump),
    )
    return result == 0
