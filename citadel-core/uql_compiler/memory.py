"""Page-isolated, best-effort process memory handling.

This protects a dedicated anonymous mmap instead of marking shared Python
allocator pages MADV_DONTDUMP. Original input bytes still exist in Python.
Use audited HSM/native key storage for production-grade key custody.
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
        if not isinstance(initial, (bytes, bytearray)):
            raise TypeError("initial must be bytes-like")
        self._size = len(initial)
        self._region = None
        self._closed = False
        self._locked = False
        self._dump_excluded = False
        self._address = 0
        if self._size:
            self._region = mmap.mmap(-1, self._size, access=mmap.ACCESS_WRITE)
            self._region[:self._size] = initial
            self._address = ctypes.addressof(ctypes.c_char.from_buffer(self._region))
        self._status = self._lock()
        if require_lock and (not self._status.locked or
                (platform.system() == "Linux" and not self._status.dump_excluded)):
            self.close()
            raise OSError("required process memory protection unavailable")

    @property
    def status(self) -> MemoryLockStatus:
        return self._status

    def __len__(self) -> int:
        return self._size

    def __enter__(self) -> "LockedBuffer":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise ValueError("secret buffer is closed")

    def view(self) -> memoryview:
        self._ensure_open()
        if not self._size:
            raise ValueError("empty secret buffer has no writable address")
        # Consumer must release any exported view before calling close.
        return memoryview(self._region)

    def write(self, data: bytes | bytearray) -> None:
        self._ensure_open()
        if len(data) != self._size:
            raise ValueError("write must preserve buffer length")
        if self._size:
            self._region[:self._size] = data

    def wipe(self) -> None:
        self._ensure_open()
        if self._size:
            ctypes.memset(self._address, 0, self._size)

    def close(self) -> None:
        if self._closed:
            return
        # Avoid freeing memory while consumer memoryviews remain outstanding.
        # Revoke the buffer API immediately, and fail visibly on unsafe closing.
        self.wipe()
        if self._region is not None:
            try:
                self._region.close()
            except BufferError as exc:
                raise RuntimeError("release all exported memoryviews before close") from exc
        if self._locked and self._size:
            self._unlock()
        self._closed = True
        self._locked = False
        self._address = 0
        self._region = None
        self._status = MemoryLockStatus(False, False, platform.system(),
                                        "wiped and closed")

    def _lock(self) -> MemoryLockStatus:
        system = platform.system()
        if not self._size:
            return MemoryLockStatus(False, False, system, "empty buffer")
        try:
            if system == "Windows":
                k32 = ctypes.WinDLL("kernel32", use_last_error=True)
                k32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                k32.VirtualLock.restype = ctypes.c_int
                if not k32.VirtualLock(self._address, self._size):
                    raise OSError(ctypes.get_last_error(), "VirtualLock failed")
            else:
                libc = ctypes.CDLL(None, use_errno=True)
                libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                libc.mlock.restype = ctypes.c_int
                if libc.mlock(self._address, self._size) != 0:
                    err = ctypes.get_errno()
                    raise OSError(err, os.strerror(err))
            self._locked = True
            if system == "Linux":
                libc = ctypes.CDLL(None, use_errno=True)
                libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
                libc.madvise.restype = ctypes.c_int
                page = mmap.PAGESIZE
                start = self._address - self._address % page
                length = ((self._address + self._size - start + page - 1) // page) * page
                self._dump_excluded = libc.madvise(start, length, 16) == 0
            return MemoryLockStatus(True, self._dump_excluded, system,
                                    "dedicated mmap region")
        except (OSError, AttributeError) as exc:
            return MemoryLockStatus(self._locked, self._dump_excluded, system,
                                    f"lock unavailable: {exc}")

    def _unlock(self) -> None:
        if platform.system() == "Windows":
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            k32.VirtualUnlock(self._address, self._size)
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.munlock(self._address, self._size)
