"""OpenSSL hybrid key establishment using locked anonymous working pages.

Process memory protection is not a hardware enclave. OpenSSL owns private key
objects; their provider memory is not guaranteed to be locked by this module.
The custom v2 combiner requires independent protocol review before production.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import mmap
import os
import platform
import threading

MAX_CONTEXT_BYTES = 4096
PUBLIC_BUNDLE_BYTES = CIPHERTEXT_BYTES = 1600
KDF_DOMAIN = b"UQL-HYBRID-X25519-MLKEM1024-v2\x00"


class _P(ctypes.Structure):
    _fields_ = [("key", ctypes.c_char_p), ("data_type", ctypes.c_uint),
                ("data", ctypes.c_void_p), ("data_size", ctypes.c_size_t),
                ("return_size", ctypes.c_size_t)]


def _load_crypto():
    path = os.environ.get("UQL_OPENSSL_LIBRARY")
    if path and not os.path.isabs(path):
        raise RuntimeError("UQL_OPENSSL_LIBRARY must be an operator-controlled absolute path")
    lib = ctypes.CDLL(path or ctypes.util.find_library("crypto") or "libcrypto.so")
    lib.OpenSSL_version_num.restype = ctypes.c_ulong
    if lib.OpenSSL_version_num() < 0x30500000:
        raise RuntimeError("UQL native crypto requires OpenSSL 3.5+ with ML-KEM support")
    return lib


L = _load_crypto()
C = ctypes.CDLL(None, use_errno=True)


def bind(name, result, *args):
    fn = getattr(L, name)
    fn.restype, fn.argtypes = result, list(args)
    return fn


V, N = ctypes.c_void_p, ctypes.c_size_t
NP = ctypes.POINTER(N)
Q = bind("EVP_PKEY_Q_keygen", V, V, V, ctypes.c_char_p)
PF = bind("EVP_PKEY_free", None, V)
PUB = bind("EVP_PKEY_get_raw_public_key", ctypes.c_int, V, V, NP)
RAW = bind("EVP_PKEY_new_raw_public_key_ex", V, V, ctypes.c_char_p, ctypes.c_char_p, V, N)
CTX = bind("EVP_PKEY_CTX_new", V, V, V)
CF = bind("EVP_PKEY_CTX_free", None, V)
DI = bind("EVP_PKEY_derive_init", ctypes.c_int, V)
DP = bind("EVP_PKEY_derive_set_peer", ctypes.c_int, V, V)
DV = bind("EVP_PKEY_derive", ctypes.c_int, V, V, NP)
EI = bind("EVP_PKEY_encapsulate_init", ctypes.c_int, V, V)
EV = bind("EVP_PKEY_encapsulate", ctypes.c_int, V, V, NP, V, NP)
KI = bind("EVP_PKEY_decapsulate_init", ctypes.c_int, V, V)
KV = bind("EVP_PKEY_decapsulate", ctypes.c_int, V, V, NP, V, N)
KF = bind("EVP_KDF_fetch", V, V, ctypes.c_char_p, ctypes.c_char_p)
KFF = bind("EVP_KDF_free", None, V)
KCN = bind("EVP_KDF_CTX_new", V, V)
KCF = bind("EVP_KDF_CTX_free", None, V)
KD = bind("EVP_KDF_derive", ctypes.c_int, V, V, N, ctypes.POINTER(_P))
PU = bind("OSSL_PARAM_construct_utf8_string", _P, ctypes.c_char_p, ctypes.c_char_p, N)
PO = bind("OSSL_PARAM_construct_octet_string", _P, ctypes.c_char_p, V, N)
PE = bind("OSSL_PARAM_construct_end", _P)
CMP = bind("CRYPTO_memcmp", ctypes.c_int, V, V, N)
CLEANSE = bind("OPENSSL_cleanse", None, V, N)
for name in ("mlock", "munlock"):
    fn = getattr(C, name)
    fn.restype, fn.argtypes = ctypes.c_int, [V, N]
C.madvise.restype, C.madvise.argtypes = ctypes.c_int, [V, N, ctypes.c_int]


def fail(stage):
    raise RuntimeError("native cryptographic operation failed: " + stage)


def _bytes(value, length=None, *, maximum=None, name="input"):
    if type(value) is not bytes:
        raise ValueError(name + " must be immutable bytes")
    if length is not None and len(value) != length:
        raise ValueError("invalid " + name + " length")
    if maximum is not None and len(value) > maximum:
        raise ValueError(name + " exceeds configured bound")


def transcript_info(bundle: bytes, ciphertext: bytes, context: bytes) -> bytes:
    """Commit to all public inputs with unambiguous length framing, v2 only."""
    _bytes(bundle, PUBLIC_BUNDLE_BYTES, name="public bundle")
    _bytes(ciphertext, CIPHERTEXT_BYTES, name="ciphertext")
    _bytes(context, maximum=MAX_CONTEXT_BYTES, name="context")
    h = hashlib.sha512(KDF_DOMAIN + b"transcript\x00")
    for value in (bundle, ciphertext, context):
        h.update(len(value).to_bytes(8, "big"))
        h.update(value)
    return KDF_DOMAIN + h.digest()


class NativeSecret:
    """Factory-owned anonymous page; no secret export method."""
    __slots__ = ("_map", "_p", "_size", "_closed", "_lock", "_pid")

    def __init__(self, *_args, **_kwargs):
        raise TypeError("use NativeSecret.allocate(); external pointers are not owned")

    @classmethod
    def allocate(cls, size=64):
        if type(size) is not int or not 1 <= size <= mmap.PAGESIZE:
            raise ValueError("invalid secret allocation size")
        if platform.system() != "Linux":
            raise OSError("Linux mlock/MADV_DONTDUMP is required")
        page = mmap.mmap(-1, mmap.PAGESIZE, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
        p = ctypes.addressof(ctypes.c_char.from_buffer(page))
        locked = False
        try:
            if C.mlock(p, mmap.PAGESIZE) != 0:
                fail("mlock")
            locked = True
            if C.madvise(p, mmap.PAGESIZE, mmap.MADV_DONTDUMP) != 0:
                fail("MADV_DONTDUMP")
            if C.madvise(p, mmap.PAGESIZE, mmap.MADV_DONTFORK) != 0:
                fail("MADV_DONTFORK")
            obj = object.__new__(cls)
            obj._map, obj._p, obj._size = page, p, size
            obj._closed, obj._lock, obj._pid = False, threading.RLock(), os.getpid()
            return obj
        except BaseException:
            CLEANSE(p, mmap.PAGESIZE)
            if locked:
                C.munlock(p, mmap.PAGESIZE)
            page.close()
            raise

    def _check(self):
        if self._closed or self._pid != os.getpid():
            raise RuntimeError("secret closed or inherited across fork")

    @property
    def pointer(self):
        self._check()
        with self._lock:
            self._check()
            return self._p

    def same_as(self, other):
        if not isinstance(other, NativeSecret) or self._pid != os.getpid() or other._pid != os.getpid():
            return False
        first, second = sorted((self, other), key=id)
        with first._lock, second._lock:
            return (not self._closed and not other._closed and self._size == other._size
                    and CMP(self._p, other._p, self._size) == 0)

    def close(self):
        if self._pid != os.getpid():
            return
        with self._lock:
            if self._closed:
                return
            CLEANSE(self._p, mmap.PAGESIZE)
            C.munlock(self._p, mmap.PAGESIZE)
            self._map.close()
            self._closed, self._p = True, 0

    def __copy__(self):
        raise TypeError("native secret ownership cannot be copied")

    def __deepcopy__(self, _memo):
        return self.__copy__()

    def __reduce__(self):
        raise TypeError("native secret cannot be serialized")

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        if hasattr(self, "_lock"):
            self.close()


class NativeKeyPair:
    __slots__ = ("_x", "_k", "_lock", "_pid")

    def __init__(self, *_args):
        raise TypeError("use NativeKeyPair.generate()")

    @classmethod
    def generate(cls):
        x = k = None
        try:
            x = Q(None, None, b"X25519")
            k = Q(None, None, b"ML-KEM-1024")
            if not x or not k:
                fail("key generation")
            obj = object.__new__(cls)
            obj._x, obj._k, obj._lock, obj._pid = x, k, threading.RLock(), os.getpid()
            return obj
        except BaseException:
            PF(x)
            PF(k)
            raise

    def _check(self):
        if not self._x or not self._k or self._pid != os.getpid():
            raise RuntimeError("key pair closed or inherited across fork")

    def public_bundle(self):
        self._check()
        with self._lock:
            self._check()
            return _public(self._x, 32) + _public(self._k, 1568)

    def close(self):
        if self._pid != os.getpid():
            return
        with self._lock:
            if self._x:
                PF(self._x)
                self._x = 0
            if self._k:
                PF(self._k)
                self._k = 0

    def __copy__(self):
        raise TypeError("native key ownership cannot be copied")

    def __deepcopy__(self, _memo):
        return self.__copy__()

    def __reduce__(self):
        raise TypeError("native keys cannot be serialized")

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        if hasattr(self, "_lock"):
            self.close()


def _public(key, size):
    result, n = ctypes.create_string_buffer(size), N(size)
    if PUB(key, result, ctypes.byref(n)) <= 0 or n.value != size:
        fail("public key extraction")
    return result.raw


def _xsecret(priv, peer_bytes, output):
    peer = ctx = None
    try:
        peer = RAW(None, b"X25519", None, peer_bytes, 32)
        ctx = CTX(priv, None)
        if not peer or not ctx or DI(ctx) <= 0 or DP(ctx, peer) <= 0:
            fail("X25519 setup")
        n = N(32)
        if DV(ctx, output.pointer, ctypes.byref(n)) <= 0 or n.value != 32:
            fail("X25519 derive")
    finally:
        CF(ctx)
        PF(peer)


def _hkdf(x, k, info):
    with NativeSecret.allocate(64) as ikm:
        ctypes.memmove(ikm.pointer, x.pointer, 32)
        ctypes.memmove(ikm.pointer + 32, k.pointer, 32)
        ib = ctypes.create_string_buffer(info)
        h = KF(None, b"HKDF", None)
        if not h:
            fail("HKDF fetch")
        try:
            ctx = KCN(h)
        finally:
            KFF(h)
        if not ctx:
            fail("HKDF context")
        try:
            params = (_P * 5)(PU(b"mode", b"EXTRACT_AND_EXPAND", 0),
                              PU(b"digest", b"SHA512", 0), PO(b"key", ikm.pointer, 64),
                              PO(b"info", ib, len(info)), PE())
            secret = NativeSecret.allocate()
            try:
                if KD(ctx, secret.pointer, 64, params) <= 0:
                    fail("HKDF derive")
                return secret
            except BaseException:
                secret.close()
                raise
        finally:
            KCF(ctx)


def encapsulate(bundle, context=b""):
    _bytes(bundle, PUBLIC_BUNDLE_BYTES, name="public bundle")
    _bytes(context, maximum=MAX_CONTEXT_BYTES, name="context")
    kp = eph = kc = None
    try:
        kp = RAW(None, b"ML-KEM-1024", None, bundle[32:], 1568)
        eph = Q(None, None, b"X25519")
        if not kp or not eph:
            fail("encapsulation setup")
        with NativeSecret.allocate(32) as xs, NativeSecret.allocate(32) as ms:
            _xsecret(eph, bundle[:32], xs)
            kc = CTX(kp, None)
            if not kc or EI(kc, None) <= 0:
                fail("ML-KEM encapsulation setup")
            ct, cn, mn = ctypes.create_string_buffer(1568), N(1568), N(32)
            if EV(kc, ct, ctypes.byref(cn), ms.pointer, ctypes.byref(mn)) <= 0 or cn.value != 1568 or mn.value != 32:
                fail("ML-KEM encapsulation")
            ciphertext = _public(eph, 32) + ct.raw
            return ciphertext, _hkdf(xs, ms, transcript_info(bundle, ciphertext, context))
    finally:
        CF(kc)
        PF(kp)
        PF(eph)


def decapsulate(kp, ciphertext, context=b""):
    if not isinstance(kp, NativeKeyPair):
        raise ValueError("invalid native recipient")
    _bytes(ciphertext, CIPHERTEXT_BYTES, name="ciphertext")
    _bytes(context, maximum=MAX_CONTEXT_BYTES, name="context")
    kp._check()
    with kp._lock:
        kp._check()
        with NativeSecret.allocate(32) as xs, NativeSecret.allocate(32) as ms:
            kc = None
            try:
                _xsecret(kp._x, ciphertext[:32], xs)
                kc = CTX(kp._k, None)
                if not kc or KI(kc, None) <= 0:
                    fail("ML-KEM decapsulation setup")
                ct, n = ctypes.create_string_buffer(ciphertext[32:]), N(32)
                if KV(kc, ms.pointer, ctypes.byref(n), ct, 1568) <= 0 or n.value != 32:
                    fail("ML-KEM decapsulation")
                return _hkdf(xs, ms, transcript_info(kp.public_bundle(), ciphertext, context))
            finally:
                CF(kc)
