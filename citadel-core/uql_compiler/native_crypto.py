"""Native OpenSSL enclave: private keys and derived secrets never enter Python byte storage."""
from __future__ import annotations
import ctypes, ctypes.util, mmap, platform, hashlib
from dataclasses import dataclass
class _P(ctypes.Structure):
    _fields_=[("key",ctypes.c_char_p),("data_type",ctypes.c_uint),("data",ctypes.c_void_p),("data_size",ctypes.c_size_t),("return_size",ctypes.c_size_t)]
L=ctypes.CDLL(ctypes.util.find_library("crypto") or "libcrypto.so"); C=ctypes.CDLL(None,use_errno=True)
def bind(n,r,*a):
    f=getattr(L,n); f.restype=r; f.argtypes=list(a); return f
Q=bind("EVP_PKEY_Q_keygen",ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_char_p); PF=bind("EVP_PKEY_free",None,ctypes.c_void_p)
PUB=bind("EVP_PKEY_get_raw_public_key",ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t)); RAW=bind("EVP_PKEY_new_raw_public_key_ex",ctypes.c_void_p,ctypes.c_void_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t)
CTX=bind("EVP_PKEY_CTX_new",ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p); CF=bind("EVP_PKEY_CTX_free",None,ctypes.c_void_p)
DI=bind("EVP_PKEY_derive_init",ctypes.c_int,ctypes.c_void_p); DP=bind("EVP_PKEY_derive_set_peer",ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p); DV=bind("EVP_PKEY_derive",ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t))
EI=bind("EVP_PKEY_encapsulate_init",ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p); EV=bind("EVP_PKEY_encapsulate",ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t))
KI=bind("EVP_PKEY_decapsulate_init",ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p); KV=bind("EVP_PKEY_decapsulate",ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p,ctypes.c_size_t)
KF=bind("EVP_KDF_fetch",ctypes.c_void_p,ctypes.c_void_p,ctypes.c_char_p,ctypes.c_char_p); KFF=bind("EVP_KDF_free",None,ctypes.c_void_p); KCN=bind("EVP_KDF_CTX_new",ctypes.c_void_p,ctypes.c_void_p); KCF=bind("EVP_KDF_CTX_free",None,ctypes.c_void_p)
KD=bind("EVP_KDF_derive",ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(_P)); PU=bind("OSSL_PARAM_construct_utf8_string",_P,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_size_t); PO=bind("OSSL_PARAM_construct_octet_string",_P,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t); PE=bind("OSSL_PARAM_construct_end",_P); CMP=bind("CRYPTO_memcmp",ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t)
C.posix_memalign.restype=ctypes.c_int; C.posix_memalign.argtypes=[ctypes.POINTER(ctypes.c_void_p),ctypes.c_size_t,ctypes.c_size_t]; C.free.restype=None; C.free.argtypes=[ctypes.c_void_p]
C.mlock.restype=ctypes.c_int; C.mlock.argtypes=[ctypes.c_void_p,ctypes.c_size_t]; C.munlock.restype=ctypes.c_int; C.munlock.argtypes=[ctypes.c_void_p,ctypes.c_size_t]; C.madvise.restype=ctypes.c_int; C.madvise.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]; C.memset.restype=ctypes.c_void_p; C.memset.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_size_t]
def fail(s): raise RuntimeError("native cryptographic operation failed: "+s)
class NativeSecret:
    __slots__=("_p","_size","_closed")
    def __init__(self,p,size=64): self._p=ctypes.c_void_p(p); self._size=size; self._closed=False
    @classmethod
    def allocate(cls):
        if platform.system()!="Linux": raise OSError("Linux mlock/madvise lockdown is required")
        page=mmap.PAGESIZE; p=ctypes.c_void_p()
        if C.posix_memalign(ctypes.byref(p),page,page)!=0 or not p.value: fail("allocation")
        if C.mlock(p,page)!=0: C.free(p); fail("mlock")
        if C.madvise(p,page,16)!=0: C.munlock(p,page); C.free(p); fail("MADV_DONTDUMP")
        C.memset(p,0,page); return cls(p.value)
    @property
    def pointer(self):
        if self._closed: raise RuntimeError("secret closed")
        return int(self._p.value)
    def same_as(self,other):
        return isinstance(other,NativeSecret) and not self._closed and not other._closed and CMP(self._p,other._p,self._size)==0
    def close(self):
        if self._closed:return
        C.memset(self._p,0,mmap.PAGESIZE); C.munlock(self._p,mmap.PAGESIZE); C.free(self._p); self._closed=True; self._p=ctypes.c_void_p()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
    def __del__(self):
        try:self.close()
        except Exception:pass
@dataclass
class NativeKeyPair:
    _x:int
    _k:int
    @classmethod
    def generate(cls):
        x=Q(None,None,b"X25519"); k=Q(None,None,b"ML-KEM-1024")
        if not x or not k: PF(x); PF(k); fail("key generation")
        return cls(x,k)
    def public_bundle(self):
        def pub(p,n):
            b=ctypes.create_string_buffer(n); z=ctypes.c_size_t(n)
            if PUB(p,b,ctypes.byref(z))<=0 or z.value!=n: fail("public key")
            return b.raw
        return pub(self._x,32)+pub(self._k,1568)
    def close(self):
        if self._x: PF(self._x); self._x=0
        if self._k: PF(self._k); self._k=0
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
    def __del__(self):
        try:self.close()
        except Exception:pass
def _xsecret(priv,peer_bytes):
    peer=RAW(None,b"X25519",None,peer_bytes,32); c=CTX(priv,None)
    try:
        if not peer or not c or DI(c)<=0 or DP(c,peer)<=0:fail("X25519 setup")
        out=ctypes.create_string_buffer(32); n=ctypes.c_size_t(32)
        if DV(c,out,ctypes.byref(n))<=0 or n.value!=32:fail("X25519 derive")
        return out
    finally:CF(c);PF(peer)
def _hkdf(x,k,transcript):
    ikm=ctypes.create_string_buffer(64); C.memset(ikm,0,64); ctypes.memmove(ikm,x,32); ctypes.memmove(ctypes.addressof(ikm)+32,k,32)
    # Transcript is public protocol data. Hash the complete, length-bound
    # transcript before HKDF rather than truncating it or exceeding EVP limits.
    # Domain separation and explicit lengths avoid ambiguous concatenations.
    if type(transcript) is not bytes or len(transcript)>8192:
        C.memset(ikm,0,64)
        raise ValueError("invalid transcript")
    info=b"UQL-HYBRID-X25519-MLKEM1024-v2\x00"+hashlib.sha512(
        b"UQL-HYBRID-TRANSCRIPT-v2\x00"+len(transcript).to_bytes(4,"big")+transcript
    ).digest()
    ib=ctypes.create_string_buffer(info); h=KF(None,b"HKDF",None); c=KCN(h); KFF(h)
    if not c:
        C.memset(ikm,0,64)
        fail("HKDF context")
    try:
        ps=(_P*5)(); ps[0]=PU(b"mode",b"EXTRACT_AND_EXPAND",0); ps[1]=PU(b"digest",b"SHA512",0); ps[2]=PO(b"key",ikm,64); ps[3]=PO(b"info",ib,len(info)); ps[4]=PE()
        s=NativeSecret.allocate()
        if KD(c,s.pointer,64,ps)<=0:s.close();fail("HKDF")
        return s
    finally:
        C.memset(ikm,0,64)
        KCF(c)
def encapsulate(bundle,context=b""):
    if len(bundle)!=1600:raise ValueError("invalid hybrid public-key bundle")
    if type(context) is not bytes or len(context)>4096:raise ValueError("invalid hybrid context")
    xp=RAW(None,b"X25519",None,bundle[:32],32); kp=RAW(None,b"ML-KEM-1024",None,bundle[32:],1568); eph=Q(None,None,b"X25519")
    if not xp or not kp or not eph:PF(xp);PF(kp);PF(eph);fail("encapsulation setup")
    xc=CTX(eph,None); kc=CTX(kp,None)
    try:
        if not xc or DI(xc)<=0 or DP(xc,xp)<=0:fail("X25519 encapsulation")
        xs=ctypes.create_string_buffer(32); xn=ctypes.c_size_t(32)
        if DV(xc,xs,ctypes.byref(xn))<=0:fail("X25519 secret")
        if not kc or EI(kc,None)<=0:fail("ML-KEM encapsulation")
        ct=ctypes.create_string_buffer(1568); cn=ctypes.c_size_t(1568); ms=ctypes.create_string_buffer(32); mn=ctypes.c_size_t(32)
        if EV(kc,ct,ctypes.byref(cn),ms,ctypes.byref(mn))<=0 or cn.value!=1568 or mn.value!=32:fail("ML-KEM encapsulation")
        pb=ctypes.create_string_buffer(32); pn=ctypes.c_size_t(32)
        if PUB(eph,pb,ctypes.byref(pn))<=0:fail("ephemeral public key")
        ciphertext=pb.raw+ct.raw
        return ciphertext,_hkdf(xs,ms,bundle+ciphertext+context)
    finally:
        for name in ("xs","ms"):
            buf=locals().get(name)
            if buf is not None: C.memset(buf,0,ctypes.sizeof(buf))
        CF(xc);CF(kc);PF(xp);PF(kp);PF(eph)
def decapsulate(kp,ciphertext,context=b""):
    if len(ciphertext)!=1600:raise ValueError("invalid hybrid ciphertext")
    if type(context) is not bytes or len(context)>4096:raise ValueError("invalid hybrid context")
    xs=_xsecret(kp._x,ciphertext[:32]); kc=CTX(kp._k,None)
    try:
        if not kc or KI(kc,None)<=0:fail("ML-KEM decapsulation")
        ct=ctypes.create_string_buffer(ciphertext[32:]); ms=ctypes.create_string_buffer(32); n=ctypes.c_size_t(32)
        if KV(kc,ms,ctypes.byref(n),ct,1568)<=0 or n.value!=32:fail("ML-KEM decapsulation")
        return _hkdf(xs,ms,kp.public_bundle()+ciphertext+context)
    finally:
        for buf in (xs, locals().get("ms")):
            if buf is not None: C.memset(buf,0,ctypes.sizeof(buf))
        CF(kc)
