"""Public API for the native-only hybrid cryptographic subsystem."""
from __future__ import annotations
from dataclasses import dataclass
from .native_crypto import NativeKeyPair,NativeSecret,encapsulate as _encapsulate,decapsulate as _decapsulate
@dataclass(frozen=True)
class HybridCiphertext:
    data: bytes
    def __post_init__(self):
        if len(self.data)!=1600:raise ValueError("invalid hybrid ciphertext length")
    def serialize(self)->bytes:return self.data
    @classmethod
    def parse(cls,data:bytes)->"HybridCiphertext":return cls(bytes(data))
@dataclass
class HybridRecipient:
    _native: NativeKeyPair
    @classmethod
    def generate(cls)->"HybridRecipient":return cls(NativeKeyPair.generate())
    @property
    def x25519_public_bytes(self)->bytes:return self.public_bundle()[:32]
    @property
    def mlkem_public_bytes(self)->bytes:return self.public_bundle()[32:]
    def public_bundle(self)->bytes:return self._native.public_bundle()
    def decapsulate(self,ciphertext:HybridCiphertext,*,context:bytes=b"")->NativeSecret:return _decapsulate(self._native,ciphertext.serialize(),context)
class HybridKeyExchange:
    @staticmethod
    def encapsulate(recipient_x25519_public:bytes,recipient_mlkem_public:bytes,*,context:bytes=b""):
        c,s=_encapsulate(recipient_x25519_public+recipient_mlkem_public,context);return HybridCiphertext(c),s
    @staticmethod
    def encapsulate_bundle(recipient_bundle:bytes,*,context:bytes=b""):
        c,s=_encapsulate(recipient_bundle,context);return HybridCiphertext(c),s
