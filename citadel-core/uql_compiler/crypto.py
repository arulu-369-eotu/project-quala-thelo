"""X25519 + ML-KEM-1024 hybrid key establishment.

The two independent KEM/shared-secret components are transcript-bound and
combined through HKDF-SHA-512. ML-KEM-1024 is the FIPS 203 standardized
parameter set exposed by supported versions of cryptography.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


_CONTEXT = b"UQL-HYBRID-X25519-MLKEM1024-v1"
_X25519_PUBLIC_BYTES = 32
_MLKEM1024_PUBLIC_BYTES = 1568
_MLKEM1024_CIPHERTEXT_BYTES = 1568


@dataclass(frozen=True)
class HybridCiphertext:
    ephemeral_x25519_public: bytes
    mlkem_ciphertext: bytes

    def __post_init__(self) -> None:
        if len(self.ephemeral_x25519_public) != _X25519_PUBLIC_BYTES:
            raise ValueError("invalid X25519 ephemeral public key length")
        if len(self.mlkem_ciphertext) != _MLKEM1024_CIPHERTEXT_BYTES:
            raise ValueError("invalid ML-KEM-1024 ciphertext length")

    def serialize(self) -> bytes:
        return self.ephemeral_x25519_public + self.mlkem_ciphertext

    @classmethod
    def parse(cls, data: bytes) -> "HybridCiphertext":
        if len(data) != _X25519_PUBLIC_BYTES + _MLKEM1024_CIPHERTEXT_BYTES:
            raise ValueError("invalid hybrid ciphertext length")
        return cls(data[:_X25519_PUBLIC_BYTES], data[_X25519_PUBLIC_BYTES:])


@dataclass
class HybridRecipient:
    x25519_private: x25519.X25519PrivateKey
    mlkem_private: mlkem.MLKEM1024PrivateKey

    @classmethod
    def generate(cls) -> "HybridRecipient":
        return cls(
            x25519.X25519PrivateKey.generate(),
            mlkem.MLKEM1024PrivateKey.generate(),
        )

    @property
    def x25519_public_bytes(self) -> bytes:
        return self.x25519_private.public_key().public_bytes_raw()

    @property
    def mlkem_public_bytes(self) -> bytes:
        return self.mlkem_private.public_key().public_bytes_raw()

    def public_bundle(self) -> bytes:
        return self.x25519_public_bytes + self.mlkem_public_bytes

    def decapsulate(self, ciphertext: HybridCiphertext, *, context: bytes = b"") -> bytes:
        peer = x25519.X25519PublicKey.from_public_bytes(ciphertext.ephemeral_x25519_public)
        x_secret = self.x25519_private.exchange(peer)
        mlkem_secret = self.mlkem_private.decapsulate(ciphertext.mlkem_ciphertext)
        return _derive_hybrid_secret(
            x_secret, mlkem_secret, self.public_bundle(), ciphertext.serialize(), context
        )


class HybridKeyExchange:
    @staticmethod
    def encapsulate(
        recipient_x25519_public: bytes,
        recipient_mlkem_public: bytes,
        *,
        context: bytes = b"",
    ) -> tuple[HybridCiphertext, bytes]:
        if len(recipient_x25519_public) != _X25519_PUBLIC_BYTES:
            raise ValueError("invalid X25519 public key length")
        if len(recipient_mlkem_public) != _MLKEM1024_PUBLIC_BYTES:
            raise ValueError("invalid ML-KEM-1024 public key length")

        x_peer = x25519.X25519PublicKey.from_public_bytes(recipient_x25519_public)
        mlkem_peer = mlkem.MLKEM1024PublicKey.from_public_bytes(recipient_mlkem_public)
        ephemeral = x25519.X25519PrivateKey.generate()
        x_secret = ephemeral.exchange(x_peer)
        mlkem_secret, mlkem_ciphertext = mlkem_peer.encapsulate()

        ciphertext = HybridCiphertext(
            ephemeral.public_key().public_bytes_raw(),
            mlkem_ciphertext,
        )
        secret = _derive_hybrid_secret(
            x_secret,
            mlkem_secret,
            recipient_x25519_public + recipient_mlkem_public,
            ciphertext.serialize(),
            context,
        )
        return ciphertext, secret

    @staticmethod
    def encapsulate_bundle(
        recipient_bundle: bytes,
        *,
        context: bytes = b"",
    ) -> tuple[HybridCiphertext, bytes]:
        expected = _X25519_PUBLIC_BYTES + _MLKEM1024_PUBLIC_BYTES
        if len(recipient_bundle) != expected:
            raise ValueError("invalid hybrid public-key bundle length")
        return HybridKeyExchange.encapsulate(
            recipient_bundle[:_X25519_PUBLIC_BYTES],
            recipient_bundle[_X25519_PUBLIC_BYTES:],
            context=context,
        )


def _derive_hybrid_secret(
    x_secret: bytes,
    mlkem_secret: bytes,
    recipient_bundle: bytes,
    ciphertext: bytes,
    context: bytes,
) -> bytes:
    salt_hash = hashes.Hash(hashes.SHA512())
    salt_hash.update(_CONTEXT)
    salt_hash.update(context)
    salt_hash.update(recipient_bundle)
    salt_hash.update(ciphertext)
    salt = salt_hash.finalize()

    return HKDF(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        info=_CONTEXT + context,
    ).derive(x_secret + mlkem_secret)
