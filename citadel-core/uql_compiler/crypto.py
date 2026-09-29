"""Hybrid X25519 + ML-KEM-1024 key establishment.

ML-KEM-1024 is the FIPS 203 standardized KEM exposed by modern versions of
cryptography. The hybrid secret is derived only after both component secrets
have been established and transcript-bound with HKDF-SHA-512.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
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

    def serialize(self) -> bytes:
        return self.ephemeral_x25519_public + self.mlkem_ciphertext

    @classmethod
    def parse(cls, data: bytes) -> "HybridCiphertext":
        if len(data) != _X25519_PUBLIC_BYTES + _MLKEM1024_CIPHERTEXT_BYTES:
            raise ValueError("invalid hybrid ciphertext length")
        return cls(data[:_X25519_PUBLIC_BYTES], data[_X25519_PUBLIC_BYTES:])


@dataclass
class HybridRecipient:
    """Long-term recipient key pair."""

    x25519_private: x25519.X25519PrivateKey
    mlkem_private: mlkem.MLKEM1024PrivateKey

    @classmethod
    def generate(cls) -> "HybridRecipient":
        return cls(x25519.X25519PrivateKey.generate(), mlkem.MLKEM1024PrivateKey.generate())

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
            x_secret,
            mlkem_secret,
            self.public_bundle(),
            ciphertext.serialize(),
            context,
        )


class HybridKeyExchange:
    """Stateless initiator for hybrid key establishment."""

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
            ephemeral_x25519_public=ephemeral.public_key().public_bytes_raw(),
            mlkem_ciphertext=mlkem_ciphertext,
        )
        secret = _derive_hybrid_secret(
            x_secret,
            mlkem_secret,
            recipient_x25519_public + recipient_mlkem_public,
            ciphertext.serialize(),
            context,
        )
        return ciphertext, secret


def _derive_hybrid_secret(
    x_secret: bytes,
    mlkem_secret: bytes,
    recipient_bundle: bytes,
    ciphertext: bytes,
    context: bytes,
) -> bytes:
    salt = hashes.Hash(hashes.SHA512())
    salt.update(_CONTEXT)
    salt.update(context)
    salt.update(recipient_bundle)
    salt.update(ciphertext)
    salt_bytes = salt.finalize()

    return HKDF(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt_bytes,
        info=_CONTEXT + context,
    ).derive(x_secret + mlkem_secret)
