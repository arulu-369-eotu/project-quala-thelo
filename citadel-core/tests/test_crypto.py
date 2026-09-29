import pytest

pytest.importorskip("cryptography")

from uql_compiler.crypto import HybridKeyExchange, HybridRecipient


def test_hybrid_key_agreement():
    recipient = HybridRecipient.generate()
    ciphertext, initiator_secret = HybridKeyExchange.encapsulate(
        recipient.x25519_public_bytes,
        recipient.mlkem_public_bytes,
        context=b"test",
    )
    recipient_secret = recipient.decapsulate(ciphertext, context=b"test")
    assert initiator_secret == recipient_secret
    assert len(initiator_secret) == 64


def test_context_binds_key():
    recipient = HybridRecipient.generate()
    ciphertext, key = HybridKeyExchange.encapsulate(
        recipient.x25519_public_bytes, recipient.mlkem_public_bytes, context=b"a"
    )
    assert key != recipient.decapsulate(ciphertext, context=b"b")
