"""Regression tests for the repaired, domain-separated hybrid transcript."""
import pytest
from uql_compiler.crypto import HybridKeyExchange, HybridRecipient

def test_complete_hybrid_handshake_and_context_binding():
    recipient = HybridRecipient.generate()
    a = b = c = None
    try:
        ct, a = HybridKeyExchange.encapsulate_bundle(recipient.public_bundle(), context=b"QU'ALA/tenant-1")
        b = recipient.decapsulate(ct, context=b"QU'ALA/tenant-1")
        c = recipient.decapsulate(ct, context=b"QU'ALA/tenant-2")
        assert a.same_as(b)
        assert not a.same_as(c)
        assert len(ct.serialize()) == 1600
    finally:
        for secret in (a, b, c):
            if secret is not None:
                secret.close()
        recipient._native.close()

def test_context_limits_fail_closed():
    recipient = HybridRecipient.generate()
    try:
        with pytest.raises(ValueError):
            HybridKeyExchange.encapsulate_bundle(recipient.public_bundle(), context=b"x" * 4097)
        with pytest.raises(ValueError):
            HybridKeyExchange.encapsulate_bundle(recipient.public_bundle(), context="not-bytes")
    finally:
        recipient._native.close()

def test_large_but_bounded_context_derives_same_key():
    recipient = HybridRecipient.generate()
    a = b = None
    try:
        ct, a = HybridKeyExchange.encapsulate_bundle(recipient.public_bundle(), context=b"c" * 4096)
        b = recipient.decapsulate(ct, context=b"c" * 4096)
        assert a.same_as(b)
    finally:
        for secret in (a, b):
            if secret is not None:
                secret.close()
        recipient._native.close()
