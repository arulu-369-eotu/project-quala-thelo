from uql_compiler.crypto import HybridKeyExchange,HybridRecipient,HybridCiphertext

def test_native_hybrid_key_agreement():
    recipient=HybridRecipient.generate()
    a=b=None
    try:
        ct,a=HybridKeyExchange.encapsulate_bundle(recipient.public_bundle(),context=b"test")
        b=recipient.decapsulate(ct,context=b"test")
        assert a.same_as(b)
        assert a.pointer != 0
        assert HybridCiphertext.parse(ct.serialize())==ct
    finally:
        if a:a.close()
        if b:b.close()
        recipient._native.close()

def test_context_binds_key():
    recipient=HybridRecipient.generate()
    a=b=c=None
    try:
        ct,a=HybridKeyExchange.encapsulate_bundle(recipient.public_bundle(),context=b"a")
        b=recipient.decapsulate(ct,context=b"a")
        c=recipient.decapsulate(ct,context=b"b")
        assert a.same_as(b)
        assert not a.same_as(c)
    finally:
        for s in (a,b,c):
            if s:s.close()
        recipient._native.close()
