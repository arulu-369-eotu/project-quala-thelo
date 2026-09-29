# UQL Omniversal Compiler

## Native cryptographic enclave

The hybrid cryptographic path is native-only:

- OpenSSL 3.5+ generates X25519 and ML-KEM-1024 private keys.
- Private key material remains in native OpenSSL objects.
- X25519, ML-KEM-1024, and HKDF-SHA-512 execute through native OpenSSL EVP APIs.
- The derived 64-byte hybrid secret is allocated outside Python, page-aligned, mlock'ed, and marked MADV_DONTDUMP.
- Python receives only an opaque native pointer for secret material.
- No secret export method exists on NativeSecret; equality is performed in native memory with CRYPTO_memcmp.
- The Linux native lockdown path fails closed if mlock or MADV_DONTDUMP cannot be established.

Public keys and ciphertexts are ordinary Python byte strings because they are not secret key material.

## Architectural boundary

Architecture declarations remain separate from executable mechanisms. Claims are made only where the implementation can enforce them.

## Verification

    python -m pip install -e '.[test]'
    python -m pytest -q

The native cryptographic subsystem requires OpenSSL 3.5+ on Linux.
