# UQL Omniversal Compiler

![Seal of Eotu](uql_compiler/next/assets/seal-of-eotu.jpg)

## UQL NEXT 0.2

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e './citadel-core[next-test]'
.venv/bin/uql compile citadel-core/examples/bell.uql --out uql-out/bell
.venv/bin/uql verify uql-out/bell
.venv/bin/uql differential uql-out/bell
.venv/bin/python -m pytest -q citadel-core/tests/next
```

Keep the printed manifest fingerprint through a trusted channel and pass it as
`uql verify BUNDLE --expect DIGEST` to detect whole-bundle substitution against
that pin. It does not establish publisher identity on its own. Output directories
must be new. The compiler performs no network calls or hardware execution.

The reference compiler core also runs directly from source with Python 3.11+
and no site packages:

```bash
PYTHONPATH=citadel-core python3 -S -m uql_compiler.next inspect citadel-core/examples/bell.uql
PYTHONPATH=citadel-core python3 -S -m uql_compiler.next simulate citadel-core/examples/phase_sensitive.uql
```

`uql compare LEFT.uql RIGHT.uql --relation premeasurement_unitary` checks all
basis-column amplitudes for at most four qubits. The alternative
`zero_input_distribution` observes the mapped classical outputs instead. Both
are bounded numerical checks; a failed check returns a specific discrepancy.

See the [formal specification](../docs/uql-next/SPECIFICATION-0.2.md),
[validation evidence](../docs/uql-next/VALIDATION.md), and
[first twelve frontier capabilities](../docs/uql-next/FRONTIER_12.md).
The tests for this new layer are separate from the existing native/QEC/DD tests;
the [audit](../docs/uql-next/AUDIT.md) records their baseline failures.

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

