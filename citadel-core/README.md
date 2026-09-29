# UQL Omniversal Compiler

Production package boundary for the UQL compiler's declarative architecture
and verified mechanisms.

## Mechanisms

- X25519 + FIPS 203 ML-KEM-1024 hybrid key establishment with HKDF-SHA-512.
- OS-backed secret-memory locking with explicit capability reporting.
- Repeated surface-code stabilizer syndrome extraction in Cirq.
- Coherence-aware Qiskit dynamical-decoupling scheduling.

The memory layer is deliberately described as **best effort**: Python's object
model cannot guarantee that no secret copies ever exist, and OS memory locking
does not constitute a mathematical guarantee against cold-boot attacks.

## Verification

Run:

    python -m pip install -e '.[test]'
    python -m pytest -q

Quantum mechanisms require their declared runtime dependencies. CI executes the
same test suite on a clean environment.
