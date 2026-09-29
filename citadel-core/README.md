# UQL Omniversal Compiler

The UQL compiler is split into two deliberate layers:

1. **Architecture declarations** — names, interfaces, and intended security
   properties.
2. **Verified mechanisms** — executable cryptographic, memory, QEC, and
   scheduling implementations with tests.

This separation is foundational: declarations never substitute for evidence.

## Implemented mechanisms

- X25519 + FIPS 203 ML-KEM-1024 hybrid key establishment with HKDF-SHA-512.
- OS-backed secret-memory locking with explicit capability reporting.
- Planar rotated surface-code syndrome extraction using the [[d^2, 1, d]]
  family for odd distance.
- Coherence-aware Qiskit dynamical-decoupling scheduling.

## Security boundaries

The memory layer is intentionally **best effort**. Python's object model can
create copies outside a locked buffer, and OS page locking is not a proof
against every privileged-memory or cold-boot acquisition technique.

The quantum layer constructs and schedules physical circuits. It does not
claim a decoder, logical-error threshold, calibrated hardware fidelity, or
fault-tolerance certification without those components and measurements.

For hardware DD execution, provide backend-derived instruction durations;
fabricated timing constants are never presented as hardware calibration.

## Verification

Install and run:

    python -m pip install -e '.[test]'
    python -m pytest -q

CI tests the package on Python 3.11, 3.12, and 3.13.
