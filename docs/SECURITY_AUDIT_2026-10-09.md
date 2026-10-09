# QUA'LA Security Audit — scoped engineering review (2026-10-09)

## Scope and assurance limits

Reviewed the public repository at `main` (the Python source and tests in
`citadel-core`, workflow, manifests, and legal documentation), plus the
separately developed enterprise-trust-plane prototype. This is **not** an audit
of any other "Codex" copies, private repositories, cloud instances, deployed
services, devices or linked projects. The review is static except for the 25
enterprise-trust-plane tests run locally. No penetration test, formal proof or
third-party assessment was completed.

## Findings

| ID | Severity | Evidence | Mitigation / disposition |
|---|---|---|---|
| Q-001 | Critical functional failure | `native_crypto._hkdf` concatenates a 1,600-byte public bundle, a 1,600-byte ciphertext and context with a label, then rejects info >1,024 bytes. Normal hybrid handshake always fails. | **Patched on feature branch**: SHA-512 length-delimited public transcript with distinct domain tag and bounded context; version v2. Regression tests added. Full environment test outstanding. |
| Q-002 | High | `native_crypto._hkdf` holds 64-byte combined secret in `ctypes.create_string_buffer` and wipes it only on success; X25519/ML-KEM intermediate ctypes buffers also lack guaranteed erasure on all exit paths. | Move cryptographic composition into audited native C/Rust code with explicit cleanup on all paths; treat this Python/ctypes implementation as experimental pending independent review. |
| Q-003 | High | The low-level `NativeSecret.pointer` property exposes a raw secret address to Python caller code, contradicting the claim of an opaque handle. | Replace raw-pointer API with opaque FFI operations and capability-scoped methods; expose no numeric pointer outside the native shim. |
| Q-004 | High | `memory.LockedBuffer` is backed by a Python bytearray; Linux `madvise(MADV_DONTDUMP)` marks entire heap pages which may also hold unrelated allocations; locking alone does not prevent copies. | Allocate separate page-aligned mmap regions for secrets, or retire this class for key storage. Keep its best-effort disclosure truthful. |
| Q-005 | Medium | No authenticated envelope, peer identity verification, key-confirmation exchange, or replay rejection is provided by `HybridKeyExchange` itself. | Integrate with a well-analyzed authenticated transport (e.g. standards-based TLS) and separately authenticate peer identity; do not label KEM output as a secure session. |
| Q-006 | Medium | `NativeKeyPair` and `NativeSecret` are not explicitly synchronized for concurrent close and use; native pointers can become dangling when callers race. | Use strict ownership lifecycle, locks/handles in native code, race tests and sanitizers before concurrency. |
| Q-007 | Medium | Workflow includes unpinned third-party actions and dependencies with wide version ranges; no package hashes, SBOM, provenance attestation or CodeQL gates. | Pin action SHAs, use lock files and signed supply-chain evidence, enable dependency review/code scanning and protected branches. |
| Q-008 | Medium | The `qec.SurfaceCode` module constructs circuits and checks operator commutation but contains no decoder or logical error benchmark. | Keep `[[d²,1,d]]` as a circuit construction claim; validate noisy syndrome extraction, decoder performance and scalable resource costs before claiming fault tolerance. |
| Q-009 | Medium | `dd.CoherenceModel.survival_fraction` is an idealized exponential estimator and local DD timings are simulations, not calibrated physical-device error budgets. | Require calibrated backend Target, measurements and statistical benchmarking before hardware claims. |
| Q-010 | High for deployment | Prototype Trust Exchange uses current Ed25519 signatures and an in-process issuer registry; no durable trust-root authority, HSM custody or anchored log is provided yet. | Next phase: ABRAXAS 7 process isolation, durable identity enrollment, HSM-backed signing, external transparency witnessing and operational revocation service. |
| Q-011 | High for deployment | Example data schemas do not establish third-party provenance or validity of an issuer's underlying evidence. | Credential issuer qualification, provenance controls, assurance levels and independent audit before customer-reliance claims. |
| Q-012 | Governance | `LICENSE` is custom, requires commercial agreements and royalties; enforceability, contribution licensing and interoperability implications have not been reviewed by counsel. | Legal review with counsel, dual-license strategy, explicit versioned commercial contract and open-core boundaries. |

## Release blockers

1. Run the crypto regression suite on compatible Linux with OpenSSL 3.5+; check
   v2 ciphertext derivation on independent implementations and publish vectors.
2. Migrate any real clients off the previous derivation version with explicit
   negotiation, no downgrade path; no evidence of deployed clients was observed.
3. Fix unsafe handling of secret-bearing ctypes buffers and pointer ownership.
4. Complete authorization, tenant-isolation and threat-model integration tests.
5. Independent cryptographic audit and adversarial review before external use.
6. Verify identity, revocation, backup, recovery, incident response and legal controls.

**No 1000/1000 security score or claim of full Codex coverage is supported.**
