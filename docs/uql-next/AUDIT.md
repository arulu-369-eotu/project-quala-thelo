# UQL NEXT architecture audit

Source baseline: `arulu-369-eotu/project-quala-thelo` main, commit
`81a515e36c35ddd28ad00096442db874d67bb5ab`. Review date: October 22, 2026,
America/Detroit. The uploaded proposal is design input, not implementation evidence.

## Findings that change the build

The README places UQL/QHL/QTL in `citadel-core`, but the actual baseline contains
cryptographic, memory, surface-code and dynamical-decoupling modules. It has no
language grammar, parser, AST, canonical IR, OpenQASM/QIR lowering, or language
conformance corpus. The previous statement that this was already a clean language
foundation was too strong. Existing mechanisms are useful neighbors, not a parser.

Baseline tests executed with Python 3.12.14, Qiskit 2.6.1 and Cirq 1.7.0:
**3 passed, 5 failed**. The failures are native key generation (2), unsupported
`spacings` scheduling argument (1), and noncommuting surface-code checks (2).
Python's SSL module and the library loaded by ctypes need not be the same OpenSSL
build; observing Python SSL 3.5.8 does not establish native ML-KEM availability.
The native code also contains an HKDF input-length rejection on its normal
transcript. Open PRs #1 and #2 contain earlier repair work; neither was merged or
silently incorporated into this additive language change. The whole repository
is not release-ready on the evidence collected here.

## Assessment of the proposal's 15 directions

| # | Direction | Engineering finding and decision |
|---|---|---|
| 1 | Proof-carrying programs | Build evidence bundles first. An unsigned receipt is not a machine-checked proof. Formal proof production needs a semantics and a trusted checker. |
| 2 | Semantic hashing | Define versioned normalized circuit identity. It is not a complete invariant for arbitrary quantum semantics; unequal hashes do not imply inequivalence. |
| 3 | Transformation receipts | Implement a bounded local rule checker and edit replay. A log without rule checking establishes only provenance. |
| 4 | Quantum BOM | Useful artifact inventory. Use an explicitly draft schema and avoid claiming SPDX/CycloneDX compatibility. |
| 5 | Resource-aware types | Start with enforced structural limits. Counts are not physical-qubit, runtime, fidelity, or logical-error estimates. |
| 6 | Capability contracts | Reject unavailable capabilities. Device selection requires versioned target data and a real resolver. |
| 7 | Hybrid concurrency | Requires a scheduler, memory/effect model and host/device semantics. The current subset rejects it. |
| 8 | Distributed semantics | Define ownership, failure and classical messaging first; simulation does not establish a deployed network. |
| 9 | Error budgets | Metrics and composition rules must be explicit. Adding per-gate error probabilities is not a general channel-error proof. |
| 10 | QEC language layer | Requires validated code constructions, decoders, code-transition semantics and noise assumptions. Baseline QEC tests currently fail. |
| 11 | Counterfactual compiler | Limit optimization claims to the declared candidate set. Heuristic Pareto search does not prove global optimality. |
| 12 | Trust contracts | Fail closed for signatures, backend attestation and independent verification until implemented and trusted identities are configured. |
| 13 | Program passport | Bind the source, IR, interfaces and evidence. Distinguish structural integrity, publisher identity and physical execution. |
| 14 | Executable claims | Attach a relation, assumptions, observation, tolerance and inconclusive result. A single-input simulator agreement is not universal equivalence. |
| 15 | Conformance lab | Implement valid/invalid examples, stable vectors, adversarial bundles, numerical comparisons and executed target tests. |

## Prior art and novelty boundaries

Verified quantum optimization predates this project: [VOQC](https://www.quics.umd.edu/publications/verified-optimizer-quantum-circuits),
[CertiQ](https://arxiv.org/abs/1908.08963), and
[Giallar](https://research.ibm.com/publications/giallar-push-button-verification-for-the-qiskit-quantum-compiler)
already address verification of transformations. UQL must make its contribution
more specific than “a verified quantum compiler.”

[OpenQASM 3](https://openqasm.com/language/) already supports quantum operations
and substantial classical control. [QIR Base Profile](https://github.com/qir-alliance/qir-spec/blob/main/specification/profiles/Base_Profile.md)
defines a constrained terminal-measurement execution interface. These are
interoperability targets, not evidence that UQL supports every feature they do.

[MQT's compiler architecture](https://arxiv.org/abs/2604.08674) and the
[IBM Quantum Engine Compiler](https://arxiv.org/abs/2408.06469) cover multi-level
and heterogeneous compilation. More directly, September 2026's
[CUDA-Q Logical](https://arxiv.org/abs/2609.13388) discusses fault-tolerant lowering,
provenance and artifact-derived resource analysis. These overlap materially with
the uploaded proposal. Their existence rules out an unsupported broad “first.”

[MQT QCEC](https://mqt.readthedocs.io/projects/qcec/en/latest/) supplies several
equivalence methods with different boundaries. The October 2026
[assurance-contract survey](https://arxiv.org/abs/2610.00255) explicitly connects
semantic relations, delivered interfaces, evidence and revision analysis.
Therefore the best research question is whether the specific integrated UQL
design and experiments in [FRONTIER_12.md](FRONTIER_12.md) improve a measured
capability beyond relevant baselines. This review is not an exhaustive priority,
patent, or legal novelty determination.

## Implemented boundary

This change builds UQL NEXT language/IR 0.2, package `1.2.0.dev0`. It does not
rename QTL (Quantum Theta Language) or QHL (Quantum Holographic Language), invent
their semantics, or implement the speculative interpretation of those names in
the proposal. It supplies no hardware attestation, deployed PROOF-369 ledger,
royalty routing, independent certification, physical error correction, quantum
network, or QIR/MLIR optimization infrastructure.

The existing LICENSE and contributor/IP documents remain authoritative and are
unchanged. The Seal of Eotu is user-designated visual identity; its presence and
hash do not certify a computation or establish trademark registration.
