# UQL NEXT implementation and release plan

The first milestone is a complete bounded implementation of the proposed twelve
foundational components. Broader language semantics advance through explicit
profiles; the number 2.0 is not a substitute for acceptance evidence.

| # | Foundation | Concrete implementation | Acceptance boundary |
|---|---|---|---|
| 1 | Specification 0.2 | SPECIFICATION-0.2.md | Defined grammar, constraints, semantics, errors and output ordering |
| 2 | AST schema | schemas/uql-ir-0.2.schema.json + model.py | Schema checks plus normative cross-field validation |
| 3 | Canonical IR | model.py | Stable restricted JSON bytes and strict reload |
| 4 | Deterministic identity | IR and circuit digest domains | Identity of the declared normal form; general equivalence excluded |
| 5 | OpenQASM lowering | emit.py | Import and execute ideal circuits through Qiskit |
| 6 | QIR lowering | emit.py | LLVM validation and actual qirrunner execution |
| 7 | Transformation receipts | passes.py + evidence.py | Exact local identities checked and edits replayed |
| 8 | Resource manifests | passes.py | Structural counts and enforced limits; physical estimates unknown |
| 9 | Evidence bundle | evidence.py | Deterministic rebuild; byte tampering and forged claims rejected |
| 10 | PROOF-369 adapter | proof369.json | Draft local format; external integration remains unavailable |
| 11 | Conformance laboratory | conformance/ + tests/next/ | Valid/invalid/golden/adversarial and target integration cases |
| 12 | Differential runner | simulate.py | Qiskit/Cirq/reference agreement under a named numerical boundary |

The Seal of Eotu is included in documentation, installed package data, each
bundle's visual identity record and each program passport. `compare.py` also
implements the first bounded experiments toward Frontier 01/02/03: choosing the
comparison relation can change the verdict, and a failed comparison reports a
specific discrepancy. It does not yet minimize failures or infer safe coherent
control contexts.

## Dependency sequence and acceptance gates

1. **Review this language milestone.** Run the new tests and installed-wheel smoke
   checks, inspect emitted targets, then reconcile the existing security PRs and
   baseline test failures separately. Do not merge merely because the new job is
   green.
2. **Establish comparison semantics.** Extend the current two relations with
   projective-unitary/channel/instrument interfaces, bit permutations, ancilla
   interpretation and explicit inconclusive outcomes. Required evidence: mutation
   corpus containing observationally equal but contextually different pairs.
3. **Add counterexample reduction and phase obligations.** Deliver reproducible
   failing artifact pairs, a declared minimization criterion and independent
   replay. Required evidence: seeded compiler faults and measured failure
   localization against QCEC/RetroQ-style baselines.
4. **Implement the qudit bridge.** Start with a qutrit embedded in two qubits;
   record isometry, unused-state behavior, output interpretation and leakage.
   Required evidence: all logical basis states and coherent superpositions.
5. **Formalize error and resource composition.** Select explicit channel metrics
   and noise assumptions. Required evidence: analytic bounds checked against
   exhaustive small-channel models; unknown assumptions cannot become zeros.
6. **Develop adaptive, network and QEC profiles.** Each needs its own type/effect
   rules, operational semantics, failure model and conformance corpus. Terminal
   circuit support must not be advertised as support for these profiles.
7. **Connect external assurance.** Supply actual PROOF-369/Kundalini Kali and
   ABRAXAS interfaces; implement signatures, verifier enrollment, revocation,
   freshness, replay rejection and witness protocols. Required evidence: tests
   using independently held keys and independently reproduced verification.

All twelve frontier tracks are specified in [FRONTIER_12.md](FRONTIER_12.md).
The first focused implementation sequence is 01 -> 03 -> 02 -> 04, then 05/07
before 08/09/10. Owners, funding and dates are unassigned; no schedule or hardware
availability is assumed. Experiments are compared against the prior art in each
track before claiming a distinct research result. Proposed functionality is not
included in the language 0.2 contract until implemented and validated.

## Release and rollback

This work belongs on an isolated draft PR against the inspected main commit.
Merge and publication require their own review; this task does not merge either
security PR or issue a release. Rollback is removal/reversion of the additive
UQL NEXT change; previously generated bundles retain their original version and
compiler-source digest and need that version to reproduce byte-for-byte.

Package discovery changes include the new subpackage. Original top-level API
names remain available through lazy imports. Existing mandatory dependency
bounds and native implementations are preserved, so the installed wheel still
declares the original SDK requirements. Running the core from source needs only
Python 3.11+. Full native crypto remains Linux/OpenSSL capability dependent.
