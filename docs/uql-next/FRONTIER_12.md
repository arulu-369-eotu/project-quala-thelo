# UQL research frontier: first twelve capabilities

Research date: October 22, 2026, America/Detroit. These are twelve proposed
UQL-specific research integrations. No item below has been established as
unprecedented. The contribution to test is the particular contract, evidence
interface and measurable behavior, rather than the general idea's name.

Bounded precursors to 01, 02 and 03 exist in this change's `compare`, digest and
receipt tools. The complete capabilities below remain proposed. Features
04..12 are not implemented by adding their names to a manifest.

## 01 — Observation-scoped semantic passports

Give every comparison an explicit relation: exact premeasurement unitary,
unitary up to one global phase, channel, instrument or selected classical
observations. Bind basis ordering, ancilla conventions, input assumptions and
output interpretation to the comparison identity. Two artifacts can share an
observed distribution while differing as reusable controlled subroutines.

**Research delta:** make the observation contract executable across source, IR,
target interfaces and evidence exchange; prohibit reusing a certificate under a
stronger relation. **First experiment:** I and Rz(2*pi) agree on zero-input
measurements but fail exact-unitary comparison; incorrect output permutations
fail distribution comparison. **Gate:** all relation-confusion mutations are
rejected. Existing [QCEC](https://mqt.readthedocs.io/projects/qcec/en/latest/) and
the [assurance-contract survey](https://arxiv.org/abs/2610.00255) make this a
specific interface-engineering research question, not a new equivalence theory.

## 02 — Counterexample-producing compilation

When a transformation disagrees with its contract, emit the source/target pair,
first failing pass, precise relation, discrepancy, reproducer and a reduced
test. For distribution failure, include a distinguishing input/measurement
when one is found; otherwise say only what discrepancy was established.

**Research delta:** preserve witnesses through lowering and minimize failures
without invalidating their type, layout or input preconditions. **First
experiment:** seed a wrong CX direction, measurement permutation and Rz sign;
reduce each failure while replaying it on a second checker. **Gate:** report
detection rate, minimality criterion, reduction cost and independently replayed
failures. [CertiQ](https://arxiv.org/abs/1908.08963), QCEC and October 2026's
[RetroQ](https://arxiv.org/abs/2610.11195) are relevant comparison points.

## 03 — Coherent-context rewrite obligations

Track whether a reusable subroutine may later be coherently controlled. A
rewrite that preserves only projective equivalence must carry its phase delta
and either restore it in a controlled context or fail the stronger contract.

**Research delta:** propagate context obligations across independently compiled
modules and cache entries, including exact phase and ancilla interfaces. **First
experiment:** compare controlled-I with controlled-Rz(2*pi) under interference;
ensure a projective certificate cannot authorize the substitution. **Gate:**
every context-lifting mutation either gets phase compensation or is rejected.
[OpenQASM's global-phase semantics](https://openqasm.com/versions/3.0/language/gates.html)
already explains the physical issue. The proposed novelty is enforcing it
through the UQL evidence/module interface, not discovering global phase.

## 04 — Qudit-to-qubit semantic bridges with leakage evidence

Represent mixed local dimensions explicitly and lower a d-level logical system
through a declared isometry into an available physical encoding. Record unused
states, decoding rules, measurement interpretation and leakage conditions.

**Research delta:** issue relation-specific bridge evidence that remains valid
through optimization and comparison, including mismatched native dimensions.
**First experiment:** embed one qutrit into two qubits, implement cyclic shift
and a phase operation, compare all logical basis states and coherent
superpositions, and inject an operation entering |11>. **Gate:** preserve the
logical transformation within the declared tolerance and detect injected
leakage. [QudCom](https://arxiv.org/abs/2311.07015) and
[MQT Qudits](https://www.cda.cit.tum.de/files/eda/2024_mqt_qudits.pdf) already compile
qudit systems; this is a proposed cross-representation assurance layer.

## 05 — Composable approximation budgets

Treat approximation as a typed obligation with a named metric, composition
rule and assumptions. Keep approximation error, model uncertainty, hardware
noise and sampling confidence in separate quantities; combine them only under
a valid theorem or explicitly chosen conservative model.

**Research delta:** produce checkable budget derivations alongside each lowering
step and invalidate estimates when their assumptions change. **First
experiment:** synthesize a short rotation sequence under a channel-distance
budget and compare conservative composed bounds with exact small-channel
calculations. **Gate:** no unsound budget acceptance on the adversarial suite;
report bound tightness and synthesis cost. [Error-crafted synthesis](https://www.nature.com/articles/s41534-025-01032-x)
already studies channel-distance-aware synthesis. A guessed fidelity number is
not an acceptable substitute for this work.

## 06 — Calibration-conditional compilation and revalidation

Attach the exact target description, calibration snapshot, uncertainty model,
validity conditions and decision dependencies to a compilation plan. When data
changes, recompute only the evidence whose assumptions depended on it.

**Research delta:** distinguish changed bytes, changed optimization choices,
changed semantic guarantees and expired physical predictions. **First
experiment:** compile under two archived calibrations with identical source;
change one gate-error assumption and check which plan/evidence nodes become
stale. **Gate:** selective invalidation agrees with a full rebuild, while
mathematical identities remain valid. This extends, rather than invents,
[calibration-aware analysis](https://riunet.upv.es/entities/publication/b5148d56-2afa-4556-853d-6aa7fa3b1dc1)
and [transpilation-drift CI](https://arxiv.org/abs/2608.08248).

## 07 — Evidence-guided uncomputation and ancilla reuse

Let the compiler reclaim a temporary qubit only when its value can be
uncomputed under explicit dependency and lifetime conditions. Record which
quantum/classical information must remain available and how reuse changes
space, depth and approximation budgets.

**Research delta:** carry dischargeable lifetime/resource obligations into the
bundle so another checker can replay reclamation decisions. **First
experiment:** compile reversible arithmetic with early/late uncomputation and
then destroy a required dependency before cleanup. **Gate:** correct reduced
states and no unsafe reuse; quantify the space/depth frontier.
[Qurts](https://arxiv.org/abs/2411.10835) and
[modular uncomputation synthesis](https://www.sri.inf.ethz.ch/publications/venev2024modular)
already address sophisticated lifetime and synthesis problems. UQL must compete
on the integrated evidence contract, not claim automatic uncomputation first.

## 08 — Timed entanglement ownership contracts

Make a network entanglement resource have endpoints, single-use ownership,
classical acknowledgment dependencies, modeled quality and expiry. Model
loss, delay, timeout, retries and consumed pairs as explicit protocol outcomes.

**Research delta:** combine linear ownership with time/quality obligations and
replayable distributed traces without implying faster-than-light messaging.
**First experiment:** simulate teleportation under delayed messages and expired
pairs; reject double consumption and recover from a timed-out attempt. **Gate:**
protocol safety under the modeled faults, plus clearly stated liveness
assumptions. [NetQASM](https://repository.tudelft.nl/record/uuid%3A49ee016f-8ce2-4cc9-b07d-674dd631e3ad)
and July 2026's [Qoreo](https://arxiv.org/abs/2607.20391) already provide substantial
network-programming machinery, including verified choreography work in Qoreo.

## 09 — Certified logical-code transitions

Compile changes between declared logical encodings as typed transformations,
with encoding/recovery interfaces, logical-observable correspondence, leakage
conditions, decoder configuration and model-dependent resource/error evidence.

**Research delta:** a reusable transition certificate tying the logical channel
and code boundary to exactly the physical schedule and noise model evaluated.
**First experiment:** use small toy codes and exhaustive logical-state tests;
deliberately swap a logical observable or decoder convention. **Gate:** verify
the intended logical map on the code subspace and detect the mutations before
attempting larger codes. [CUDA-Q Logical](https://arxiv.org/abs/2609.13388) already
addresses heterogeneous QEC lowering and provenance, so UQL needs a demonstrable
interoperable transition-checking result. No surface-code reliability claim
follows from a successful ideal toy-code experiment.

## 10 — Branch-sensitive quantum/classical interfaces

Describe adaptive computation as a quantum instrument with classical outcomes,
branch conditions, bit layouts, parameter bindings and host/device lifetimes.
Do not flatten distinct branches into a final histogram and call it equivalent.

**Research delta:** certify the delivered adaptive interface across host code,
OpenQASM/QIR profiles and evidence, including postselection and missing outcomes.
**First experiment:** compare a measurement-conditioned correction with a faulty
branch implementation that matches an aggregate histogram on one input.
**Gate:** branch and interface contracts expose the defect; unsupported backend
profiles fail explicitly. [QIR profiles](https://github.com/qir-alliance/qir-spec/blob/main/specification/profiles/Base_Profile.md)
and [OpenQASM classical control](https://openqasm.com/versions/3.0/language/classical.html)
provide foundations; this is a proposed cross-interface assurance extension.

## 11 — Policy-constrained Pareto plans with decision receipts

Generate a declared finite set of execution plans and explain each elimination:
semantic mismatch, unsupported capability, exceeded budget, stale assumption or
domination by another candidate. A cheap but untrusted plan must not become an
automatic fallback for an attested execution requirement.

**Research delta:** checkable local decision certificates connecting policy and
multi-objective planning, rather than opaque scoring. **First experiment:**
enumerate a small plan set and check every feasibility/dominance decision with
an independently written verifier. **Gate:** correct frontier over that set,
stable tie rules and no policy downgrade; no claim of global optimality.
[Existing Pareto compilation](https://portal.fis.tum.de/en/publications/achieving-pareto-optimality-in-quantum-circuit-compilation-via-a-/)
is direct prior art for optimization; the policy/evidence interaction is the
candidate UQL extension.

## 12 — Verifier-diversity and change-attribution laboratory

Record which parsers, lowering paths, runtime libraries, rule sets and numerical
engines each check shares. Multiple green adapters with one faulty shared
translation do not become independent proof by vote. Use controlled mutations
and revision replay to separate fault detection from causal attribution.

**Research delta:** machine-readable dependence and observation coverage
attached to claims, plus reproducible mutation experiments that expose common
failure modes. **First experiment:** corrupt a shared output-map interpretation;
show which nominally different backends agree incorrectly and which interface
checker catches it. **Gate:** disclose common dependencies, quantify mutation
detection and reject unsupported independence labels. The
[assurance-contract survey](https://arxiv.org/abs/2610.00255),
[RetroQ](https://arxiv.org/abs/2610.11195) and
[SLSA provenance](https://github.com/slsa-framework/slsa/blob/main/spec/build-provenance.md)
are relevant foundations; none is treated as a certification of UQL.

## What would justify a stronger claim

For each track: freeze the precise contribution, publish an implementable
specification within the intended public scope, compare against named current
baselines, release reproducible experiments, record failure/inconclusive cases,
and obtain independent reproduction before upgrading the evidence status.
Priority claims require a deeper literature search on the exact mechanism.
Public UQL work must not disclose unrelated proprietary system internals.
