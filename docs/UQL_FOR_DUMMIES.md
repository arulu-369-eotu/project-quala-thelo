# UQL for Dummies

## A beginner's manual to the public research core and Learning Lab

**Edition 1.0 · November 8, 2026 · Public-source scope**

You do not need to be a quantum physicist to start here. You do need to keep
one useful habit: ask what an example actually demonstrates before deciding
what it proves.

This manual explains the Python research components available in
`project-quala-thelo` and introduces an additive local Learning Lab. It was
prepared from the public `main` baseline
[`81a515e`](https://github.com/arulu-369-eotu/project-quala-thelo/tree/81a515e36c35ddd28ad00096442db874d67bb5ab),
whose Python package declares version `1.1.0`. The Lab is an addition to that
baseline; this manual does not declare a new production or Community release.

**Scope:** public UQL interfaces, general background, original synthetic
examples, and local diagnostic results. QTL, QHL, UQL Master, private research,
operational integrations, and private infrastructure are outside this guide.
No restricted implementation or private design document was used to write it.

**License:** the repository remains governed by [LICENSE](../LICENSE).
Its EL-SOCL v1.0 terms restrict commercial and institutional use. Public
visibility does not turn this repository into an unrestricted open-source
Community distribution. This manual and the Lab create no additional license
grant, change of ownership, or entitlement to separately held IP.

## Contents

1. [What you can learn here](#1-what-you-can-learn-here)
2. [The public and proprietary boundary](#2-the-public-and-proprietary-boundary)
3. [The vocabulary in plain language](#3-the-vocabulary-in-plain-language)
4. [Find your way around](#4-find-your-way-around)
5. [Set up a learning environment](#5-set-up-a-learning-environment)
6. [Your first working Python exercise](#6-your-first-working-python-exercise)
7. [Use the UQL Learning Lab](#7-use-the-uql-learning-lab)
8. [Read the public API](#8-read-the-public-api)
9. [Understand tests and current limitations](#9-understand-tests-and-current-limitations)
10. [Practice and check your understanding](#10-practice-and-check-your-understanding)
11. [Contribute while preserving the boundary](#11-contribute-while-preserving-the-boundary)
12. [Preserve a useful record](#12-preserve-a-useful-record)

## 1. What you can learn here

UQL is the project name used by the public `uql-omniversal-compiler` package.
The reviewed `main` implementation exposes Python objects for architecture
declarations, memory-buffer handling, a coherence model, dynamical-decoupling
scheduling, surface-code construction, and experimental hybrid key exchange.

Think of this checkout as a research workbench: several components can be
examined and exercised individually. Their presence in one package does not
establish that they form a complete secure application.

There is an important version distinction. The reviewed baseline does not
provide a UQL text parser, a `.uql` command-line compiler, or a `uql` executable.
This guide therefore teaches the Python interfaces that are present. It does
not invent language syntax. The separate UQL NEXT work in
[draft PR #3](https://github.com/arulu-369-eotu/project-quala-thelo/pull/3)
has its own review and release hold; this addition does not merge or republish
that branch's implementation.

By the end, you should be able to:

- Run a small Python exercise using the current public API.
- Distinguish a declared property from an observed result.
- Explore a simple coherence model with controlled inputs.
- Read a diagnostic report without mistaking it for a certification.
- Recheck a report's contents, compare public source fingerprints, and replay
  the named experiments.
- Explain which components remain blocked or outside the experiment.

For a quick introduction, read Sections 1–4 and 9. For hands-on learning,
continue through Sections 5–7. For a teaching session, use the exercises in
Section 10 and keep each learner's report local.

## 2. The public and proprietary boundary

This tutorial adds explanations and a bounded educational tool. It does not
expand the release boundary of the surrounding research project.

| Material | Treatment in this manual and Lab |
| --- | --- |
| Existing public Python interfaces on the reviewed `main` baseline | Explain and call selected interfaces with synthetic inputs. |
| General quantum-computing and software-testing concepts | Explain at an introductory level. |
| New teaching examples and Lab code | Included under the existing repository terms. |
| QTL, QHL, UQL Master, and separately restricted research | Excluded; names identify the boundary only. |
| Private services, credentials, customer data, deployment details, or unreleased integration designs | Excluded. |
| UQL NEXT and other pending branch implementations | Remain separate; no branch merge or release approval is implied. |
| Existing license and IP notices | Preserved; read them before use or redistribution. |

The Lab hashes an explicit list of public source files to identify its inputs.
It does not search folders for private research, read arbitrary source paths
from a report, inspect key material, or connect to a remote service. Its one
subprocess reads the local Git revision for provenance; it performs no Git
write or network operation.

The broader repository has historical research material and pending boundary
work. [PR #4](https://github.com/arulu-369-eotu/project-quala-thelo/pull/4)
records a separate Community release-boundary proposal. Its draft status is
preserved. This tutorial does not clear the whole repository for a future
open-source distribution. Material already present in public history requires
its own review; a new manual cannot undo earlier publication.

## 3. The vocabulary in plain language

| Term | Working explanation |
| --- | --- |
| Bit | A classical value represented as 0 or 1. |
| Qubit | A quantum system described by amplitudes for measurement outcomes. It is not a free container for reading many classical answers simultaneously. |
| Gate | An operation on one or more qubits. |
| Circuit | A sequence of quantum operations, sometimes including measurement and reset. |
| Simulator | Classical software that models specified quantum behavior. Simulation does not establish how a physical device will perform. |
| Backend | The software simulator or hardware execution target used for a circuit. |
| Compiler | Software that translates or transforms a program into another representation or execution form. The package name alone does not tell you which language features are implemented. |
| Coherence | A description of how quantum-state information persists under a chosen model or measurement procedure. |
| Dynamical decoupling (DD) | Carefully timed operations intended to reduce some idle-time noise effects. A timing model and actual hardware behavior both matter. |
| Quantum error correction (QEC) | Encoding and checking quantum information so specified errors can be detected and, with suitable decoding and operations, corrected. |
| Stabilizer check | A check associated with a quantum code. Compatible checks must satisfy the required commutation conditions. |
| Key establishment | A procedure for obtaining shared secret material. It does not by itself supply authenticated messaging, secure storage, or a complete network protocol. |
| Evidence | A record of a particular observation or test, with enough context to understand its limits. |

Three distinctions will save you time:

1. A declaration states an intention or label.
2. An implementation supplies a mechanism.
3. A test observes selected behavior under stated conditions.

Each step needs its own evidence. One passing test cannot silently stand in
for all three.

## 4. Find your way around

These are the paths needed for this guide. Other research compartments are
not part of the tutorial's source set.

| Path | Why you would open it |
| --- | --- |
| [README.md](../README.md) | Project entry point and governance links. |
| [LICENSE](../LICENSE) | Existing permissions and restrictions. |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Contribution and disclosure expectations. |
| [citadel-core/pyproject.toml](../citadel-core/pyproject.toml) | Python package name, dependency ranges, and test settings. |
| [architecture.py](../citadel-core/uql_compiler/architecture.py) | Declaration and manifest objects. |
| [memory.py](../citadel-core/uql_compiler/memory.py) | Buffer wiping and reported OS memory capabilities. |
| [dd.py](../citadel-core/uql_compiler/dd.py) | Coherence model and DD scheduling interface. |
| [qec.py](../citadel-core/uql_compiler/qec.py) | Surface-code object and validation interface. |
| [citadel-core/tests/](../citadel-core/tests/) | Existing public-core regression tests. |
| [tools/uql_learning_lab.py](../tools/uql_learning_lab.py) | The new local experiment and report tool. |
| [tests/test_uql_learning_lab.py](../tests/test_uql_learning_lab.py) | Separate acceptance tests for the Lab. |

Run the commands below from the repository root unless a step says otherwise.

## 5. Set up a learning environment

### Supported starting point

Use Linux and Python 3.11, 3.12, or 3.13 for the documented package workflow.
Those Python versions appear in the existing CI matrix. The validation
reported in this manual used Python 3.12.14 on Linux.

The native crypto subsystem documents an OpenSSL 3.5+ requirement. Package
imports eagerly load native crypto bindings along with the other components,
so missing native dependencies can affect even a non-crypto tutorial import.
The native secret-allocation path also requires Linux memory-locking and
dump-exclusion capabilities.

On a Mac, use a Linux virtual environment at the operating-system level, such
as a Linux VM, for this package workflow. A Python virtual environment alone
does not turn macOS into Linux. This edition does not claim a verified native
macOS or Windows package workflow.

### Install from the repository

If you already have the repository, open its root and skip the first two lines.

```bash
git clone https://github.com/arulu-369-eotu/project-quala-thelo.git
cd project-quala-thelo
python3 --version
openssl version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e './citadel-core[test]'
```

The brackets select the package's test dependencies. Editable installation
makes imports refer to this local checkout. Dependencies are version ranges,
so another installation can resolve different versions; keep that difference
in mind when comparing results.

Check that the public package can be imported:

```bash
python -c "from uql_compiler import CoherenceModel; print(CoherenceModel(100, 80).effective_coherence_us)"
```

Expected output:

```text
80
```

An OpenSSL command-line version does not guarantee that Python's native loader
will find the same library. If an import fails with a missing library or
symbol, diagnose the environment before using the Lab's results. Do not change
system library links or weaken memory controls simply to suppress an error.

### Read and verify without installing the research package

The Lab's `--help` and report-verification commands use the Python standard
library. They can run from a full checkout without importing UQL or its
third-party dependencies. Running experiments without the package installed
will report blocked imports rather than demonstrate working UQL capabilities.
Replay requires the dependencies needed by the original experiments.

## 6. Your first working Python exercise

Save the following as a temporary `uql_first_steps.py` file and run it with
the activated environment's `python`. It uses dummy bytes, a simple numerical
model, and public object construction. It neither handles real secrets nor
executes on quantum hardware.

```python
from uql_compiler import (
    ArchitectureDeclaration,
    CompilerManifest,
    CoherenceModel,
    LockedBuffer,
    SurfaceCode,
)

architecture = ArchitectureDeclaration(
    name="Beginner local exercise",
    version="1",
    mechanisms=(),
    security_properties=(),
)
manifest = CompilerManifest(architecture)
print("Unrun example verified:", manifest.is_verified("unrun-example"))

with LockedBuffer(b"DEMO") as buffer:
    print("Synthetic buffer length:", len(buffer))
    buffer.wipe()
    print("Synthetic buffer wiped:", bytes(buffer.view()) == b"\x00" * 4)

model = CoherenceModel(t1_us=100.0, t2_us=80.0)
print("Effective coherence (us):", model.effective_coherence_us)
print("Model survival at 10 us:", f"{model.survival_fraction(10.0):.6f}")

code = SurfaceCode(distance=3)
print("Constructed surface parameters:", code.parameters)
print("Constructed ancilla count:", code.num_ancillas)
```

Expected output in the validated environment:

```text
Unrun example verified: False
Synthetic buffer length: 4
Synthetic buffer wiped: True
Effective coherence (us): 80.0
Model survival at 10 us: 0.882497
Constructed surface parameters: (9, 1, 3)
Constructed ancilla count: 8
```

What did you learn?

- The manifest starts without verified mechanisms. Its membership check does
  not execute a security test.
- The named buffer's dummy bytes can be overwritten. This does not establish
  that every copy elsewhere in a Python process has been erased.
- The coherence method returns a model prediction for supplied numbers.
- The surface object exposes counts. Constructing it does not validate the
  code's mathematical checks or establish fault tolerance. The reviewed
  baseline's validation failures are recorded in Section 9.

`LockedBuffer.status` separately reports whether OS locking and dump exclusion
were established. The demonstration above does not require those flags to be
true, and its printed wipe result must not be described as proof of an
isolated hardware enclave.

## 7. Use the UQL Learning Lab

The Lab turns selected public APIs into a repeatable learning session with
bounded inputs and an inspectable report. It adds no private-language syntax,
remote service, new cryptographic protocol, or hardware integration.

### Run a comparison

```bash
python tools/uql_learning_lab.py run --compare-t2-us 120 --output /tmp/uql-learning-report.json
```

The output file must not already exist. Choose a new filename for another
session; the tool refuses to overwrite an existing file or symlink. Omit
`--output` when you only want the on-screen summary.

By default the reference scenario uses T1 = 100 microseconds and T2 = 80
microseconds. `--compare-t2-us 120` changes T2 for a second scenario while
keeping T1 fixed. The current public model uses:

`effective_coherence_us = min(t1_us, t2_us)`

`survival_fraction = exp(-idle_us / effective_coherence_us)`

The result at 80 microseconds is approximately `0.367879` for the reference
and `0.449329` for the comparison. These are mathematical outputs from the
implemented model. They are not measured device survival probabilities, a
noise characterization, or a demonstration that a particular physical change
will improve a device by that amount.

### Understand each record

| Record | What a pass covers | Limits |
| --- | --- | --- |
| `declarations` | A new manifest leaves an unrun example unverified. | No architecture or security audit. |
| `memory` | A four-byte dummy buffer is wiped; OS capability flags are recorded. | No process-wide erasure, hardware isolation, or resistance to a privileged attacker is established. |
| `coherence` | The public numerical model returns the requested curve or curves. | No hardware measurement or empirical optimization. |
| `surface` | The selected public object's existing `validate()` method returns, and counts are recorded. | Even a pass would not establish a decoder's performance or circuit-level fault tolerance. |
| `dd` | A one-qubit synthetic idle-window example produces at least two X operations. | No hardware noise reduction, timing certification, or general circuit equivalence proof. |
| `crypto` | Always `not_run` in this Lab. | No key generation, key exchange, secret export, or cryptographic validation is attempted by the Lab. |

A blocked record includes an exception class rather than a traceback or
memory contents. In the reviewed Linux environment the Lab reported
`declarations`, `memory`, and `coherence` as passed; `surface` and `dd` as
blocked; and `crypto` as not run. Consult the core tests for detailed diagnosis.

### Check and replay the record

```bash
python tools/uql_learning_lab.py verify /tmp/uql-learning-report.json
python tools/uql_learning_lab.py verify /tmp/uql-learning-report.json --replay --require-pass coherence --require-pass memory
```

Verification checks the supported format, bounded values, result consistency,
the report's SHA-256 digest, and the exact allowlisted public source-file
hashes in this checkout. It rejects duplicate JSON keys, non-finite numbers,
unknown fields, and files larger than 256 KiB. Some observations have additional
consistency checks, including recomputing the simple coherence curve.

`--replay` reruns the public exercises using the recorded inputs and compares
their observations. It does not recreate an entire old operating system or
dependency environment. A different memory-lock capability or repaired
component can legitimately change a result and make replay comparison fail.
The recorded Git revision describes the run's checkout; the exact file hashes
identify the allowlisted contents, including local edits. A Git revision alone
does not establish that a worktree was clean.

`--require-pass NAME` supplies a narrow acceptance gate. If a required check
was blocked or not run, verification exits with code 2. For example, requiring
`crypto` always fails in this edition. `run` exits with code 0 when a valid
session/report is produced, even when some capabilities are blocked; read the
per-check statuses before deciding whether an experiment met your goal.

**Trust limit:** a digest can detect an edit when the stored digest is not also
replaced. Anyone able to rewrite a report can calculate another digest.
The report is self-reported local evidence, not a signature, trusted identity,
timestamp service, independent attestation, or proof that the original author
executed its claimed checks. Replay supplies a fresh local observation, with
the same scope limits as the named exercises.

### Change the inputs

```bash
python tools/uql_learning_lab.py run --t1-us 100 --t2-us 80 --compare-t2-us 120 --idle-us 0 20 80 160 --distance 3
```

Times are microseconds. T1 and T2 must be finite, positive, and at most
1,000,000. Idle times must be finite and between 0 and 1,000,000; a run accepts
1–64 idle values. Surface distances are limited to 3, 5, 7, or 9. These bounds
keep the educational workload predictable; they are not hardware calibration
or physical-validity checks.

## 8. Read the public API

Use the source and tests for exact contracts. This table is a reading guide.

| Public entry point | Role | Beginner interpretation |
| --- | --- | --- |
| `ArchitectureDeclaration(...)` | Stores a name, version, mechanisms, and security-property labels. | A description of intent. |
| `CompilerManifest(architecture, verified_mechanisms=...)` | Stores verification labels. | `is_verified()` checks membership; it does not audit evidence. |
| `LockedBuffer(initial, require_lock=False)` | Handles a mutable buffer and reports OS memory capabilities. | Use dummy data while learning; inspect status separately from wipe behavior. |
| `CoherenceModel(t1_us, t2_us)` | Supplies the simple coherence calculation used here. | A deliberately limited model with explicit units. |
| `DDConfig(...)` | Holds DD timing and budget settings. | Settings require validation against the chosen software and execution target. |
| `build_dd_pass_manager(...)` | Builds the public DD pass-manager path. | The reviewed baseline has a dependency-interface failure. |
| `SurfaceCode(distance)` | Constructs a surface-code object and exposes validation/circuit interfaces. | Counts, compatible checks, decoder quality, and fault tolerance are separate questions. |
| `HybridRecipient` / `HybridKeyExchange` | Expose the experimental public hybrid key-establishment interface. | Existing baseline regression tests fail; do not treat this guide as a secure messaging recipe. |
| `HybridCiphertext` | Wraps a fixed-size serialized public ciphertext representation. | Length acceptance does not establish authentication or successful key establishment. |

The public crypto code names X25519, ML-KEM-1024, and HKDF-SHA-512. Those names
describe components present in the repository; they do not establish that the
combined implementation is secure, standardized as a whole, or independently
certified. The Lab deliberately does not exercise this subsystem.

This guide provides no method for exporting or dereferencing native secret
handles. A native handle and OS memory controls should not be interpreted as
hardware-backed attestation or complete process isolation.

## 9. Understand tests and current limitations

Run the original public-core suite from the repository root:

```bash
python -m pytest -q citadel-core/tests
```

At baseline `81a515e`, the execution used for this manual produced **3 passed
and 5 failed**, with no skipped tests. The environment was Linux, Python
3.12.14, OpenSSL 3.5.7, Qiskit 2.6.2, Cirq Core 1.7.0, cryptography 50.0.2, and
pytest 8.4.2. These are recorded observations, not a guarantee that every
environment will fail in exactly the same way.

| Area | Observed result | Consequence for this guide |
| --- | --- | --- |
| Memory tests | Both passed. | The dummy-buffer exercise is included with its stated limits. |
| DD spacing normalization | Passed. | A helper calculation works; that does not validate the scheduling path. |
| Hybrid key agreement and context binding | Two failures at the existing HKDF info-limit path. | No successful exchange or cryptographic-security claim. |
| DD scheduling | One failure because the installed Qiskit interface rejects `spacings`. | The Lab records a blocked DD check. |
| Surface-code validation/circuit construction | Two failures because X/Z stabilizers do not commute. | Counts are not promoted into a valid-code or fault-tolerance claim. |

The new Lab is tested separately:

```bash
python -m unittest discover -s tests -p test_uql_learning_lab.py -v
```

Its acceptance tests cover report generation and replay, model comparisons,
tampering and source mismatches, invalid inputs, strict JSON handling,
bounded report sizes, source allowlisting, refusing overwrites, and refusing
to promote untested crypto into a passing result. They do not repair or replace
the original core tests. The preparation run completed **16 Lab tests passed,
with no failures or skips**, including verification without third-party
imports and honest blocked results when package dependencies are absent.

Pending repairs and language work already have their own branches and review
history. This addition changes neither those branches nor the existing
cryptographic, DD, or QEC implementations. It does not certify a production
system or approve a Community release.

### Troubleshooting

| Symptom | Next action |
| --- | --- |
| `ModuleNotFoundError` for `uql_compiler` | Activate the environment where the editable package was installed; check that installation completed. |
| Missing Cirq or Qiskit | Recheck the package installation and dependency-resolution output. |
| Native library or symbol error during import | Check the actual native library selected in the Linux environment; the OpenSSL CLI alone is insufficient evidence. |
| `surface` or `dd` is blocked on the reviewed baseline | Compare with the known failures above. A report containing a blocked status is still an honest report. |
| Memory status says locking or dump exclusion is unavailable | Record the limitation. A wipe observation does not override a missing OS capability. |
| Output file already exists | Use a new filename; the Lab will preserve the existing file. |
| Report digest mismatch | Treat the file as changed or invalid; do not edit the verifier to accept it. |
| Public-source fingerprint mismatch | Use the matching reviewed checkout or generate a fresh report for the changed sources. |
| Replay observations differ | Inspect dependency versions, source contents, and current OS capability. Retain the old report for comparison. |
| A required check was not passed | The acceptance gate is working. Resolve the blocked capability or explicitly choose a narrower learning goal. |

## 10. Practice and check your understanding

### Exercise A: Find the model's bottleneck

Run the Lab with T1 = 100, T2 = 120, and comparison T2 = 240. Use idle times
0, 20, and 80 microseconds. Predict whether the two curves will differ.

**Answer:** they match in this model because both effective coherence values
are capped by T1 = 100. This teaches a property of the implemented formula;
it does not establish that changing a physical device's T2 will leave all its
other behavior unchanged.

### Exercise B: Test input rejection

Try T1 = 0, then try `nan`. Both must be rejected with exit code 2 before any
experiment runs or report is created. A rejected input is not a successful
hardware or security test; it is evidence of input validation.

### Exercise C: Ask a narrower question

Generate a report and verify it with `--require-pass coherence`. Then verify
the same report with `--require-pass crypto`.

**Answer:** the first succeeds when the public model ran; the second fails
because crypto was not run. The existence of a valid report cannot substitute
for a required experiment.

### Exercise D: Observe tampering

Make a copy of a local report. Change one recorded runtime version without
changing its digest, then verify the copy. Verification must reject it. Keep
the original file for replay.

**Answer:** this demonstrates a consistency/integrity check, not an
unforgeable authorship mechanism. Someone who controls the entire file can
replace both its contents and digest.

### Exercise E: Explain a surface-code result accurately

Your first Python exercise printed `(9, 1, 3)`. A colleague asks whether that
proves a functioning distance-three fault-tolerant memory.

**Answer:** the printed tuple is an object parameter. The baseline's own
stabilizer validation fails, and the demonstration did not evaluate a decoder,
noise model, logical error rate, or hardware implementation.

## 11. Contribute while preserving the boundary

Start with [CONTRIBUTING.md](../CONTRIBUTING.md) and [LICENSE](../LICENSE).
Useful beginner contributions include clearer explanations, reproducible
synthetic examples, narrowly scoped bug reports, and regression tests tied
to observed behavior.

For this educational layer:

1. Work from public interfaces and synthetic fixtures. Keep a short source
   list for new explanations and examples.
2. Keep QTL, QHL, UQL Master, private research, private endpoints, credentials,
   customer data, and restricted integration designs out of changes and
   screenshots. Do not translate private designs into public pseudocode.
3. Do not copy another branch wholesale to make an example work. Preserve
   each branch's existing review and release boundaries.
4. Preserve license and authorship notices. Do not describe this mixed-scope
   repository as an unrestricted Community distribution.
5. Review the actual changed-file list, generated files, and built artifacts
   before publication. Do not commit local reports merely because they are JSON.
6. Run the appropriate tests and retain their real results, including
   failures. Record dependency and source versions when they affect behavior.

The Lab's source allowlist is explicit in `SOURCE_PATHS`. Expanding it should
be a deliberate public-scope change. Reports cannot supply additional file
paths for the tool to read.

If you encounter material that may have been disclosed unintentionally,
contact the maintainers through an appropriate private channel. Avoid
reproducing it in a public issue. Editing a current file does not retract its
earlier public history.

## 12. Preserve a useful record

The existing [LICENSE](../LICENSE) names **Eotu Labs WhaleWorks LLC / Harold
Hakeem Stone-Mayfield** in its copyright notice. This guide preserves that
existing attribution and makes no new ownership assignment or priority claim.

A future reader should be able to answer four questions:

- Which source revision and files were involved?
- What inputs and environment were used?
- What actually ran, passed, failed, or remained untested?
- What rights and release boundaries applied?

The Lab records selected runtime metadata, exact allowlisted file hashes,
inputs, and per-exercise results. Git history supplies the repository's change
record. Neither mechanism alone establishes invention priority, independent
validation, or permanent preservation.

For an approved future release, preserve its reviewed source, documentation,
test results, dependency information, and rights notices together. Keep
restricted research separately governed. The value of the record comes from
letting another person reproduce and assess the work within those boundaries.

### Public sources for this edition

- The baseline [package manifest](https://github.com/arulu-369-eotu/project-quala-thelo/blob/81a515e36c35ddd28ad00096442db874d67bb5ab/citadel-core/pyproject.toml),
  [public API exports](https://github.com/arulu-369-eotu/project-quala-thelo/blob/81a515e36c35ddd28ad00096442db874d67bb5ab/citadel-core/uql_compiler/__init__.py),
  and their public implementation files.
- The baseline [regression tests](https://github.com/arulu-369-eotu/project-quala-thelo/tree/81a515e36c35ddd28ad00096442db874d67bb5ab/citadel-core/tests)
  and [CI matrix](https://github.com/arulu-369-eotu/project-quala-thelo/blob/81a515e36c35ddd28ad00096442db874d67bb5ab/.github/workflows/uql-ci.yml).
- The existing repository license and contribution/IP notices, interpreted
  here only to preserve their current scope.
- The public review-status notices on draft PRs #3 and #4, used only to
  identify work excluded from this addition.
- The new Lab source and acceptance tests linked in Section 4, plus the local
  execution observations recorded in Section 9.
