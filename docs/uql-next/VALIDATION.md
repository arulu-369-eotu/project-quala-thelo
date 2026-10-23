# Executed validation evidence

Scope: UQL NEXT language/IR 0.2 on upstream baseline
`81a515e36c35ddd28ad00096442db874d67bb5ab`. User-facing review date:
October 22, 2026, America/Detroit. Execution host reports UTC separately.

## Environment actually used

Linux x86_64; Python 3.12.14; pytest 8.4.2; Qiskit 2.6.1; Cirq 1.7.0;
qiskit-qasm3-import 0.6.0; llvmlite 0.50.0 (LLVM 22.1.0);
qirrunner 0.9.7; jsonschema 4.26.0. Python SSL reports OpenSSL 3.5.8;
the baseline native crypto's separately loaded provider capability is not
inferred from that value. No macOS or physical quantum hardware run occurred.

## Results

| Check executed | Result | Interpretation |
|---|---|---|
| `python -m pytest -q citadel-core/tests/next` | 96 passed | New bounded language, evidence and backend suite |
| Full `citadel-core/tests` suite | 99 passed, 5 failed | The same five baseline crypto/DD/QEC failures remain |
| JSON Schema checks and fixed Bell vector | Passed in new suite | Schema structure and stable normalized identities |
| Optimizer numerical checks | Passed in new suite | 12 seeded 3-qubit circuits, all 8 basis inputs, exact-amplitude comparison within tolerance |
| Qiskit/Cirq differential tests | Passed in new suite | 10 seeded circuits under the stated ideal output-distribution boundary |
| QIR LLVM validation | Passed in new suite | Five emitted randomized programs accepted by LLVM |
| QIR execution | Passed in new suite | Phase/order-sensitive deterministic case and 256-shot Bell sanity check |
| Bundle tampering and forged rehashed claim | Rejected in new suite | Integrity and local reproducibility; not publisher authentication |
| Source core with `python -S` | Passed in new suite | No site packages needed for parser/core import |
| Python wheel build | Passed | New subpackage, compare module and original seal are included |
| Installed-wheel CLI, from `/tmp` | Passed | Compile and verify a phase-sensitive example; Qiskit/Cirq comparison passes |
| `git diff --check` | Passed | No whitespace errors in tracked changes |

The installed-wheel test used `pip install --no-deps` after the required
validation SDKs were separately installed. An attempted full dependency
resolution encountered proxy timeouts for the pre-existing cryptography
requirement; a complete fresh-network installation is not established by
this run. The existing dependency bounds were preserved.

The new workflow declares Python 3.11/3.12/3.13 jobs. Their presence in YAML is
not evidence of completed hosted CI; see the PR's actual check status. Local
execution here establishes only Python 3.12 on Linux. Test artifacts generated
by another machine or verifier require their own identity and evidence.

## Existing failures

1. `test_native_hybrid_key_agreement`: native key generation fails in this host.
2. `test_context_binds_key`: same native capability failure.
3. `test_dd_inserts_timed_sequence`: Qiskit rejects `spacings` keyword.
4. `test_surface_code_is_single_logical_qubit`: X/Z stabilizers do not commute.
5. `test_surface_code_extracts_repeated_syndromes`: same validation failure.

These were observed before the language changes and reproduced with the new
suite present. No xfail marker, skip or weakening of the original tests was
introduced. Existing security PRs are separate work. This evidence does not
support calling the whole repository production-ready, formally proved,
hardware-secure or independently certified.
