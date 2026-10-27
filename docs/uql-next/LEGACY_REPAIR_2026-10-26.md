# UQL NEXT legacy repair reconciliation — October 26, 2026

Status: locally validated repair; PR #3 remains a draft and release hold.
This is maintenance of the existing mixed-scope UQL NEXT research branch,
not a Community release, rights clearance, or production security certification.

## Source comparison

- PR #3 inspected head: `5a1a44f5c21bfea2c814529a19ca162318b54708`.
- PR #2 inspected head: `2fc4db7cf5892731eba299f62425a7b389b03bd2`.
- Both PRs were open drafts at inspection. Common base is main
  `81a515e36c35ddd28ad00096442db874d67bb5ab`.
- Run 39886697956: all three general CI jobs failed. The Python 3.12 job
  120196414492 logs confirm crypto key generation (two), DD API (one), and
  stabilizer commutation (two) failures; 81 passed and 18 optional tests skipped.
- Run 37962991634: PR #2 job 113930248652 succeeded using an Ubuntu 25.10
  container and an explicit ML-KEM support assertion. It was not a three-version
  matrix result and does not establish compatibility with PR #3.
- Local unmodified PR #3, Python 3.12.14 with all validation adapters installed:
  **99 passed, 5 failed**, reproducing the same five failure sites.

## Minimal reconciliation and compatibility decisions

| Area | Relevant PR #2 repair | Applied decision |
| --- | --- | --- |
| Native key generation | EVP_PKEY_CTX_new_from_name, keygen_init, keygen for ML-KEM-1024 | Ported; free X25519 and partial ML-KEM objects on keygen failure. No fallback to weaker algorithms. |
| HKDF transcript | Length-bound, domain-separated SHA-512 transcript hash, v2 HKDF domain, bounded context | Ported because keygen alone exposes the existing HKDF info-limit failure: a complete handshake transcript already exceeds 3200 bytes. Retained transient-buffer wiping. |
| Native secret API | PR #2 removes public pointer and changes its legacy test | Deliberately not ported in this repair. PR #3 public pointer and its original assertion are preserved. Pointer API hardening remains a separately reviewed compatibility change. |
| DD | Replace unsupported spacings with spacing and remove unsupported sequence_min_length_ratios | Ported supported spacing list. A small padding subclass retains min_idle_ratio using calibrated X durations rather than silently dropping the configuration policy. |
| QEC | Correct alternating boundary half-plaquettes | Ported exactly; original commutation validation remains enabled. |
| CI environment | PR #2 uses an ML-KEM-capable container | Keep PR #3 Python 3.11/3.12/3.13 matrix. Build isolated OpenSSL 3.5.4 pinned to upstream commit c1eeb9406b6142148f267594197d853403d10208; expose its libraries only to the job and assert ML-KEM availability. |

No textual conflicts existed in these three implementation files: PR #3 had
not changed them relative to main. The conflicts above are semantic/API and
runtime-environment decisions. A wholesale merge/cherry-pick of PR #2 would
also import unrelated enterprise, memory, assurance, documentation and workflow
work; none of that is included here. The original tests are byte-for-byte unchanged.

The v2 KDF intentionally derives different keys from a v1 transcript and has no
v1 fallback. Both peers must use the v2 implementation. This repair does not add
wire-version negotiation, authenticated peer identity, or downgrade protection;
those remain protocol/release review requirements. The pointer property remains
an inherited raw-address exposure, not an enclave or arbitrary-code isolation boundary.

## Executed local validation

Linux x86_64, isolated OpenSSL **3.5.4**, built from the commit above. The host
OpenSSL 3.0.13 was not replaced. All environments installed the existing
`citadel-core[next-test]` dependency set, including actual Qiskit, Cirq, LLVM,
OpenQASM importer, and qirrunner adapters.

| Interpreter | Full suite with strict markers | CLI compile / verify / differential |
| --- | --- | --- |
| Python 3.11.17 | 119 passed, 0 failed, 0 skipped | PASS / PASS / PASS |
| Python 3.12.14 | 119 passed, 0 failed, 0 skipped | PASS / PASS / PASS |
| Python 3.13.16 | 119 passed, 0 failed, 0 skipped | PASS / PASS / PASS |

Validated dependency versions: Qiskit 2.6.1, Cirq 1.7.0, cryptography 50.0.2,
pytest 8.4.2, llvmlite 0.50.0, qirrunner 0.9.7.

Executed commands (for each interpreter with isolated library path):

```sh
python -m pytest -q citadel-core/tests --strict-markers --junitxml=results.xml
uql compile citadel-core/examples/bell.uql --out /tmp/unique-bell-output
uql verify /tmp/unique-bell-output
uql differential /tmp/unique-bell-output
```

Additional regressions cover maximal/invalid contexts on both sides, independent
synthetic HKDF known-answer agreement, IKM wiping on KDF failure, X25519 cleanup
on ML-KEM failure, changed ciphertext deriving a different secret (ML-KEM implicit
rejection), DD threshold boundaries using supplied calibrated durations, exact
unitary/timing preservation, and QEC full GF(2) rank plus logical/stabilizer
commutation at distances 3, 5, 7, and 9. These extend the original tests.

## Remaining verification and release limits

- The modified GitHub Actions workflow has not yet been executed as a hosted
  run at the time this record was written. Local results are not hosted CI attestations.
- Only the dependency versions above were exercised. The DD adapter overrides
  Qiskit's protected padding hook; compatibility with other allowed Qiskit
  versions requires continued regression testing.
- The isolated OpenSSL build used `no-tests`; this task tests UQL against it and
  does not claim to validate the OpenSSL implementation itself.
- QEC checks establish structural algebra and circuit construction, not decoder
  quality, circuit-level noise performance, or a fault-tolerance proof.
- No hardware backend, independent crypto audit, external checkpoint witness,
  live PROOF-369/ABRAXAS service, Apple/device testing, or production deployment
  was performed.
- No Community package, licensing files, restricted-master code, or unrelated PR
  #2 functionality is included. Neither PR is merged or made ready for review.

Sources: https://github.com/arulu-369-eotu/project-quala-thelo/pull/2,
https://github.com/arulu-369-eotu/project-quala-thelo/pull/3,
https://github.com/arulu-369-eotu/project-quala-thelo/actions/runs/39886697956,
https://github.com/arulu-369-eotu/project-quala-thelo/actions/runs/37962991634.
