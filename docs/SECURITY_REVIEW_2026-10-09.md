# Security review and remediation — October 9, 2026

## Result

**120 tests passed, zero failed or skipped.** Bandit 1.9.4 reported zero findings
in production Python code. pip-audit 2.10.1 reported zero known vulnerabilities
across the 61 pinned verification dependencies. The exact environment and
results are recorded in [VERIFICATION_RESULTS.json](VERIFICATION_RESULTS.json).
The two synthetic partner demos passed. Package installation, compilation,
JSON parsing, shell syntax and diff-whitespace checks passed.

These are bounded engineering results. They do not prove absence of unknown
vulnerabilities, production readiness, cryptographic certification or control
claim truth. GitHub-hosted CI is a separate run after publication.

## Scope and provenance

Reviewed the complete current repository tree: all production Python modules,
tests, package configuration, governance/research documents and the prior full
enterprise upgrade. Main baseline:
`81a515e36c35ddd28ad00096442db874d67bb5ab`. The previous feature branch contained
only protocol.py; its Library ZIP supplied the rest of the prior package. Its
protocol differed only in blank-line whitespace and was reconciled without
removing existing functionality. License, patent terms and compartmentalized
research archives were preserved.

The initial combined suite contained 33 tests: 28 passed and 5 failed. Two native
crypto failures initially reflected the host's system OpenSSL 3.0.13 lacking
ML-KEM; three were actual Qiskit/surface-code defects. The unmodified native code
was then rerun with independently downloaded, checksum-verified OpenSSL 3.5.8,
and reproduced `native cryptographic operation failed: HKDF info limit`.

The review covers this accessible repository and prior upgrade, not OpenAI's
internal Codex implementation, every project in the user's account, user-device
operating systems, running production infrastructure, external providers or
unprovided GRANDMASTER_CODEX assets. No external penetration test or production
credential access occurred. Git history was used for baseline reproduction,
not a complete historical-secret audit.

## Confirmed defects and repairs

Severity below is engineering prioritization, not an independently assigned
CVSS score. Availability/research defects are identified separately from
security defects; no unsupported exploitability claim is made.

| Finding | Priority/type | Repair and verification |
| --- | --- | --- |
| Valid hybrid transcript always exceeds 1,024-byte HKDF info bound | Release blocker / functional crypto defect | v2 length-framed SHA-512 public-input commitment; full and maximum context agreement; independent HKDF comparison |
| X25519, ML-KEM and HKDF intermediate buffers not locked and not reliably wiped on failure | High / secret lifecycle | Dedicated locked anonymous pages for application-owned intermediates; cleanup in success/failure paths; injected KDF failure and cleanse tests |
| Native secret accepts arbitrary owned pointers; copied/closed handles can be used unsafely | High / native memory safety | Factory-only ownership, copy/serialization rejection, idempotent close, synchronized key use and closed/fork rejection and MADV_DONTFORK pages |
| Unchecked OpenSSL capability produces opaque ML-KEM startup failure | Medium / deployment correctness | Explicit OpenSSL 3.5 minimum and controlled absolute library path; no weaker fallback |
| Surface-code boundary stabilizers fail commutation; logical operators use wrong orientation | Release blocker / mathematical research defect | Corrected Z boundaries and logical orientations; commutation/rank, small pure-error distance and syndrome simulation checks |
| DD pass uses unsupported spacings/sequence_min_length_ratios arguments | Release blocker / API defect | Supported Qiskit 2.5 spacing argument and a tested padding hook preserving idle/pulse budget; unitary preservation checks |
| DD numeric validation admits NaN/infinite timing values | Medium / numerical correctness | Finite, strict numeric bounds and rejection tests |
| Closed LockedBuffer can be repopulated | Medium / lifecycle misuse | Closed-state checks and cleanup; retained memoryviews explicitly remain a caller responsibility |
| Nonce/event commit occurs before receipt signing, so signer failure burns challenge without receipt | High / authorization availability | Sign and persist receipt outbox inside the nonce/event transaction; fault-injection rollback and retry |
| Outstanding challenge is not tied to a policy revision | High / policy consistency | Persist policy digest with each challenge; refuse consumption under changed configuration |
| Authorization can extend an already corrupt local hash chain | High / audit integrity | Full chain validation before issuing/consuming authorization; corrupted history denies without append |
| Policy accepts mutable lists and boolean freshness limits | Medium / configuration ambiguity | Immutable tuple shape, strict bounds and duplicates rejection |
| Receipt verification accepts underspecified signed bodies | Medium / verification contract | Complete field, type, hash, reason and decision validation before acceptance |
| Deep JSON/invalid Unicode can escape the intended rejection boundary | Medium / availability | Bounded strict parser translates malformed, recursive and surrogate inputs to TrustError; targeted negatives plus 200 generated byte inputs |
| Revoked issuer key ID can be enrolled again after removal | Medium / operator trust lifecycle | Terminal tombstones and persistent issuer roots; rotation requires a new ID |
| Prior dependency tooling uses pip 25.0.1 with reported advisories | High / verification environment, not application vulnerability | Upgraded to pip 26.2.1; six distinct advisory IDs (12 duplicate audit records) cleared; pinned and hash-locked CI tooling |

The previous reusable-Passport, external-witness and licensing proposals were
also completed as explicit prototype APIs, with actual code and negative tests.
That implementation work is not represented as discovery of vulnerabilities in
nonexistent prior modules.

## What the three prioritized products now do

1. **QUA'LA Trust Passport:** reusable issuer credentials, holder possession,
   exact buyer scope, credential freshness, persisted revocation and signed
   receipts. One credential passes separate procurement, banking, healthcare
   and supply-chain example policies in tests. Policies are illustrative.
2. **ABRAXAS 7:** separate JSON verification worker, operator-provisioned roots,
   terminal key revocation, atomic replay rejection across connections/process
   restart, private software key files and an explicit hardware-evidence adapter
   boundary. Missing hardware evidence produces denial, never a synthetic PASS.
3. **PROOF-369:** independently keyed checkpoint witnesses, monotonic stored
   observation, distinct-key quorum, fork/rollback refusal, signed license
   entitlements and an access gate combining fresh ALLOW evidence, a pinned
   policy, exact checkpoint head and live entitlement.

The exact trust model and gaps are in
[THREAT_MODEL.md](../enterprise-trust-plane/THREAT_MODEL.md).

## Verification method and practical limits

- Native test dependency: official OpenSSL 3.5.8 archive SHA-256
  `a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2`.
  Local build only; the host system library was not replaced.
- Crypto checks compare derived keys, exercise maximum context and ciphertext
  tampering/low-order X25519 rejection, compare HKDF-SHA512 against the independent
  cryptography implementation and inject memory-lock/KDF failures, and verify that owned secret pages are absent
  from a fork child. Synthetic
  known-answer material in tests is public. These checks are not a formal proof
  of the custom hybrid combiner.
- Quantum checks use noiseless circuit/Clifford simulation. They establish the
  tested algebra and measurement behavior, not physical fault tolerance,
  decoding performance or quantum advantage.
- Trust checks include mutation, substitution, wrong scope/holder/key, revocation,
  expiry, policy revision, corrupted history, transactional signer failures,
  concurrent nonce reuse, separate-worker restart, quorum manipulation,
  witness persistence/forks and licensing scope/revocation.
- Bandit scans production Python. Manual review covers its native pointer and
  protocol logic beyond pattern matching. Zero scanner findings is not a proof
  of memory safety or security. The separate fixed-argument git scanner uses
  subprocess without shell execution; it emits only filenames/rules/counts.
- The secret-pattern scan covers current tracked and proposed non-ignored files
  for private key blocks and common GitHub/AWS/Slack/OpenAI token forms, rejects
  unexpected symlinks/oversized files and prints no matched values. It is not a
  general secret, PII or historical-credential detector.
- Dependency results apply to pinned Python packages in this verification lock,
  as known to the audit service on this review date. Native dependencies, future
  vulnerabilities, user systems and external services are outside that result.
- Read-only CI permissions, commit-pinned actions, hash-locked dependencies,
  checksum-verified native source and disabled persisted checkout credentials
  reduce build supply-chain exposure. No artifact signing, SLSA certification
  or independently reproducible release attestation is claimed.

## Remaining release gates

Independent review of the custom hybrid v2 protocol and trust wire formats;
a real audited hardware identity/signing integration; authenticated remote
transport and independently administered hosts; rate/storage budgets and load
and recovery tests; operational clock/root/key custody; independently retained
latest checkpoints; older-receipt inclusion proofs; and applicable CIME ledger
and settlement integrations. Local administrator/root compromise and coherent
storage rollback cannot be eliminated by this prototype.

No production-security score out of 1,000 is assigned. The concrete results
above are more defensible than a subjective numeric assurance rating.

## Primary technical references

- OpenSSL HKDF parameters and 1,024-byte info limit:
  https://docs.openssl.org/3.5/man7/EVP_KDF-HKDF/
- HKDF construction and use guidance:
  https://www.rfc-editor.org/rfc/rfc5869
- Qiskit supported dynamical-decoupling parameters:
  https://quantum.cloud.ibm.com/docs/en/api/qiskit/qiskit.transpiler.passes.PadDynamicalDecoupling
- Official OpenSSL release archive:
  https://www.openssl-library.org/source/old/3.5/
