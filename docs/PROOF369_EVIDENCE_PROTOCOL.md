# PROOF-369 Evidence Protocol v0.1 (experimental)

PROOF-369 is a **measured-evidence record format**, not a claim of
independent certification, blockchain finality or post-quantum signatures.

## Measurement contract

Each signed export contains an ordered set of validated, tenant-scoped,
canonical JSON measurements with explicit source SHA-256 commitment,
measurement time, outcome, and measurable test counts/duration/coverage.

- `PASS` requires a nonzero test count, zero failures and zero skips.
- Unknown metric names, inconsistent test totals, negative values,
  unsupported outcomes and malformed commitments are rejected.
- The append-only logical chain binds each row to its predecessor using
  domain-separated SHA-256 and deterministic canonical JSON.
- Each snapshot checkpoint is signed with domain-separated Ed25519.
  Independently provisioned public keys verify the full export without
  trusting the database server.
- Deleting, altering or reordering rows fails verification against the
  already witnessed checkpoint. **A signer can still create competing
  histories unless external witnesses record checkpoints.**

## Example integration sequence

1. CI produces test results associated with a pinned Git commit SHA.
2. A trusted evidence ingester checks CI provider provenance and normalizes
   the counts into the measurement schema; do not accept self-reported metrics
   from untrusted users as independently verified evidence.
3. `EvidenceLedger.append(measurement)` stores the record after full-chain
   verification.
4. `EvidenceLedger.export()` returns records and signed checkpoint.
5. A separate organization provisions the signer public key through a trusted
   channel, then invokes `verify_export(records, checkpoint, public_key)`.
6. External witnesses independently store the signed checkpoint and source
   attestation to detect rollback and split views.

## Threat model and limits

This implementation uses SQLite, a single local signer and Ed25519
(non-post-quantum) signatures. Database concurrency is serialized for writers.
Local tamper detection is bounded by the last independently saved checkpoint.
Signed hashes do **not** prove that a test was actually run, that the tester
was independent, or that the committed source was the deployed binary.

The signing key is supplied by the caller. Production requires hardware-backed
signing, key rotation/revocation, transparent external witnessing, access
controls, event provenance, backup recovery, rate limits and an independent
security review. No claims of 10,000/10,000 assurance are supported.

## Reproduction

```sh
python -m pip install -e './enterprise-trust-plane[test]'
python -m pytest -q enterprise-trust-plane/tests
```

Reference implementation: `enterprise-trust-plane/src/quala_trust/proof369.py`.
Verification regression tests: `enterprise-trust-plane/tests/test_proof369.py`.
