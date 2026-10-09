# Enterprise Release Gates — QUA'LA / ABRAXAS 7 / PROOF-369

## Current engineering priority

**P0: QUA'LA Trust Passport.** Produce narrowly scoped, independently verifiable
vendor attestations, verifier policy, issuer qualification and explicitly
documented business-use constraints. Current `enterprise-trust-plane`
protocol is a prototype, not a complete verifier or deployed passport.

**P1: ABRAXAS 7.** Separate policy decision and evidence issuer processes;
enroll HSM/KMS-backed verifier identities; establish durable revocation,
transparency witnesses, rate limits, authorization, and disaster recovery.
The present code does not implement the full independent-verifier service.

**P2: PROOF-369.** Require qualified independent verifiers, anti-equivocation
log anchoring, cryptographic provenance and evidence before developing
inter-enterprise trust-score, licensing, or certification claims.

## Non-negotiable release criteria

- Full CI passes on supported Python/OpenSSL combinations and dedicated
  OpenSSL 3.5+ ML-KEM runner. Never use skipped tests as proof of crypto.
- No secret bytes enter Python-managed buffers, including all exception
  paths, as demonstrated with native memory instrumentation.
- Opaque secret handles with synchronized lifecycle and no external pointer
  exports. Any Python/ctypes native key path must receive independent review.
- Explicitly authenticated identities, tenant scoping, challenge expiration,
  atomic nonce consumption, durable replay protection and revocation.
- Protocol v2 key-derivation reference vectors and downgrade-rejection tests.
- QEC commutation/rank and noisy decoder benchmarks before fault-tolerance
  claims; calibrated hardware evidence before dynamical-decoupling claims.
- Reproducible dependencies, dependency scanning, artifact attestations and
  branch protection.
- Independent penetration test, SAST, fuzzing and cryptographic code audit.
- Legal review of license, patents, contracts, privacy and sector requirements.
- Operational controls: restore drills, incident response, audit retention,
  availability targets and multi-tenant isolation.

## Scoring

Do not assign a perfect or greater-than-perfect score. Maintain an auditable
scorecard with evidence links and explicit FAIL/PASS/UNTESTED states per gate.
Release remains BLOCKED until all required controls are verified.
