# PROOF-369 × GitHub CI × External Witnesses × ABRAXAS 7

**Release state:** Experimental reference implementation, not a licensed certification authority or production-deployed independent witness network.

## Security boundary — what each cryptographic result actually establishes

1. GitHub Actions runs a specified test suite, writes a bounded JSON report, and invokes [actions/attest](https://github.com/actions/attest) to obtain **Sigstore-backed SLSA build provenance** for the *artifact digest*. The action's success alone is not a separate independent verifier.
2. A PROOF-369 producer retrieves the artifact and invokes **gh attestation verify** with pinned repository, exact workflow path, protected source ref and commit. **Only then** does it append measured results to a local hash chain and issue its own signed checkpoint.
3. Independent witness operators receive the *whole* chain and signed checkpoint. They verify the chain and signature, enforce sequence monotonicity and reject forks/rollback against their own persistent history, then sign a receipt using their private key.
4. ABRAXAS 7 (operated separately from PROOF-369 and witnesses) independently invokes GitHub CLI again on the actual artifact, verifies the PROOF-369 chain and trusted checkpoint key, requires a unique-key threshold of witness receipts, checks freshness and exact linkage to the attested artifact, and signs an ALLOW receipt. A failed condition denies admission.
5. A receiving party must verify the ABRAXAS 7 signature **and provision the verifier public key through an independent trusted channel**. A signed statement is not proof that the signer is trustworthy.

**Very important:** A signed test artifact proves its authenticated origin and integrity. It does not prove the tests are sufficiently comprehensive, that the branch is protected, or that there are zero vulnerabilities. Evidence remains subject to the exact signed workflow, provenance, approved commit, policy and external review.

## Files

- \`.github/workflows/proof369-attested-ci.yml\` — test measurement + GitHub provenance issuance. All third-party actions are SHA pinned.
- \`src/quala_trust/github_ci.py\` — pins the GitHub repository, signer workflow, commit and ref in real \`gh attestation verify\` execution, checks structured metrics.
- \`src/quala_trust/proof369.py\` — source commitment, monotonic evidence chain, signed checkpoints.
- \`src/quala_trust/witness.py\` — separately deployed monotonic witness, signed receipts and fork/rollback rejection.
- \`src/quala_trust/abraxas7.py\` — proof verification + external quorum + fresh GitHub evidence + signed admission receipt.
- \`src/quala_trust/operator.py\` — three executable modes: \`ingest\`, \`witness\`, \`verify\`.
- \`tests/test_assurance.py\` — adversarial injection tests. Mocked GitHub CLI in unit tests **does not constitute a real attestation verification**.
- \`tests/test_operator.py\` — independent Python process witness execution.
- \`docs/ZENITH_TEN_CAPABILITIES.md\` — proposed next-generation features with verifiable KPIs.

## Required independent environment

PROOF signer host, two or more witness hosts, and ABRAXAS verifier host **must be separately administered** for independence. Do not colocate signing keys, databases, or administrative identities in a production assurance configuration. File-backed PEM signers below are **development examples**; in production integrate reviewed HSM/KMS-backed signing and protect audit state with independent retention/anti-rollback mechanisms.

Each operator installs the \`quala-enterprise-trust\` package, a pinned/verified GitHub CLI version for \`ingest\` and \`verify\`, and a trust store of Ed25519 public keys established out of band. Avoid passing signing keys in CLI arguments or uploading them to GitHub.

## Example process boundaries (do not use sample names as actual credentials)

On the GitHub CI run page obtain \`proof369-ci-report-<run_id>-<attempt>\`; retrieve its \`proof369-ci.json\`. The artifact may be retrieved using \`gh run download <RUN_ID> -R arulu-369-eotu/project-quala-thelo --name <ARTIFACT_NAME> --dir downloaded\`. The public source ref must be a reviewed/protected \`refs/heads/main\`, **not** a feature branch.

Manually verify the report before admission (the operator also performs this step):

\`\`\`bash
gh attestation verify downloaded/proof369-ci.json \
  --repo arulu-369-eotu/project-quala-thelo \
  --signer-workflow arulu-369-eotu/project-quala-thelo/.github/workflows/proof369-attested-ci.yml \
  --source-digest YOUR_EXACT_40_CHARACTER_COMMIT_SHA \
  --source-ref refs/heads/main --format json
\`\`\`

### 1 — Separate PROOF evidence producer

Using a PROOF private key readable only by its owner (0600), run:

\`\`\`bash
python -m quala_trust.operator ingest \
  --tenant bank1 \
  --repo arulu-369-eotu/project-quala-thelo \
  --source-sha YOUR_EXACT_40_CHARACTER_COMMIT_SHA \
  --database proof.db --proof-private proof-private.pem \
  --ci-report downloaded/proof369-ci.json \
  --out proof-export.json
\`\`\`

This step **refuses non-main refs**, runs \`gh attestation verify\`, then appends and signs a complete evidence export. The signed chain does not independently validate GitHub evidence on the witness host; ABRAXAS repeats verification.

### 2 — Two or three external witness operators

For each witness, independently enroll the PROOF public key and a uniquely held witness private key. Example for independently operated \`east\` host:

\`\`\`bash
python -m quala_trust.operator witness \
  --id east --tenant bank1 --database east-witness.db \
  --checkpoint-public proof-public.pem \
  --witness-private east-private.pem \
  --evidence proof-export.json --out east-receipt.json
\`\`\`

Repeat on *different* administrative domains (\`west\`, \`backup\`) with separately created keys and databases. Verify that receipt files, public keys and the PROOF export are transported over authenticated channels.

### 3 — ABRAXAS independent verifier operator

A verifier operator has separately pinned PROOF and all witness public keys, its own signer, the exact authorized GitHub source commit, and a genuine GitHub CLI:

\`\`\`bash
python -m quala_trust.operator verify \
  --id abraxas-west --tenant bank1 \
  --repo arulu-369-eotu/project-quala-thelo \
  --source-sha YOUR_EXACT_40_CHARACTER_COMMIT_SHA \
  --checkpoint-public proof-public.pem \
  --verifier-private abraxas-private.pem \
  --witness-public east=east-public.pem \
  --witness-public west=west-public.pem \
  --witness-receipt east-receipt.json \
  --witness-receipt west-receipt.json \
  --evidence proof-export.json \
  --ci-report downloaded/proof369-ci.json \
  --out abraxas-allow.json
\`\`\`

The \`source-sha\` value must be exactly the approved **40-character commit hash**; do not replace it with a floating branch name. This command will fail closed unless the check is signed, fresh, from \`main\`, witnessed by at least two distinct keys, and matches the **specific** attested CI artifact.

ABRAXAS admission receipts are Ed25519-signed, **not post-quantum**. Public keys do not establish independent organizational identity by themselves; key enrollments and operator vetting are mandatory.

## Offline GitHub verification

Use \`gh attestation download\` to obtain the bundle and \`gh attestation trusted-root\` to save trusted roots on a trusted connected machine. Copy those alongside the artifact; supply \`--bundle\` and \`--trusted-root\` to \`ingest\`/\`verify\`. Track trusted-root refresh and revocation, and record the exact CLI binary digest.

## Test and release gates

Run \`python -m pytest -q enterprise-trust-plane/tests\` in supported Python versions. CI unit tests with a **mock** CLI establish control-flow correctness only. CI attestation issuance success verifies that GitHub published signed provenance; it does **not** independently prove the production ABRAXAS verifier validated that specific record.

Before production: externally operated witness pilots, independently trusted key enrollment, actual offline/online \`gh\` verification tests, versioned protocol interoperability, quantified load/fault testing, CI workflow protection, signer HSM integration, private key rollover, backup/restore drills and independent penetration/crypto audit.

Do not claim network-wide assurance, post-quantum signatures, HSM-backed identity, independent certification or 10,000/10,000 security based on the reference implementation.
