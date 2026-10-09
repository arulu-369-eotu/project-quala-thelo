# ZENITH-10: Ten Evidence-Driven Differentiators

**Objective:** build commercially valuable capabilities with measurable customer outcomes. These are engineering targets, not claims of established novelty, future revenues, exponential performance improvement or regulatory certification.

The three-product sequence remains: **QUA'LA Trust Passport → ABRAXAS 7 Enterprise Trust Plane → PROOF-369 Assurance Network**. Each addition must preserve fail-closed behavior and identify its independent evaluator.

| # | Proposal | Deliverable & security property | Empirical acceptance gate | Status |
|---|---|---|---|---|
| 1 | **Witness Constellation** | Signed, append-only evidence checkpoints observed by separately administered 2-of-3 witnesses; detect fork, rollback and unauthorized backdating | Inject 100+ tamper/fork/rollback attempts; detect 100%, retain continuity across restart; document separate operators | Reference code and adversarial tests committed; external hosts **not deployed** |
| 2 | **Causal Evidence Graph** | Signed chain of source commit → CI attestation → SBOM → executable hash → runtime deployment → vendor credential; verify every edge before acceptance | Demonstrate 0 accepted mismatched build/deploy pairs across an adversarial replay corpus; run independent graph verification | Planned |
| 3 | **Q-Day Switchboard** | Inventory signing/KEM algorithms and affected assets; maintain audited migration plans with explicit protocol negotiation, dual-algorithm interoperability tests and downgrade rejection | Test controlled rotation and rollback prevention, key expiry and escrow recovery; verify PQ interoperability against NIST-selected algorithms | Planned. Existing ML-KEM test coverage is only a foundation |
| 4 | **Confidential Trust Passport** | Selectively disclose individual vendor-control assertions rather than entire questionnaires; cryptographically bind audiences/expiry/revocation | Quantify disclosed bytes and fields per authorization; negative tests for linking, replay and cross-audience disclosure | Planned; requires review of appropriate VC/SD-JWT standards |
| 5 | **Revocation Shockwave** | Signed revocation epochs distributed to verifiers; fail closed on stale, disconnected or contradictory epoch state | Measure P50/P99 revocation propagation under load, offline denial and hostile clock skew; set contractual bounds only after observing results | Planned |
| 6 | **Sovereign Hardware Trust Roots** | Independent signer/verifier HSM/KMS identities, enclave-verified measurements, hardware key rotation and key-compromise drills | 0 exportable raw signing keys from approved custody; mandatory dual-control enrollment; document vendor attestation chains | Planned; current reference signers are PEM-backed |
| 7 | **Executable Assurance Policy Compiler** | Versioned deterministic controls compiled from sector policies into auditable allow/deny decisions; property-based tests block unsafe privilege escalation | No implicit ALLOW in 1,000+ fuzzed malformed-policy cases; policy diffs and provenance signed before activation | Existing simple policies; full compiler planned |
| 8 | **Supply-Chain Blast-Radius Twin** | Graph dependencies, vendor attestations, package SBOMs and service criticality to compute affected trust passports after a CVE or signer compromise | Measure alert latency, false positives and remediation time on independently labeled incident simulations | Planned |
| 9 | **Quantum-Ledger Lifeboat** | Wallet and ledger exposure inventories, signed migration recommendations, dual-key authorization where protocols permit; state precisely what Bitcoin/Ethereum consensus changes require | Reproducible key-exposure classification, cross-chain testnet migration drills and explicit failure simulations | Planned; **cannot retroactively make Bitcoin/Ethereum quantum-safe** |
| 10 | **Assurance Exchange & Metered Licensing** | CIME policy-coded verification licenses, privacy-preserving usage receipts and disputeable settlement evidence anchored to signed decisions | Reconcile 100% test transactions to authorized receipts with no double billing; independent legal/privacy review | Planned |

## Design constraints

- Real-time claims require real measurements and published confidence intervals.
- Zero knowledge, confidential computing, threshold signatures and post-quantum signatures must be specified using reviewed libraries and independently validated protocols. Names alone convey no security properties.
- Crypto-agility must never imply already-issued public keys are safe from future quantum attacks; quantify exposure and control migration boundaries.
- An enterprise operator must be able to run an **independent verifier** without permission to alter the claim issuer's signing key, witness database, or test pipeline.
- Each new feature must include threat model, meaningful adversarial tests, SLO proposal, telemetry, policy rollback plan, and an acceptance gate.
- The expected business impact must be validated in design-partner pilots: procurement time saved, avoided repeated questionnaires, verified credential freshness, onboarding cycle duration, auditable dispute resolution.
- Regulatory mappings are evidence support tools and are **not automatically certifications**.
- Network effects are hypotheses until qualified issuers, purchasers, pricing and interoperable partner participation are observed.

## Development order

**Gate A — Reliability:** secure GitHub CI artifact issuance, authorized source identity, replay rejection and reproducible acceptance suites. Current GitHub tests and attestation issuance are evidence for only this gate.

**Gate B — Independently witnessed assurance:** deploy and test operators outside the repo owner's security perimeter, quorum on three distinct custody domains, external public keys and anti-equivocation gossip.

**Gate C — Customer utility:** credential lifecycle and revocation APIs, signed policies, explicit evidence retention/privacy controls, procurement or healthcare integrations.

**Gate D — Quantum migration:** crypto-inventory, conservative dual-signature migration, documented algorithm and hardware assurances.

**Gate E — Commercial ecosystem:** paying design partners, interoperability trials, agreed liability boundaries, documented licensing and independent operational audits.

The rating goal is *continuously verified excellence*. Any numeric score must remain bounded by the chosen scale and accompanied by current independently reviewable evidence.
