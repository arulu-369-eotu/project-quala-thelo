# Enterprise priorities and release gates

The first commercial objective is a paid, measurable vendor-assurance pilot.
Code alone does not establish market demand, patents, certifications or buyer
exclusivity. No enterprise partnership or ROI is claimed by this release.

## 1. QUA'LA Trust Passport

**Buyer:** procurement teams, banks, healthcare organizations and supply-chain
operators that repeatedly request the same vendor control evidence.

**Delivered:** reusable issuer-signed credentials with vendor identity,
holder public key, control claims and source-evidence SHA-256 commitments.
Each buyer receives a fresh, scoped challenge response signed by the credential
holder. The verifier enforces its own approved issuer and control policy, source
credential freshness, expiry, revocation and one-time use. Raw source reports are
not included. The signed claims remain visible to the verifier; this is not
selective-disclosure cryptography or a W3C VC interoperability claim.

**Pilot:** one approved issuer, one buyer, three controls, one integration. Establish
baseline review time and repeat evidence requests; compare them with verified
pilot measurements. Audit every approval and denial. A claim to reduced risk or
cost requires measured results and buyer acceptance.

**Before production:** independent protocol and implementation review, stable
control definitions, real issuer assurance procedures, root custody, disputes,
privacy review and operational recovery. Relative-time control values must be
refreshed by issuers or replaced with policy-defined absolute timestamps.

## 2. ABRAXAS 7 Enterprise Trust Plane

**Buyer:** enterprises requiring a verifier outside the evidence producer's
administrative boundary.

**Delivered:** a bounded JSON worker in a separate process; persistent explicit
issuer enrollment and irrevocable key-ID revocation; scope and policy pinning;
atomic SQLite replay rejection and persisted signed receipts. Policy can require
verified hardware identity. Without a configured, validated hardware adapter,
that policy rejects requests. Existing hardware records expire and do not survive
restart without revalidation. A software key file never satisfies the hardware
requirement.

**Before production:** select and implement an actual TPM, HSM or platform
attestation verifier with certified roots and freshness/revocation checking;
independently audit it. Provision verifier signing in hardware where required.
Deploy the verifier on a distinct host/account, authenticate remote transport,
protect configuration and storage, enforce rate and storage budgets, and monitor
clock, audit availability and recovery. A process on the same host does not by
itself establish remote independence. The worker has no TCP listener or remote
identity provider. Python key-file signing is a software prototype path.

## 3. PROOF-369 Assurance Network

**Buyer:** cross-enterprise relying parties and approved licensing operators.

**Delivered:** signed ledger-head checkpoints; separately keyed witnesses;
persistent fork/rollback refusal against previously observed checkpoints;
quorum verification and exact scope/head binding. A licensing gate requires a
fresh signed ALLOW receipt at the anchored head, a sufficient distinct-key
witness quorum and a live signed entitlement for the vendor, tenant, product
and capability. Licensing roots are provisioned separately from evidence roots.
Credential and entitlement revocations are stored persistently.

A witness proves observation of a checkpoint. It does not prove control claims,
physical machine state, accreditation, complete ledger history, legal validity
of an agreement, or absence of hidden forks. Different keys are required by code;
independent hosts, owners and administration must be established operationally.
Receipt inclusion proofs for older heads are not implemented; the license gate
accepts only the checkpoint's exact head. Entitlements are reusable until expiry
or revocation and are not a usage quota or payment mechanism.

**Before production:** separately operated witness hosts and checkpoint retention,
independent validation, key rotation and incident governance, inclusion proofs,
network transport and dispute procedures. Implement the applicable CIME ledger
and settlement requirements before claiming commercial license compliance.
This release neither transfers money nor meters or routes micro-royalties.

## Proposed milestones

| Milestone | Acceptance evidence |
| --- | --- |
| Protocol review | Independent written review of hybrid v2, Passport, receipts and root lifecycle |
| Procurement pilot | Measured review-time improvement; audited approvals; no unauthorized policy escapes observed in agreed tests |
| Independent ABRAXAS deployment | Actual attestation validation, separate administrative domains, authenticated transport, tested recovery |
| PROOF-369 external pilot | At least two genuinely independent operators; persisted checkpoints; recovery and fork exercises |
| Commercial release | Executed agreements, approved pricing, operational SLA, independent security review and required settlement integrations |

No fixed pricing, guaranteed profit or exclusivity premium is justified before
buyer discovery and those measurements.
