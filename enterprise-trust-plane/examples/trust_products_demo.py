"""Local demonstration of all three products, using synthetic control claims."""
import json
from pathlib import Path
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from quala_trust import (TrustLedger, IssuerRegistry, PersistentIssuerRegistry,
        PassportTrustPlane, example_policy, issue_passport, present_passport,
        verify_receipt, Witness, create_checkpoint, EntitlementVerifier,
        issue_entitlement, licensed_receipt_access)


def main():
    at = int(time.time())
    issuer, holder, verifier, licensor = [Ed25519PrivateKey.generate() for _ in range(4)]
    with tempfile.TemporaryDirectory(prefix="quala-demo-") as directory:
        root = Path(directory)
        with TrustLedger(root/"verifier.sqlite") as ledger:
            registry = PersistentIssuerRegistry(ledger)
            registry.enroll("buyer", "auditor", "key-1", issuer.public_key())
            plane = PassportTrustPlane(ledger, registry, "abraxas-7", verifier)
            policy = example_policy("procurement", tenant="buyer", audience="procurement", issuer="auditor")
            plane.add_policy(policy)
            passport = issue_passport(passport_id="vendor-passport-1", subject="vendor-1",
                issuer="auditor", key_id="key-1", holder_key=holder.public_key(),
                claims={"security_review_passed": True, "supplier_ownership_reviewed": True,
                        "critical_patch_sla_days": 10}, evidence_sha256="a"*64, signer=issuer, now=at)
            challenge = plane.challenge(tenant="buyer", audience="procurement", purpose="procurement-onboard", now=at)
            presentation = present_passport(passport, challenge, holder_signer=holder, now=at)
            receipt = plane.decide_passport(presentation, tenant="buyer", audience="procurement", purpose="procurement-onboard", now=at)
            verify_receipt(receipt, verifier.public_key())
            checkpoint = create_checkpoint(ledger, network="proof369-demo", ledger_id="demo-ledger",
                          verifier_id="abraxas-7", signer=verifier, now=at)
            witness_keys, witness_receipts, witnesses = {}, [], []
            try:
                for i in range(2):
                    key = Ed25519PrivateKey.generate()
                    name = f"witness-{i+1}"
                    witness = Witness(root/f"{name}.sqlite", witness_id=name, signer=key,
                              network="proof369-demo", ledger_id="demo-ledger", verifier_id="abraxas-7",
                              trusted_verifier_key=verifier.public_key())
                    witnesses.append(witness)
                    witness_keys[name] = key.public_key()
                    witness_receipts.append(witness.observe(checkpoint, now=at))
                licensing_roots = IssuerRegistry()
                licensing_roots.enroll("buyer", "eotu-licensor", "license-key", licensor.public_key())
                licensing = EntitlementVerifier(ledger, licensing_roots)
                entitlement = issue_entitlement({"version": "proof369-entitlement-v1", "license_id": "demo-license",
                    "licensor": "eotu-licensor", "key_id": "license-key", "tenant": "buyer", "subject": "vendor-1",
                    "product": "trust-passport", "capabilities": ["verify"], "issued_at": at, "expires_at": at+3600,
                    "agreement_sha256": "b"*64}, licensor)
                authorization = licensed_receipt_access(receipt=receipt, entitlement=entitlement,
                    entitlement_verifier=licensing, proposal=checkpoint, witness_receipts=witness_receipts,
                    trusted_verifier_key=verifier.public_key(), witness_keys=witness_keys, quorum=2,
                    network="proof369-demo", ledger_id="demo-ledger", verifier_id="abraxas-7",
                    tenant="buyer", subject="vendor-1", audience="procurement", purpose="procurement-onboard",
                    policy_sha256=policy.sha256, product="trust-passport", capability="verify", now=at)
                print(json.dumps({"demo": "synthetic-local-only", "passport_decision": receipt["receipt"]["decision"],
                                  "ledger_verified": ledger.verify_chain(), "witness_signatures": len(witness_receipts),
                                  "licensed_access": authorization["authorized"], "hardware_attestation": "unavailable"}, indent=2))
            finally:
                for witness in witnesses:
                    witness.close()


if __name__ == "__main__":
    main()
