"""Offline, ephemeral-key pilot. No network, personal data or live approvals."""
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from quala_trust import (
    IssuerRegistry, TrustLedger, TrustPlane, example_policy,
    issue_attestation, verify_receipt,
)

issuer_key = Ed25519PrivateKey.generate()
verifier_key = Ed25519PrivateKey.generate()
registry = IssuerRegistry()
registry.enroll("acme", "reviewer-1", "key-2026", issuer_key.public_key())
policy = example_policy("ai", tenant="acme", audience="procurement", issuer="reviewer-1")

with TrustLedger(":memory:") as ledger:
    plane = TrustPlane(ledger, registry, "quala-demo-verifier", verifier_key)
    plane.add_policy(policy)
    challenge = plane.challenge(tenant="acme", audience="procurement", purpose="ai-onboard")
    signed = issue_attestation(
        challenge, issuer="reviewer-1", key_id="key-2026", signer=issuer_key,
        evidence_sha256="c" * 64,
        claims={"model_evaluation_passed": True, "authorized_data_use": True,
                "human_oversight_enabled": True},
    )
    receipt = plane.decide(signed, tenant="acme", audience="procurement", purpose="ai-onboard")
    print(json.dumps({"decision": receipt["receipt"]["decision"],
                      "policy_sha256": policy.sha256,
                      "verified_receipt": verify_receipt(receipt, verifier_key.public_key()),
                      "chain_valid": ledger.verify_chain(), "head": ledger.head()}, indent=2))
