"""Illustrative cross-sector onboarding packs; not statutory compliance standards.

Production clients MUST approve thresholds, source assurance, control semantics,
and audit procedures before using a pack for real authorization.
"""
from __future__ import annotations

from .protocol import Policy, Rule, TrustError

EXAMPLE_CONTROLS: dict[str, tuple[Rule, ...]] = {
    "procurement": (
        Rule("security_review_passed", "eq", True),
        Rule("supplier_ownership_reviewed", "eq", True),
        Rule("critical_patch_sla_days", "lte", 30),
    ),
    "supply-chain": (
        Rule("shipment_provenance_verified", "eq", True),
        Rule("software_bill_of_materials_available", "eq", True),
        Rule("supplier_traceability_percent", "gte", 95),
    ),
    "banking": (
        Rule("kyc_controls_reviewed", "eq", True),
        Rule("third_party_risk_score", "lte", 35),
        Rule("incident_drill_days_ago", "lte", 90),
    ),
    "healthcare": (
        Rule("data_minimization_verified", "eq", True),
        Rule("business_associate_terms_executed", "eq", True),
        Rule("incident_drill_days_ago", "lte", 90),
    ),
    "energy": (
        Rule("resilience_test_passed", "eq", True),
        Rule("recovery_time_minutes", "lte", 240),
        Rule("software_bill_of_materials_available", "eq", True),
    ),
    "manufacturing": (
        Rule("supplier_traceability_percent", "gte", 95),
        Rule("contingency_inventory_days", "gte", 30),
        Rule("labor_due_diligence_reviewed", "eq", True),
    ),
    "cloud": (
        Rule("residency_controls_verified", "eq", True),
        Rule("disaster_recovery_test_passed", "eq", True),
        Rule("critical_patch_sla_days", "lte", 30),
    ),
    "ai": (
        Rule("model_evaluation_passed", "eq", True),
        Rule("authorized_data_use", "eq", True),
        Rule("human_oversight_enabled", "eq", True),
    ),
    "retail": (
        Rule("payment_tokenization_verified", "eq", True),
        Rule("fraud_monitoring_enabled", "eq", True),
        Rule("consumer_privacy_reviewed", "eq", True),
    ),
    "logistics": (
        Rule("shipment_provenance_verified", "eq", True),
        Rule("carrier_security_reviewed", "eq", True),
        Rule("disruption_drill_days_ago", "lte", 120),
    ),
}


def example_policy(sector: str, *, tenant: str, audience: str,
                   issuer: str) -> Policy:
    if sector not in EXAMPLE_CONTROLS:
        raise TrustError("unknown industry policy pack")
    return Policy(policy_id=f"{sector}-pilot-v1", tenant=tenant,
                  audience=audience, purpose=f"{sector}-onboard",
                  allowed_issuers=(issuer,), rules=EXAMPLE_CONTROLS[sector])
