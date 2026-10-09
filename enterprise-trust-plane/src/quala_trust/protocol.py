"""Deterministic, bounded wire format for QUA'LA Trust Exchange v1.

Ed25519 is used for current application-level signatures; it is NOT post-quantum.
Signers are supplied by the calling application; no private keys are stored here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ATTEST_DOMAIN = b"QU'ALA-ATTESTATION-V1\x00"
RECEIPT_DOMAIN = b"QU'ALA-RECEIPT-V1\x00"
MAX_WIRE_BYTES = 16_384
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}\Z")
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
ATTEST_FIELDS = frozenset({
    "version", "issuer", "key_id", "tenant", "audience", "purpose",
    "nonce", "issued_at", "expires_at", "claims", "evidence_sha256",
})


class TrustError(ValueError):
    """Reject an invalid request; callers must interpret errors as DENY."""


def identifier(s: str) -> str:
    if type(s) is not str or not ID_PATTERN.fullmatch(s):
        raise TrustError("invalid identifier")
    return s


def _json_shape(obj: Any, depth: int = 0) -> None:
    if depth > 8:
        raise TrustError("JSON structure too deep")
    if obj is None or type(obj) in (str, bool):
        if type(obj) is str and len(obj) > 4_096:
            raise TrustError("oversized string")
        if type(obj) is str and any(0xD800 <= ord(c) <= 0xDFFF for c in obj):
            raise TrustError("unpaired Unicode surrogate")
        return
    if type(obj) is int:
        if abs(obj) > 2**53 - 1:
            raise TrustError("integer outside interoperable range")
        return
    if type(obj) is list:
        if len(obj) > 128:
            raise TrustError("oversized list")
        for item in obj:
            _json_shape(item, depth + 1)
        return
    if type(obj) is dict:
        if len(obj) > 128:
            raise TrustError("oversized object")
        for k, v in obj.items():
            if type(k) is not str:
                raise TrustError("JSON object keys must be strings")
            _json_shape(k, depth + 1)
            _json_shape(v, depth + 1)
        return
    raise TrustError("unsupported JSON type (including floating point)")


def canonical(obj: Any) -> bytes:
    _json_shape(obj)
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(raw) > MAX_WIRE_BYTES:
        raise TrustError("wire payload too large")
    return raw


def loads_strict(source: bytes | str) -> Any:
    """Parse external JSON without duplicate-key or non-finite-number ambiguity."""
    if type(source) is bytes:
        try:
            source = source.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise TrustError("invalid UTF-8") from exc
    if type(source) is not str:
        raise TrustError("invalid JSON input type")
    try:
        size = len(source.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise TrustError("invalid Unicode input") from exc
    if size > MAX_WIRE_BYTES:
        raise TrustError("invalid or oversized JSON input")

    def distinct_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise TrustError("duplicate JSON object field")
            result[key] = value
        return result

    try:
        parsed = json.loads(source, object_pairs_hook=distinct_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(
                                TrustError("non-finite JSON number")))
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise TrustError("invalid JSON") from exc
    canonical(parsed)
    return parsed


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def _is_hex256(s: Any) -> bool:
    return type(s) is str and HEX256.fullmatch(s) is not None


def validate_claims(claims: Any) -> dict[str, bool | int | str]:
    if type(claims) is not dict or not (1 <= len(claims) <= 32):
        raise TrustError("claims must contain 1..32 named controls")
    for name, value in claims.items():
        identifier(name)
        if type(value) not in (str, bool, int):
            raise TrustError("claims must be boolean, string or integer")
        if type(value) is str and len(value) > 256:
            raise TrustError("claim value too long")
        if type(value) is int and abs(value) > 2**53 - 1:
            raise TrustError("claim integer out of range")
    return dict(claims)


def validate_attestation(payload: Any) -> dict[str, Any]:
    if type(payload) is not dict or frozenset(payload) != ATTEST_FIELDS:
        raise TrustError("invalid attestation schema")
    for field in ("issuer", "key_id", "tenant", "audience", "purpose"):
        identifier(payload[field])
    if payload["version"] != "quala-attestation-v1":
        raise TrustError("unsupported attestation version")
    if not _is_hex256(payload["nonce"]) or not _is_hex256(payload["evidence_sha256"]):
        raise TrustError("invalid SHA-256 commitment or nonce")
    issued, expires = payload["issued_at"], payload["expires_at"]
    if type(issued) is not int or type(expires) is not int or issued < 0:
        raise TrustError("invalid timestamps")
    if not 0 < expires - issued <= 300:
        raise TrustError("attestation lifetime must be within 1..300 seconds")
    validate_claims(payload["claims"])
    canonical(payload)
    return payload


def sign_attestation(payload: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    validate_attestation(payload)
    copy = json.loads(canonical(payload))
    signature = key.sign(ATTEST_DOMAIN + canonical(copy)).hex()
    return {"payload": copy, "signature": signature}


def verify_attestation(envelope: Any, key: Ed25519PublicKey) -> dict[str, Any]:
    if type(envelope) is not dict or set(envelope) != {"payload", "signature"}:
        raise TrustError("invalid signed envelope")
    payload = validate_attestation(envelope["payload"])
    sig = envelope["signature"]
    if type(sig) is not str or len(sig) != 128 or re.fullmatch(r"[0-9a-f]{128}", sig) is None:
        raise TrustError("invalid signature encoding")
    try:
        key.verify(bytes.fromhex(sig), ATTEST_DOMAIN + canonical(payload))
    except InvalidSignature as exc:
        raise TrustError("signature verification failed") from exc
    return payload


def verify_receipt(receipt: Any, trusted_verifier_key: Ed25519PublicKey) -> bool:
    if type(receipt) is not dict or set(receipt) != {"receipt", "signature"}:
        raise TrustError("invalid receipt envelope")
    signature = receipt["signature"]
    if type(signature) is not str or re.fullmatch(r"[0-9a-f]{128}", signature) is None:
        raise TrustError("invalid receipt signature format")
    body = receipt["receipt"]
    required = {"version", "verifier", "ledger_seq", "ledger_hash", "previous_hash", "at",
                "tenant", "audience", "purpose", "issuer", "key_id", "policy_id",
                "policy_sha256", "attestation_sha256", "evidence_sha256", "decision",
                "reason_codes", "nonce_commitment"}
    optional = {"passport_id", "subject", "passport_sha256", "presentation_sha256"}
    if type(body) is not dict or not required <= set(body) or set(body) - required - optional or body.get("version") != "quala-receipt-v1":
        raise TrustError("invalid receipt schema")
    if set(body) & optional and not optional <= set(body):
        raise TrustError("incomplete passport receipt")
    for field in ("verifier", "tenant", "audience", "purpose", "issuer", "key_id", "policy_id"):
        identifier(body[field])
    for field in ("ledger_hash", "previous_hash", "policy_sha256", "attestation_sha256", "evidence_sha256", "nonce_commitment"):
        if not _is_hex256(body[field]):
            raise TrustError("invalid receipt hash")
    if type(body["ledger_seq"]) is not int or body["ledger_seq"] < 1 or type(body["at"]) is not int or body["at"] < 0:
        raise TrustError("invalid receipt sequence or time")
    reasons = body["reason_codes"]
    if type(reasons) is not list or len(reasons) > 33 or any(type(r) is not str or not 1 <= len(r) <= 160 for r in reasons):
        raise TrustError("invalid receipt reason codes")
    if body["decision"] not in ("ALLOW", "DENY") or (body["decision"] == "ALLOW") != (not reasons):
        raise TrustError("inconsistent receipt decision")
    if optional <= set(body):
        identifier(body["passport_id"])
        identifier(body["subject"])
        if not _is_hex256(body["passport_sha256"]) or not _is_hex256(body["presentation_sha256"]):
            raise TrustError("invalid passport receipt hash")
    try:
        trusted_verifier_key.verify(bytes.fromhex(signature), RECEIPT_DOMAIN + canonical(body))
    except InvalidSignature as exc:
        raise TrustError("receipt signature verification failed") from exc
    return True


@dataclass(frozen=True)
class Rule:
    field: str
    operation: str
    value: bool | int | str | tuple[str, ...]

    def __post_init__(self) -> None:
        identifier(self.field)
        if self.operation not in ("eq", "gte", "lte", "one_of"):
            raise TrustError("unknown policy operation")
        if self.operation in ("gte", "lte") and type(self.value) is not int:
            raise TrustError("ordered rules require integer thresholds")
        if self.operation == "one_of":
            if type(self.value) is not tuple or not self.value or len(self.value) > 32:
                raise TrustError("one_of requires a non-empty string tuple")
            if any(type(v) is not str for v in self.value):
                raise TrustError("one_of requires string values")
        if self.operation == "eq" and type(self.value) not in (bool, int, str):
            raise TrustError("invalid equality value")
        canonical(self.as_dict())

    def check(self, claims: Mapping[str, Any]) -> bool:
        if self.field not in claims:
            return False
        actual = claims[self.field]
        if self.operation == "eq":
            return type(actual) is type(self.value) and actual == self.value
        if self.operation == "one_of":
            return type(actual) is str and actual in self.value
        if type(actual) is not int:
            return False
        return actual >= self.value if self.operation == "gte" else actual <= self.value

    def as_dict(self) -> dict[str, Any]:
        value = list(self.value) if type(self.value) is tuple else self.value
        return {"field": self.field, "operation": self.operation, "value": value}


@dataclass(frozen=True)
class Policy:
    policy_id: str
    tenant: str
    audience: str
    purpose: str
    allowed_issuers: tuple[str, ...]
    rules: tuple[Rule, ...]
    max_age_seconds: int = 120
    require_hardware_identity: bool = False
    max_credential_age_seconds: int = 86400

    def __post_init__(self) -> None:
        for name in (self.policy_id, self.tenant, self.audience, self.purpose):
            identifier(name)
        if type(self.allowed_issuers) is not tuple or type(self.rules) is not tuple or not 1 <= len(self.allowed_issuers) <= 32 or not 1 <= len(self.rules) <= 32 or any(type(r) is not Rule for r in self.rules):
            raise TrustError("fail-closed policies require issuer and rule allowlists")
        if len(set(self.allowed_issuers)) != len(self.allowed_issuers):
            raise TrustError("duplicate allowed issuer")
        for issuer in self.allowed_issuers:
            identifier(issuer)
        if len(set(r.field for r in self.rules)) != len(self.rules):
            raise TrustError("ambiguous duplicate policy controls")
        if type(self.max_age_seconds) is not int or not 1 <= self.max_age_seconds <= 300:
            raise TrustError("invalid policy freshness limit")
        if type(self.require_hardware_identity) is not bool:
            raise TrustError("invalid hardware identity policy")
        if type(self.max_credential_age_seconds) is not int or not 1 <= self.max_credential_age_seconds <= 2592000:
            raise TrustError("invalid credential freshness limit")

    def as_dict(self) -> dict[str, Any]:
        return {"policy_id": self.policy_id, "tenant": self.tenant,
                "audience": self.audience, "purpose": self.purpose,
                "allowed_issuers": list(self.allowed_issuers),
                "rules": [r.as_dict() for r in self.rules],
                "max_age_seconds": self.max_age_seconds,
                "require_hardware_identity": self.require_hardware_identity,
                "max_credential_age_seconds": self.max_credential_age_seconds}

    @property
    def sha256(self) -> str:
        return digest(self.as_dict())

    def evaluate(self, issuer: str, claims: Mapping[str, Any]) -> list[str]:
        reasons = []
        if issuer not in self.allowed_issuers:
            reasons.append("ISSUER_NOT_ALLOWED")
        for rule in self.rules:
            if not rule.check(claims):
                reasons.append(f"CONTROL_FAILED:{rule.field}")
        return reasons


class IssuerRegistry:
    """Explicit tenant-scoped trust roots. Operator must persist/load them securely."""

    def __init__(self) -> None:
        self._keys: dict[tuple[str, str, str], Ed25519PublicKey] = {}
        self._revoked: set[tuple[str, str, str]] = set()

    def enroll(self, tenant: str, issuer: str, key_id: str,
               public_key: Ed25519PublicKey) -> None:
        slot = (identifier(tenant), identifier(issuer), identifier(key_id))
        if not isinstance(public_key, Ed25519PublicKey) or slot in self._keys or slot in self._revoked:
            raise TrustError("invalid or duplicate issuer key enrollment")
        self._keys[slot] = public_key

    def revoke(self, tenant: str, issuer: str, key_id: str) -> None:
        slot = (identifier(tenant), identifier(issuer), identifier(key_id))
        self._revoked.add(slot)
        self._keys.pop(slot, None)

    def lookup(self, tenant: str, issuer: str, key_id: str) -> Ed25519PublicKey:
        try:
            return self._keys[(identifier(tenant), identifier(issuer), identifier(key_id))]
        except KeyError as exc:
            raise TrustError("issuer key not enrolled or revoked") from exc

    def hardware_verified(self, tenant: str, issuer: str, key_id: str, *, now: int) -> bool:
        """Software enrollment alone never establishes hardware provenance."""
        return False
