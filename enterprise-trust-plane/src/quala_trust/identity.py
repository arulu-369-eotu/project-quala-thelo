"""Persistent issuer roots and an explicitly provisioned hardware verifier seam."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .passport import instant
from .protocol import IssuerRegistry, TrustError, identifier, _is_hex256


@dataclass(frozen=True)
class HardwareIdentity:
    key_sha256: str
    evidence_sha256: str
    challenge: str
    not_before: int
    expires_at: int


class HardwareEvidenceVerifier(Protocol):
    """Adapters must validate actual certificates, trust roots and nonce binding."""
    def verify(self, *, public_key: bytes, evidence: bytes, challenge: str,
               now: int) -> HardwareIdentity: ...


class PersistentIssuerRegistry(IssuerRegistry):
    def __init__(self, ledger, *, hardware_verifiers: dict[str, HardwareEvidenceVerifier] | None = None):
        super().__init__()
        self.db = ledger.db
        self._hardware: dict[tuple[str, str, str], HardwareIdentity] = {}
        self._hardware_verifiers = dict(hardware_verifiers or {})
        self.db.execute("CREATE TABLE IF NOT EXISTS issuer_roots(tenant TEXT NOT NULL, issuer TEXT NOT NULL, key_id TEXT NOT NULL, public_key TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)), PRIMARY KEY(tenant,issuer,key_id))")

    def enroll(self, tenant: str, issuer: str, key_id: str, public_key: Ed25519PublicKey) -> None:
        slot = tuple(identifier(x) for x in (tenant, issuer, key_id))
        if not isinstance(public_key, Ed25519PublicKey):
            raise TrustError("invalid issuer public key")
        if self.db.execute("SELECT 1 FROM issuer_roots WHERE tenant=? AND issuer=? AND key_id=?", slot).fetchone():
            raise TrustError("duplicate or revoked issuer enrollment")
        self.db.execute("INSERT INTO issuer_roots VALUES(?,?,?,?,0)", (*slot, public_key.public_bytes_raw().hex()))

    def lookup(self, tenant: str, issuer: str, key_id: str) -> Ed25519PublicKey:
        slot = tuple(identifier(x) for x in (tenant, issuer, key_id))
        row = self.db.execute("SELECT public_key,revoked FROM issuer_roots WHERE tenant=? AND issuer=? AND key_id=?", slot).fetchone()
        if row is None or row[1] != 0 or not _is_hex256(row[0]):
            raise TrustError("issuer key not enrolled or revoked")
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(row[0]))

    def revoke(self, tenant: str, issuer: str, key_id: str) -> None:
        slot = tuple(identifier(x) for x in (tenant, issuer, key_id))
        # Even never-enrolled IDs get a tombstone, preventing later reuse.
        self.db.execute("INSERT INTO issuer_roots VALUES(?,?,?,'',1) ON CONFLICT(tenant,issuer,key_id) DO UPDATE SET revoked=1", slot)
        self._hardware.pop(slot, None)

    def verify_hardware(self, tenant: str, issuer: str, key_id: str, *, provider: str,
                        evidence: bytes, challenge: str, now: int | None = None) -> None:
        at = instant(now)
        key = self.lookup(tenant, issuer, key_id).public_bytes_raw()
        validator = self._hardware_verifiers.get(identifier(provider))
        if validator is None:
            raise TrustError("hardware attestation provider unavailable")
        if type(evidence) is not bytes or not 1 <= len(evidence) <= 65536 or not _is_hex256(challenge):
            raise TrustError("invalid hardware evidence")
        result = validator.verify(public_key=key, evidence=evidence, challenge=challenge, now=at)
        if (type(result) is not HardwareIdentity or result.key_sha256 != hashlib.sha256(key).hexdigest()
                or result.evidence_sha256 != hashlib.sha256(evidence).hexdigest()
                or result.challenge != challenge or type(result.not_before) is not int
                or type(result.expires_at) is not int or not result.not_before <= at < result.expires_at
                or not 1 <= result.expires_at - result.not_before <= 86400):
            raise TrustError("hardware attestation binding invalid")
        self._hardware[(tenant, issuer, key_id)] = result

    def hardware_verified(self, tenant: str, issuer: str, key_id: str, *, now: int) -> bool:
        key = self.lookup(tenant, issuer, key_id).public_bytes_raw()
        result = self._hardware.get((tenant, issuer, key_id))
        return bool(result and result.not_before <= now < result.expires_at
                    and result.key_sha256 == hashlib.sha256(key).hexdigest())
