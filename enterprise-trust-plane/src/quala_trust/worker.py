"""ABRAXAS verifier in a separate process, with bounded JSON stdin/stdout.

Transport, access control, hardware providers and independent hosting are
deployment integrations. There is deliberately no unauthenticated TCP server.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .identity import PersistentIssuerRegistry
from .ledger import TrustLedger
from .passport import PassportTrustPlane
from .protocol import (MAX_WIRE_BYTES, Policy, Rule, TrustError, canonical,
                       loads_strict, _is_hex256)


def private_file(path: Path) -> bytes:
    """Refuse symlinks, shared permissions, wrong owners and oversized keys."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 128:
            raise TrustError("verifier key file must be private and owned by this account")
        value = os.read(fd, 129).strip().decode("ascii")
        if not _is_hex256(value):
            raise TrustError("invalid verifier key encoding")
        return bytes.fromhex(value)
    finally:
        os.close(fd)


def policy_from_dict(body):
    fields = {"policy_id", "tenant", "audience", "purpose", "allowed_issuers", "rules",
              "max_age_seconds", "require_hardware_identity", "max_credential_age_seconds"}
    if type(body) is not dict or set(body) != fields or type(body["rules"]) is not list or type(body["allowed_issuers"]) is not list:
        raise TrustError("invalid configured policy")
    rules = []
    for r in body["rules"]:
        if type(r) is not dict or set(r) != {"field", "operation", "value"}:
            raise TrustError("invalid configured rule")
        value = r["value"]
        if r["operation"] == "one_of":
            if type(value) is not list:
                raise TrustError("invalid one_of rule")
            value = tuple(value)
        rules.append(Rule(r["field"], r["operation"], value))
    return Policy(**{**body, "allowed_issuers": tuple(body["allowed_issuers"]), "rules": tuple(rules)})


def load_plane(config_path, db_path):
    config_file = Path(config_path).resolve(strict=True)
    if config_file.stat().st_uid != os.getuid() or config_file.stat().st_mode & 0o022:
        raise TrustError("operator configuration must not be writable by other accounts")
    with config_file.open("rb") as f:
        config = loads_strict(f.read(MAX_WIRE_BYTES + 1))
    if type(config) is not dict or set(config) != {"version", "verifier_id", "verifier_key_file", "roots", "policies"} or config["version"] != "abraxas-worker-v1":
        raise TrustError("invalid worker configuration")
    if type(config["roots"]) is not list or len(config["roots"]) > 32 or type(config["policies"]) is not list or not 1 <= len(config["policies"]) <= 32:
        raise TrustError("invalid trust root or policy list")
    if type(config["verifier_key_file"]) is not str:
        raise TrustError("invalid verifier key path")
    key_path = config_file.parent / config["verifier_key_file"]
    key = Ed25519PrivateKey.from_private_bytes(private_file(key_path))
    ledger = TrustLedger(db_path)
    try:
        registry = PersistentIssuerRegistry(ledger)
        # Restrict runtime lookups to exactly the operator's current root list.
        roots = set()
        for root in config["roots"]:
            if type(root) is not dict or set(root) != {"tenant", "issuer", "key_id", "public_key"} or not _is_hex256(root["public_key"]):
                raise TrustError("invalid configured trust root")
            slot = (root["tenant"], root["issuer"], root["key_id"])
            if slot in roots:
                raise TrustError("duplicate configured root")
            roots.add(slot)
            public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(root["public_key"]))
            existing = ledger.db.execute("SELECT public_key,revoked FROM issuer_roots WHERE tenant=? AND issuer=? AND key_id=?", slot).fetchone()
            if existing:
                if existing != (root["public_key"], 0):
                    raise TrustError("configured root changed or revoked")
            else:
                registry.enroll(*slot, public)
        original_lookup = registry.lookup
        def restricted_lookup(tenant, issuer, key_id):
            if (tenant, issuer, key_id) not in roots:
                raise TrustError("issuer not in current operator configuration")
            return original_lookup(tenant, issuer, key_id)
        registry.lookup = restricted_lookup
        plane = PassportTrustPlane(ledger, registry, config["verifier_id"], key)
        for body in config["policies"]:
            plane.add_policy(policy_from_dict(body))
        return plane
    except BaseException:
        ledger.close()
        raise


def dispatch(plane, request):
    if type(request) is not dict or type(request.get("action")) is not str:
        raise TrustError("invalid request")
    fields = {"action", "tenant", "audience", "purpose"}
    action = request["action"]
    if action == "challenge" and set(request) == fields:
        return plane.challenge(**{k: request[k] for k in fields - {"action"}})
    if action == "decide_passport" and set(request) == fields | {"submission"}:
        return plane.decide_passport(request["submission"], **{k: request[k] for k in fields - {"action"}})
    raise TrustError("unsupported action or request fields")


def main():
    parser = argparse.ArgumentParser(description="Separate ABRAXAS verification process")
    parser.add_argument("--config", required=True)
    parser.add_argument("--database", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    plane = load_plane(args.config, args.database)
    try:
        while True:
            line = sys.stdin.buffer.readline(MAX_WIRE_BYTES + 1)
            if not line:
                return
            if len(line) > MAX_WIRE_BYTES:
                sys.stdout.write('{"error":"DENY_OVERSIZED_REQUEST"}\n')
                sys.stdout.flush()
                return
            try:
                result = {"result": dispatch(plane, loads_strict(line))}
            except (TrustError, ValueError, TypeError, KeyError):
                result = {"error": "DENY_INVALID_REQUEST"}
            sys.stdout.write(canonical(result).decode("ascii") + "\n")
            sys.stdout.flush()
    finally:
        plane.ledger.close()


if __name__ == "__main__":
    main()
