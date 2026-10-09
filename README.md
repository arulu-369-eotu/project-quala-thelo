# PROJECT QUA'LA THE'LO

A research core plus a tested enterprise trust prototype. The three enterprise
priorities are implemented in this order:

| Priority | Product | Current implementation | Next release gate |
| --- | --- | --- | --- |
| 1 | QUA'LA Trust Passport | Reusable issuer-signed vendor controls; holder-bound presentations; buyer policy; revocation; signed receipts | Independent review, issuer contracts and a measured procurement pilot |
| 2 | ABRAXAS 7 Enterprise Trust Plane | Separate verifier process; persistent enrolled roots; fail-closed hardware requirement; atomic replay protection and receipt outbox | A real hardware attestation adapter, remote transport, access control and isolated operations |
| 3 | PROOF-369 Assurance Network | Signed checkpoints, distinct-key witness quorum, fork rejection and licensing entitlement gate | Independently hosted witnesses, external validation, governance and settlement integrations |

See [the prioritized product plan](docs/ENTERPRISE_PARTNER_BLUEPRINT.md) and
[the security review](docs/SECURITY_REVIEW_2026-10-09.md). Passing a policy verifies
configured software evidence; it does not establish regulatory compliance,
hardware truth, quantum advantage, or financial settlement.

## Compartments

- `citadel-core/`: native X25519 + ML-KEM-1024 + HKDF-SHA512, surface-code
  measurement research and timed dynamical decoupling.
- `enterprise-trust-plane/`: the three trust product prototypes.
- `gm-369-dossier/`: declarative command-and-control research compartment.
- `supreme-sun-archive/`: declarative Supreme SUN research archive.
- `scripts/`: reproducible local crypto test dependency and secret-pattern scan.

## Verify locally on Linux, Python 3.12

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-ci.lock
python -m pip install --no-deps --no-build-isolation -e ./citadel-core -e ./enterprise-trust-plane
bash scripts/build_test_openssl.sh
export UQL_OPENSSL_LIBRARY="$PWD/.test-openssl/openssl-3.5.8/libcrypto.so.3"
python -m pytest -q citadel-core/tests enterprise-trust-plane/tests
python -m bandit -r citadel-core/uql_compiler enterprise-trust-plane/src -q
python -m pip_audit --strict --disable-pip --no-deps -r requirements-ci.lock
python scripts/scan_secrets.py
python enterprise-trust-plane/examples/trust_products_demo.py
```

The native secret-memory path requires Linux and an OpenSSL 3.5+ ML-KEM provider.
It fails closed when page locking or dump exclusion fails. The enterprise package
can be tested independently without that native library. The CI lock is for the
verified Python 3.12 environment; other environments need their own resolved and
audited lock.

## Cryptographic compatibility

Hybrid derivation now uses a versioned **v2** transcript commitment, with length
framing and SHA-512 over the recipient public bundle, ciphertext and bounded
context. The old path always exceeded its HKDF `info` limit for valid bundles.
There is no v1 fallback. Public bundles and ciphertexts retain their 1,600-byte
lengths, so applications must pin the derivation version in their protocol.
Key establishment alone does not authenticate a peer or confirm possession of
the derived key.

## Governance

`LICENSE` and `PATENTS.md` govern EL-SOCL v1.0 / CIME. This work preserves their
terms. The new entitlement code validates signed software access rights; it
does not implement the license's decentralized ledger or micro-royalty settlement
requirements. Commercial readiness remains contingent on those integrations and
independent validation.
