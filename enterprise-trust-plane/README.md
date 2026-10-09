# QUA'LA enterprise trust prototypes, v0.2

1. **Trust Passport**: issue_passport, present_passport and PassportTrustPlane.
2. **ABRAXAS 7**: PersistentIssuerRegistry and a separate abraxas-verifier worker.
3. **PROOF-369**: Witness, create_checkpoint, verify_anchor, EntitlementVerifier
   and licensed_receipt_access.

All application signatures are Ed25519, which is classical cryptography.
The hybrid post-quantum research core is separate and does not make these
signatures or worker transport post-quantum secure.

## Try the local synthetic demo

    python -m pip install -e ./enterprise-trust-plane
    python enterprise-trust-plane/examples/trust_products_demo.py

The demo uses local software keys and local witness files. It validates the API
flow without representing an independently operated network or actual hardware
attestation. It never handles real agreements or transfers money.

## Separate verification process

    abraxas-verifier --config /absolute/path/config.json --database /absolute/path/verifier.sqlite

Configuration is a bounded JSON object with version=abraxas-worker-v1,
verifier_id, verifier_key_file, roots and policies. Each root contains tenant,
issuer, key_id and the hex Ed25519 public_key. Each policy uses Policy.as_dict().
The key file contains a hex Ed25519 private key, is owned by the worker account,
is mode 0600, and is not a symlink. Protect the containing directory too.
Configuration cannot be writable by other accounts. Run the database in an
operator-owned private directory; restrict backups and all access to its files.

The worker reads one bounded JSON request per line, and replies with a result or
a generic DENY error. Requests are either challenge with tenant, audience and
purpose, or decide_passport with those fields plus submission from present_passport.
Caller-controlled timestamps and administrative enrollment/revocation actions
are not available through this channel. This is a process interface, not a
network service. Authenticate and isolate any transport added around it.

Issuer roots survive restart. Runtime lookup is restricted to the current
operator root list. Reusing a revoked key ID or changing its enrolled public key
is refused; enroll a new key ID for rotation. Administrative revocation methods
must only be called by the trusted operator. There is no automatic distributed
root synchronization. Hardware provenance is unavailable until a real adapter
is provisioned and independently reviewed. Revalidate hardware evidence on
restart; software enrollment alone is always insufficient.

## Evidence boundaries

Canonical JSON is this project's bounded integer-only format, not RFC 8785.
Passport control claims are disclosed to the verifier, while raw source evidence
is committed by hash. Issuer signatures assert claims; code cannot prove they
are true. Example sector policies are illustrative and require buyer approval.

One-time nonces and signed receipts commit in one SQLite transaction. A local
hash chain detects malformed/reordered history, but a privileged administrator
can rewrite storage and revocation state. Independently retained signed
checkpoints are needed for rollback detection. Witness quorum establishes signed
observation of a head, not legal or scientific truth. See THREAT_MODEL.md and
the root security review for the remaining release gates.
