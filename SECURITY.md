# Security reporting and release status

Use GitHub private vulnerability reporting if enabled, or request a private
reporting channel from repository maintainers. Do not post production credentials,
private keys or sensitive third-party information. No staffed response SLA is
asserted here.

This release repairs reproduced defects and adds adversarial regression tests,
pinned dependency hashes, known-vulnerability auditing, secret-pattern scanning
and pinned CI actions with read-only repository permissions. See
[the dated evidence report](docs/SECURITY_REVIEW_2026-10-09.md) for exact scope,
results and limitations. GitHub-hosted CI completion is a separate result from
local validation.

The native hybrid protocol, hardware attestation integrations, external witness
hosting and commercial settlement remain independent-review/release gates.
The code is an engineering prototype and research core, not production security
certification. Private-root/configuration custody and genuine administrative
separation are required for the stated operational trust model.
