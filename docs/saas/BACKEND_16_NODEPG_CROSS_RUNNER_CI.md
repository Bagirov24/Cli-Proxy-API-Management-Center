# Backend16 — cross-runner Node24 pg installed bytes acceptance (CI only)

**Scope:** one pull request, two distinct disposable GitHub-hosted Ubuntu
24.04 / Node24 jobs, one dependent comparison job. This is not an
approved server-only package, signed provenance, real Railway staging
evidence, a release gate, or permission to change production.

## Why

The previously verified Backend16 dual-lock gate independently resolves
two genuine npm v3 dependency graphs, verifies both sources/SHA512 SRI,
matches them against the unchanged historical 14-package canonical
SHA256
`b5e2aa1735babcbca40748c0983a73c36c57488f96d857fd4087ae4e7a5341fa`,
runs two `npm ci --ignore-scripts` installations, and hashes the installed
file trees. Two trees match within the same runner. Multiple earlier jobs
happened to observe identical tree digests, but no CI job *required*
separate hosted runner receipts to agree.

## Separate-job proof

`.github/workflows/saas-backend16-nodepg-cross-runner-ci.yml` has two
independent `proof_a` and `proof_b` hosted jobs. Each checks out the
same exact workflow GitHub SHA, validates source-only regression tests,
and invokes `verify-backend16-nodepg-cross-runner-ci.mjs record`.
The wrapper enforces GitHub pull_request, Linux X64, Node24, CI-only
environment with no Railway flags, no production mode, no physical
DB/broker flags and no unverified Node pg package directory.

Each job runs the **existing** dual-lock tool as a separate subprocess,
which creates, verifies and destroys TWO new ephemeral npm locks and
installs. Thus the cross-runner workflow performs four independent lock
resolutions and four clean installs in total, not one shared cache or
lockfile, and without any frontend npm dependency or lockfile.

The wrapper requires one occurrence each of the authentic resolution,
historical-graph-match, independent-resolution-match, installed-tree-match
and frozen-install markers, plus a single canonical final success line.
Marker order is verified. The sanitized child status must be zero,
with no signal, error or stderr. Raw npm output is never forwarded.
The wrapper extracts only the 64-character observed tree SHA256 and the
unchanged historical graph SHA256.

Each job writes only five bounded ASCII values to its GitHub-controlled
`GITHUB_OUTPUT`: immutable slot A/B, pull request HEAD SHA, checked-out
workflow SHA, historical graph digest and installed file-tree digest.
The independent `compare` job depends on BOTH successful proofs, checks
its actual checked-out SHA, checks both slot labels, the same exact
PR HEAD / GitHub checkout SHA, the canonical graph SHA256, complete
receipt shape, and equality of the two installed-tree SHA256 values.
Missing, malformed, mismatched or duplicated markers/receipts deny.

On success:

`B16_NODEPG_CROSS_RUNNER_FROZEN_BYTES_MATCH_PASS`

`B16_NODEPG_CROSS_RUNNER_TREE_SHA256=<observed_64_hex>`

`NO RELEASE AUTHORIZATION`

**Important:** GitHub-hosted jobs supply distinct disposable execution
environments, but this is an *unsigned GitHub Actions job-output
comparison*, not a cryptographically signed identity assertion by two
independent organizations or a vetted upstream publisher. The SHA256 is
observed evidence only; it must never become an automatically accepted
production fingerprint. Any registry/package drift MUST fail, not cause
an update to the historical canonical graph just to make CI green.

## Acceptance and hard stops

Exact-head CI must include all THREE cross-runner jobs SUCCESS,
Main CI, Backend16 Private Read, authenticated standalone Node pg peer
on disposable physical PostgreSQL16, and the full mTLS broker →
immutable vault → exact-session tenant SQL0008 RLS → COMMIT →
PID death + Native Bun TLS negative acceptance. Do not substitute the
new cross-runner job for a physical backend check.

This does not authorize an npm server package under the Bun frontend,
stable runtime selection, production supply-chain review, SBOM
approval, tarball provenance, signed operator gates, a real external
vault, live PKI/IAM/OIDC/audit/restore, or a staging/production rollout.
The root `bun@1.3.14` / `bun.lock` remains unchanged. CI-only Native
Bun canary stays segregated, and
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` remains a mandatory
release hard stop. Never deploy, publish a GitHub Release, apply permanent
SQL0008, edit Railway, live credentials/IAM/volumes, production
Core/Gateway or `custom-no-apikey-fun` through this change.
