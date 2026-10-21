# Backend16 P2 — exact-head Native source-only reproducibility across GitHub runners

**Scope:** two independent disposable GitHub-hosted Ubuntu 24.04 / Node24
proof jobs, followed by a third comparison job. Each checks out the same
exact PR **HEAD SHA** (not the synthetic pull-request merge commit).
No package installs, source bundle, stable Bun runtime, PostgreSQL service,
deployment, server executable, signed provenance or release authorization.

## Reused verifiers and checked pins

This gate reuses three existing, independently reviewed offline validators:
the seven-module Native source closure (PR #97), deterministic source-only
CycloneDX and independent graph verifier (PR #98/#99), and the P2
`BLOCKED_RELEASE` 17-missing-proof artifact evidence contract (PR #100).
No source closure/policy or Bun pin is regenerated to make CI green.

Every runner must reproduce these manually pinned reviewed digests:

| Receipt | SHA256 |
| --- | --- |
| Seven-file source inventory | `9a0e30c78d1c2d07ee3b4695cdfa1d570f5c8f0e2f75f2371b010a8edad5687c` |
| Source-only CycloneDX JSON | `c8617a1c461757f3325909435693471df8253fde2044a313af6953c46ef199e3` |
| Future artifact **evidence plan** (not executable) | `df2aeac8f92113fb8896a099abd0d389e1674229a7ed71262e24bc68a8552186` |

These are local reviewer-pinned source fingerprints, **not** supply-chain
publisher identities, signature-verification keys or full SBOM digests.
The v1 P2 plan remains `BLOCKED_RELEASE` with 17 missing fields,
`stableRuntimeApproved:false`, `serverArtifactBuilt:false`,
`stagingAuthorized:false` and `productionAuthorized:false`.

## Independent hosted jobs

`.github/workflows/saas-backend16-native-source-repro-ci.yml`
contains `proof_a`, `proof_b` and dependent `compare` jobs, all on
`ubuntu-24.04` with `node-version: '24'`, read-only repository permissions,
disabled checkout credential persistence and explicit
`ref: github.event.pull_request.head.sha`.

Each proof job independently invokes the current source graph, BOM and
P2 artifact-contract verifiers. It checks an actual `git rev-parse HEAD`
against the PR head; `GITHUB_SHA` (the event's synthetic merge SHA)
is recorded separately so it cannot be mistaken for the checkout commit.
The only data transferred between jobs through GitHub-controlled
`GITHUB_OUTPUT` are slot A/B, head, event SHA, checkout, three
64-character digests and the literal `BLOCKED_RELEASE` status.

The comparison job starts only after **both** proof jobs succeed,
independently checks out the PR head and re-verifies its local source.
It checks expected slots, exact PR head and event SHAs, every digest,
receipt shape and the release hard stop. A missing, duplicated, substituted
or mismatched receipt causes failure; a single successful proof cannot
produce acceptance. `GITHUB_OUTPUT` must be the runner-managed
`_runner_file_commands/set_output_...` regular file under `RUNNER_TEMP`.
No policy hashes are silently refreshed.

Successful comparison prints:

- `B16_NATIVE_SOURCE_CROSS_RUNNER_EXACT_HEAD_MATCH_PASS`
- `B16_NATIVE_SOURCE_CROSS_RUNNER_SOURCE_SHA256=<reviewed_sha256>`
- `B16_NATIVE_SOURCE_CROSS_RUNNER_CYCLONEDX_SHA256=<reviewed_sha256>`
- `B16_NATIVE_SOURCE_CROSS_RUNNER_CONTRACT_SHA256=<reviewed_sha256>`
- `B16_NATIVE_SOURCE_CROSS_RUNNER_BLOCKED_RELEASE`
- `NO RELEASE AUTHORIZATION`

Unit tests cover deterministic independent copies, tampered files and
permissions, symlinks, wrong graph/checksums, untrusted environment,
fabricated/missing receipts, wrong slot, checkout/head/event mismatch
and direct CLI denial.

## Security boundaries

These are unsigned GitHub CI observations and **do not** prove full Bun-only
server build reproducibility, verified stable Bun peer identity, a complete
runtime SBOM, third-party dependencies, signed SLSA/provenance or live PKI/IAM.
The existing physical Native TLS and PostgreSQL16/RLS workflows remain
triggered by this script/test/workflow/doc change, and continue to test real
wrong-root, CA-signed wildcard, always-deny callback, PID lifecycle, tenant
RLS, backup/restore and broker/vault contracts. This offline cross-runner
comparison neither substitutes for nor simulates those acceptance tests.

Do not change root `bun@1.3.14` or `bun.lock`, upgrade the CI-only canary
into production, add a Node24 `pg` runtime fallback, change the
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` factory hard stop,
touch live credentials/IAM/Railway/Core/Gateway, replay permanent SQL0008,
deploy, tag a release or merge without independent review and explicit
owner authorization. All live gates remain `LIVE_UNVERIFIED` and
**release is `BLOCKED_RELEASE`**.
