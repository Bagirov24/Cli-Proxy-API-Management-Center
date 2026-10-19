# Backend16.21 — combined version-pinned vault + private mTLS reader review

**Status:** isolated **source-only integration candidate**; no Railway deployment,
real IAM broker, PostgreSQL credential, production release or schema migration.

## Pinned source composition

This integration branch starts at the exact PR #69 head
`4e097b5fa3451d719703ecf15e9c97be58bdb2a1` (the private mTLS secret
reader, based on #64 and ultimately #60). It then overlays *only* the three
version-pinned vault files from PR #68 head
`7ad8c26e3cf4c5de6030c52521c7c5c6b6d06a90`:

- `backend16StagingVersionedPrincipalVault.ts` —
  Git blob `435b8c679459e9d5853b8d7430c76ad5bf8ce7d8`
- `saasBackend16StagingVersionedPrincipalVault.test.ts` —
  Git blob `35e770161cbd080a4327cd74096b582d3b3dea88`
- `BACKEND_16_11_VERSIONED_PRINCIPAL_VAULT.md` —
  Git blob `d57a0d8fade2e4e59a19a2d83bf974e56f9d51b7`

This is **not** an upstream merge, a substitute for independent security
review, or an approval to merge the whole integration branch directly to
`main`. PR #60, #64, #68 and #69 remain independently reviewable.

## Joint contract

A successful disposable real-mTLS secret exchange is routed through the
*updated* version-pinned vault, rather than merely importing the two modules.
The native Node 24 acceptance runner must prove:

1. The approved secret ID/version and exact LOGIN produce the expected
   synthetic credentials from one authenticated mutual-TLS GET.
2. The vault captures the operator's SHA256 manifest digest and provider
   method before asynchronous digest verification and refuses runtime
   `nowMs` injection or noncanonical config objects.
3. A broker that responds after local workload approval revocation cannot
   return a secret from `reader.readVersion` **or**
   `vault.readPrincipal`; each rejected request uses precisely one
   network GET and no retry or cached credential.
4. Previously pinned CA/leaf, exact SAN, no redirect, body limits, cancellation
   and generic error contracts still hold, together with the actual Bun
   mTLS client test.
5. The GitHub Actions native PostgreSQL16 test remains ephemeral and
   must never attach to or re-run SQL0008 on permanent Railway staging.

The evidence markers are:
`B16_MTLS_BROKER_CI_INFLIGHT_APPROVAL_REVOKED_DENY`
and `B16_MTLS_VAULT_CI_INFLIGHT_APPROVAL_REVOKED_DENY`.
Neither marker alone is a production credential-vault acceptance.

## Release sequence and non-negotiable stops

Review PR #60 and its vault changes independently, along with PR #68.
Review PR #64 and PR #69 independently. Reconcile all reviewed changes
onto **one** pinned commit, then require the complete six-workflow
CI matrix including native mTLS and disposable PostgreSQL16 E2E.
Only after those reviews and CI can an authorized maintainer decide on
main-branch merges; follow-up E2E is **not** evidence of live Railway
Vault/IAM, provider revocation, root/SAN trust, OIDC, audit or recovery.

Permanent Railway staging SQL0008 was installed once on 2026-10-19 and
independently reconciled as INSTALLED:
`36fb4858-3d5b-4c15-a115-ba4a2a56cba6` installer PASS,
`623f00ff-92f0-4fb5-9a91-d7ba0d33a3df` read-only installed PASS.
Do **not** recreate the installer or replay SQL0008 for any reason.
No production Core/Gateway change, `custom-no-apikey-fun` action,
`/data` write or Railway volume operation belongs to this stage.
