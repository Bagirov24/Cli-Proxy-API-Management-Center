# Backend16 — two frozen Node24 pg byte trees (CI-only)

**Scope:** source-only disposable GitHub Node24 proof, not server packaging
approval, a live staging attestation, or permission to deploy. Do not change
the frontend root `bun@1.3.14` / `bun.lock`, add an npm root lockfile,
install global drivers or re-enable the unverified Native Bun.SQL staging
factory.

## Why this is separate from the npm lock graph

The existing `verify-backend16-nodepg-real-lock-ci.mjs` already performs
two independent npm v3 resolutions, manifest/origin/SRI verification, exact
canonical graph equality, historical 14-package SHA256
`b5e2aa1735babcbca40748c0983a73c36c57488f96d857fd4087ae4e7a5341fa`,
and two `npm ci --ignore-scripts`. Before this change it checked each
lockfile remained byte-identical and both installations' top-level
`pg@8.23.1` metadata. It did not separately compare **all installed file
bytes** in the two `node_modules` trees.

That leaves a CI-evidence gap: an unexpected post-install mutation of a
transitive file or an installed native/symlink payload might not be caught
by checking the lockfile and the top-level version alone.

## New fail-closed contract

`verify-backend16-nodepg-installed-tree-ci.mjs` recursively observes
each independent installation under its real, CI-created
`node_modules` root. It requires a regular `pg/package.json`,
rejects symlinks, nonregular entries, native `.node` payloads and
`pg-native` / `node-gyp` paths, denies world- or group-writable
entries and uses no shell or external network.

The file walker bounds directory depth (18), total entries (20,000),
regular files (12,000), individual file bytes (24 MB) and total files
(100 MB); refused content is never printed. Each file is opened
`O_NOFOLLOW` and compared to its original lstat inode/device/size to
reject a swapped symlink. The canonical SHA256 includes the entire sorted
relative path, byte length, executable bit and full file SHA256 for
every file, including npm's own hidden metadata. Two independently
produced receipts must have exactly equal digests, file counts and
total bytes. A missing byte, extra file, changed mode or different
package content blocks CI **before physical SQL/TLS tests**.

The runner prints only:
- `B16_NODEPG_FROZEN_TREE_INDEPENDENT_MATCH_PASS`
- `B16_NODEPG_FROZEN_TREE_SHA256=<observed_64_hex>`

The second hash is an **unsigned observation** of files on the same
disposable GitHub runner, not a historical fingerprint, a published
package digest or security approval. Do not hardcode it as a new expected
production digest. The existing historical lock fingerprint is
unchanged. A failed comparison must NOT lead to silently relaxing the
walker's bounds or updating the historical graph hash.

## Required evidence and remaining limitations

On an exact PR head, the genuine dual-lock runner must print the
original resolution/graph/frozen-install markers PLUS the new installed
tree marker **before** independent authenticated PostgreSQL16 TLS peers
and both mTLS broker → immutable vault → exact-session tenant RLS
full-chain tests. The isolated Node tests cover equal file trees,
tampering, extra files, symlinks, native addons, writable files,
oversized/deep entries and duplicate/forged receipts. The private-read,
standalone peer and full PG16 workflows all need to run when the
gate changes.

A separate [cross-runner CI proof](BACKEND_16_NODEPG_CROSS_RUNNER_CI.md)
now requires two independent GitHub-hosted jobs to match this installed
byte-tree hash before a comparison job succeeds. The proof is an
**unsigned CI job-output comparison**, not a supplier signature or
independent security approval.

Even matched installed bytes do not independently establish a signed
software provenance, upstream publisher identity, approved vulnerability
review, an independently signed reproducible build or a reviewed
production server artifact. The next P1/P2 stages remain a separate **stable runtime ADR**
and **server-only package lock/artifact approval**, followed by live
PKI/IAM/OIDC/audit/restore and independently signed staging release gates.
No production driver is wired into this React/Vite repository.

Permanent SQL0008 must never be replayed as part of this test.
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` remains a release
hard stop. No Railway operations, real credentials/volumes, deployment,
GitHub Releases, Core/Gateway or `custom-no-apikey-fun` changes.
