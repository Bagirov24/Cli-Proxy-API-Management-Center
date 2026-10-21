# Backend16 — pinned standalone Node24 peer TLS experiment (CI only)

**Scope:** Disposable GitHub Actions Node24 + `postgres:16.6`. This
independent peer TLS experiment is **not** the obsolete #79 combined
broker/RLS runner, not a production transport and not a release gate.

## Prior gap

The standalone `.github/workflows/saas-backend16-nodepg-peer-ci.yml`
performed `npm install --no-save --package-lock=false pg@8.23.1` into
`/tmp` before its real PG16 TLS negative cases. Pinning only the
top-level package version did not verify its transitive npm resolution,
registry origins, SRI or historical observed canonical graph. Its success
could therefore be reported for a different dependency graph than the
locked full-chain acceptance.

## Shared dual-lock composition

The independent peer workflow now invokes the already-reviewed
`verify-backend16-nodepg-real-lock-ci.mjs` rather than installing an
unlocked third copy. Before running any physical peer probe, the existing
gate generates two independent Node24 npm lockfiles in separate temp
directories, checks each manifest/lock, source and SRI, matches both
graphs, compares the same **14-package canonical SHA256**:

`b5e2aa1735babcbca40748c0983a73c36c57488f96d857fd4087ae4e7a5341fa`

Only then does the existing gate execute two
`npm ci --ignore-scripts` installations and confirm both lockfile
digests remain unchanged. Neither a dependency, lockfile nor npm package
is added to the Bun frontend. The unchanged expected fingerprint
**MUST NOT** be automatically updated on registry drift.

A small peer-only composition runs the **existing**
`verify-backend16-nodepg-peer-ci.ts` against each verified install.
Its package path must match
`/tmp/b16-nodepg-dual-lock-ci-*/independent-a|b` and is passed
only by the scoped runner. No `pg` module is loaded from a global,
frontend or unreviewed package path.

## Mandatory real physical TLS security cases, for BOTH installs

- Authenticated physical PG16 PID and `pg_stat_ssl.ssl=true` with
  exact `postgres.railway.internal` SAN, callback invoked.
- Physical PID disappears on client close.
- Always-deny callback refuses before PostgreSQL authentication.
- Wrong root CA refuses.
- Same-root, CA-valid wildcard SAN refuses.
- Same-root wrong-host SAN refuses.
- CN-only certificate refuses.

Each existing probe marker must be observed exactly once per install;
a missing, duplicated, cancelled or errored run fails the entire
job. Only verified status/marker strings are emitted; raw npm or
child-process errors are not forwarded.

The full broker → vault → dual-LOGIN → SQL0008 exact-session RLS →
COMMIT → PID-disposal run remains the later #80/#81/#87 composition
and is **not** duplicated or replaced. This standalone test is
specifically transport peer identity and reuse of the genuine package
graph. It cannot substitute a signed operator CA, a stable approved
server package, independent mTLS/IAM, real OIDC or live release checks.

## Acceptance boundaries

On the exact candidate HEAD, require the standalone dual-locked peer
workflow, full disposable PG16/RLS workflow, locked private-read gates,
main CI, and normal checks to succeed. Preserve all prior
wrong-root/wildcard/CN-only and forced-callback assertions.

The project remains on `bun@1.3.14`; native canary Bun is CI-only.
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` is still a hard
release stop. No Railway, permanent SQL0008, credentials, IAM, volumes,
production Core/Gateway, `custom-no-apikey-fun`, deployment or
release operation belongs to this change.
