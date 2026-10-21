# Backend16 P1 — offline stable Native Bun archive preflight

**Status 2026-10-21:** `NATIVE_BUN_TARGET_SELECTED`,
`STABLE_RUNTIME_UNAVAILABLE`, `BLOCKED_RELEASE`.
This is **security review preparation**, not runtime approval,
signed provenance, release attestation, installer or deployment.

## Context

Option A **Native Bun.SQL** is the selected future physical PostgreSQL
transport. Node24 `pg` remains an independent CI-only transport
comparator, **not a production fallback**.

The official [Bun releases](https://github.com/oven-sh/bun/releases)
still showed stable **1.4.3** when checked on 2026-10-21; no
`bun-v1.4.4` tag was found. Stable Bun 1.3.14/1.4.3 failed required
same-socket TLS callback/wildcard negatives. The SHA512-pinned
`1.4.4-canary.1+6bb5dc195` passed the disposable CI negatives but
is **CI-only** and must always be refused as a stable candidate.

## Offline verification, not runtime approval

`verify-backend16-native-stable-archive-preflight.mjs` exports pure,
no-side-effect checks:

- `assertBackend16StableNativeBunDescriptor(descriptor)` requires
  an exact schema with no extra fields, `@oven/bun-linux-x64`
  (Linux x64 only), official HTTPS registry tarball URL, a
  strict non-prerelease semantic version **at least 1.4.4**,
  40-hex pinned full source revision, exactly bound
  `<version>+<first_9_source_hex>` CLI revision, an exact archive
  length (1–150 MB) and canonical SHA512 base64 digest.
  Wrong origin, path/query, floating/latest/canary/RC, unsupported
  platform, fake revision, bad padding or unknown fields fail closed.
- `inspectBackend16StableNativeBunArchive(descriptor, bytes)`
  verifies provided archive length and actual byte SHA512 using
  constant-time digest comparison. It performs **no fetch,
  extraction, execution, install, PATH modification or SQL access**.
  It can return only `ARCHIVE_INTEGRITY_ONLY_NOT_APPROVED` and
  `stableRuntimeApproved:false`, `stagingAuthorized:false`,
  `productionAuthorized:false`.
- Direct CLI invocation exits nonzero with a hard stop, so merely
  running the module cannot make a release check green.

The unit test has a **fictional `1.4.4` metadata object with dummy
bytes**. A positive test is proof of the parser/checksum algorithm,
not proof a stable upstream release exists, publisher provenance,
a genuine Bun binary or working PostgreSQL peer authentication.
No stable candidate manifest is checked in here.

The existing independent Native TLS CI workflow now triggers on
the preflight source, tests and document. It must run offline
regressions before the unchanged SHA512-pinned canary installer and
real disposable PostgreSQL16 negative TLS checks. The full PG16/RLS
workflow also remains mandatory; this does not replace it.

## Independent stable candidate procedure (not executed)

1. Wait for a supported **published stable** Bun release newer than
   the known failing versions. Independently confirm tag, exact
   npm package origin/publisher, source SHA, CLI revision and OS/arch.
2. Obtain a security-reviewed, separately pinned SHA512 and byte
   count **before** testing archive content. Never auto-update the
   expected digest simply to make CI green. Verify real archive bytes
   with the offline preflight; do not treat a matching hash as a
   cryptographic publisher attestation.
3. In a separately approved disposable CI workflow, only after
   reviewed archive integrity and safe extraction, verify the
   actual executable's `--revision` and `Bun.revision` against
   separately pinned metadata. This preflight **cannot execute it**.
4. Preserve all strict physical PostgreSQL16 acceptance: one-
   and two-argument Native SQL constructors with always-deny
   callback, authenticated same-PID TLS+exact SAN, wrong-root,
   CA-signed wildcard, CN-only, wrong SAN, two tenant RLS,
   lock/cancellation, COMMIT, revocation and PID disposal. Never
   skip or mark an expected security failure as green.
5. Independently approve reproducible server-only Bun package,
   dependency policy, signed provenance/SBOM, operator-owned
   live PKI/IAM/OIDC/audit/PITR, SQL0008 read-only receipt,
   genuine two-tenant E2E, rollback and ten signed release gates.
   A preflight by itself satisfies **none** of these.

The factory remains explicitly hard-stopped:
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false`.
Keep root `bun@1.3.14` and `bun.lock` unchanged; no Node production
fallback, root npm lockfile, global Bun upgrade, public listener,
permanent SQL0008 replay, Railway, live credentials/volumes/IAM,
Core/Gateway, `custom-no-apikey-fun`, deployment or GitHub Release.

**P1 stable runtime: BLOCKED_RELEASE. P2 server artifact: BLOCKED_RELEASE.**
