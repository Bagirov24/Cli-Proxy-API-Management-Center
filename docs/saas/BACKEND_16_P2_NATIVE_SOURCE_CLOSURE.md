# Backend16 P2 — frozen Native Bun.SQL source-closure inventory (CI only)

**Status 2026-10-21: UNMOUNTED_SOURCE_CLOSURE_VERIFIED_ONLY.**
**NOT_A_PRODUCTION_SBOM.** This is NOT a Bun server artifact, complete
runtime dependency lock, executed build, vulnerability attestation,
signature, signed provenance, or permission to deploy.

## Why a source boundary now

[The Native Bun.SQL architecture ADR](BACKEND_16_P1_NATIVE_BUN_SQL_ADR.ru.md)
chooses Option A. The latest verified stable release remains Bun 1.4.3,
whose same-socket TLS peer-identity negatives fail; no trusted stable Bun
runtime or production package can yet be assembled.

The staging physical pool, exact-session SQL read, TLS trust, versioned
principal vault, mTLS broker client and private handler already exist as
**unmounted server-side source contracts**. It is useful to freeze their
precise review surface before creating a future independent Bun-only server
entrypoint or build. They are NOT currently a bootable server application:
operator-owned OIDC, persistent session authority, reviewed composition,
external PKI/IAM, off-host audit, packaging and live evidence remain missing.

## Offline, reviewed, fixed seven-file closure

`scripts/saas-staging/backend16-native-server-source-closure.v1.json` is
a manually reviewed policy for **exactly seven** Backend16 modules:

- `backend16StagingBunPhysicalPgPool.ts` — unmounted Bun.SQL physical pool
- `backend16StagingPgTlsTrust.ts` — branded TLS CA and exact SAN contract
- `backend16ExactSessionSqlRead.ts` — exact-session SQL read predicates
- `backend16PhysicalPgAdmission.ts` — physical PG LOGIN admission
- `backend16PrivateTenantProjectRead.ts` — unmounted private read port
- `backend16StagingVersionedPrincipalVault.ts` — immutable secret version
- `backend16PrivateMtlsVersionedSecretReader.ts` — private mTLS broker client

The policy lists each module's **exact reviewed Git blob SHA-1 ID** and
complete expected static type/value import graph. Allowed built-in imports
are only `node:crypto`, `node:https`, `node:tls`. There is **no**
`pg`/`pg-native`, React/Vite, Node production fallback, npm package,
public HTTP listener, OIDC implementation or downloaded dependency in
this *limited* physical-transport source inventory.

`verify-backend16-native-source-closure-ci.mjs` reads the fixed policy
from its own checked-in location, not a request, environment variable,
user-supplied path or mutable runtime config. It refuses:

- unexpected/missing modules, new imports, changed type/value edges,
  outside-module resolution, third-party, dynamic, re-exported or
  `require()` modules; `import.meta`, `eval()` and a public listener
- any file whose bytes differ from the reviewed Git object identifier
- file symlinks, writable files, untrusted directory symlinks, absent,
  nonregular or oversized entries
- a policy that claims `stableRuntimeApproved`,
  `serverArtifactBuilt` or `productionAuthorized`

The CI-only inspector also computes a deterministic SHA256 of the
observed **seven-file source inventory**, including relative paths,
file byte counts, Git blob IDs, full file SHA256 hashes, declared
imports and built-in dependencies. This serves as a **source-inventory
precursor** for a future independently reviewed SBOM; it is not an
actual CycloneDX/SPDX server dependency SBOM.

The Git blob SHA-1 pin binds to the reviewed repository object, not an
upstream supplier signature. The observed inventory SHA256 is calculated
from files in the current job; it is **not independently signed**,
publisher-authenticated or accepted as release provenance. A future
legitimate code change requires explicit review and coordinated
manifest-pin update. NEVER auto-refresh pinned hashes to get green CI.

Success markers are limited to:

`B16_NATIVE_BUN_SOURCE_CLOSURE_CI_PASS`

`B16_NATIVE_BUN_SOURCE_CLOSURE_SHA256=<observed_64_hex>`

`B16_NATIVE_BUN_SOURCE_CLOSURE_NO_SERVER_ARTIFACT`

`NO RELEASE AUTHORIZATION`

## Mandatory testing and exclusions

The independent Native TLS workflow runs both the pure adversarial source
tests and direct fail-closed inspector **before** the SHA512-pinned CI-only
Bun canary is installed and tested against real disposable PostgreSQL16.
The full PG16/RLS workflow must still run on source/policy changes and
exercise the existing mTLS broker → immutable vault → two independent
locked pg installations → exact-session RLS, COMMIT and PID death, plus
the Native wrong-root/wildcard/always-deny negatives. No test skips,
expected-failure or `continue-on-error`.

Even a PASS cannot authorize release. The independent stable Native Bun
binary/P1 TLS acceptance is still blocked; P2 still needs a real separately
reviewed **Bun-only package and lock**, reproducible server build, signed
provenance and actual complete SBOM. A full runtime inventory must extend
the current source surface with the selected session/OIDC, audit,
composition and server-only startup/shutdown implementation, all under
separate review. No executable server is added here.

Keep frontend `bun@1.3.14` / `bun.lock` unchanged. Keep
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` in the staging
factory. Keep Node24 `pg@8.23.1` CI-only as a security comparator,
not production fallback. Do not replay permanent SQL0008 or perform
Railway, real IAM/credentials/volumes, production Core/Gateway,
`custom-no-apikey-fun`, deployment or GitHub Release operations.
All ten live release gates remain `LIVE_UNVERIFIED`.
