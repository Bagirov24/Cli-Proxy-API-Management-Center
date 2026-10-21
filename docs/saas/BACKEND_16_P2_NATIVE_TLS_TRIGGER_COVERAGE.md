# Backend16 P2 — Native TLS pull-request trigger closure (CI only)

**Status:** `SOURCE_TRIGGER_COVERAGE_ONLY`, `BLOCKED_RELEASE`.
This change fixes a concrete CI coverage gap in the existing Native Bun.SQL
transport acceptance. It does not produce a Bun server artifact, package,
complete SBOM, signed attestation, stable runtime or live release receipt.

## What was missing

Before this change, the independent
`.github/workflows/saas-backend16-native-tls-experiment.yml` watched only
`backend16StagingPgTlsTrust.ts` from the **seven-file reviewed Native
source closure**. Changes to the other six pinned server modules could
trigger the full physical PG16 workflow and source-only cross-runner, but
would not necessarily trigger the **separate** Native TLS workflow.
The native workflow also did not watch
`scripts/saas-staging/verify-backend16-native-pg-tls-ci.ts`, the real
physical PostgreSQL16 Native TLS acceptance harness. This created a risk
of reusing earlier green Native acceptance instead of rerunning it for
an altered transport, broker, vault, SQL admission or physical test harness.

The independent Native TLS workflow now explicitly path-triggers on
**all seven exact pinned source files** plus the physical Native PG16
probe. No modules or source-review hashes were changed, and the
full physical PG16/RLS workflow's explicit module triggers stay intact.
The source-only two-runner reproducibility workflow still watches
`backend16*.ts` in the reviewed server directory.

## Fail-closed regression guard

`verify-backend16-native-tls-trigger-coverage-ci.mjs` independently
inspects the three GitHub workflow `on.pull_request.paths` lists against
the **reviewed, exact** source-closure manifest, not a fabricated list or
a comment string. It rejects missing, commented, duplicated, misspelled
or syntactically moved entries, unreviewed manifest drift, unexpected
fields, missing physical Native TLS harness triggers and absent new guard
source/test/document triggers. The Native workflow must execute the guard
before its fixed SHA512-pinned CI-only Bun canary installation, followed
by the real disposable PostgreSQL16 same-socket TLS probe.
The full PG16/RLS workflow, Ubuntu24.04/Node24, pinned `postgres:16.6`,
read-only permissions and rejection of `continue-on-error` remain required.

The independent cross-runner workflow executes these pure Node24 tests
in both proof jobs and the comparison job; Native TLS runs them before
the physical TLS probe. Physical PG16 also reruns for changes to this
guard, tests or documentation. No network, dependency installation,
Bun upgrade, listener, production credentials or deployment is introduced.

CI-only success markers:

`B16_NATIVE_TLS_SOURCE_TRIGGER_COVERAGE_CI_PASS`

`B16_NATIVE_TLS_SOURCE_TRIGGER_MODULE_COUNT=7`

`B16_NATIVE_TLS_SOURCE_TRIGGER_BLOCKED_RELEASE`

`NO RELEASE AUTHORIZATION`

These markers establish path/step routing, not success of physical TLS.
Physical wrong-root, CA-signed wildcard, one/two constructor always-deny
callback, exact-session two-tenant RLS, PID disposal, backup/restore and
mTLS broker/vault negatives must **also** succeed in their own real jobs.

## Boundaries

Keep root `bun@1.3.14` and `bun.lock`, the fixed Native canary strictly
CI-only and `NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` intact.
Node24 `pg` remains CI-only comparator, not a production fallback.
No SQL0008 replay, Railway, real IAM/PKI, live staging, deployment,
production Core/Gateway, approval fabrication, source hash refresh,
GitHub Release or merge. Stable Bun peer identity, full server-only build,
independent reviews and all ten signed live release gates remain blocked
or `LIVE_UNVERIFIED`. **Release decision: `BLOCKED_RELEASE`.**
