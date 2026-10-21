# Backend16 P2 — scoped CycloneDX inventory of reviewed Native Bun.SQL source

**Evidence level:** `UNMOUNTED_SOURCE_SCOPE_ONLY`,
`NOT_A_PRODUCTION_SBOM`, `BLOCKED_RELEASE`.

This source-only step follows the frozen seven-file
[Native Bun source closure](BACKEND_16_P2_NATIVE_SOURCE_CLOSURE.md)
and the [Option A Native Bun.SQL ADR](BACKEND_16_P1_NATIVE_BUN_SQL_ADR.ru.md).
It produces **deterministic CycloneDX 1.6-structured JSON for
the reviewed transport/vault/broker source files only**.
It does not produce a deployable executable, Bun server artifact,
complete production SBOM, approved runtime lock, a signed provenance
statement, publisher verification, or any live staging receipt.

## What is inventoried

The exact seven Git-pinned modules from the source closure policy:
the unmounted Native Bun physical pool, private TLS trust, exact-session
SQL predicate, physical LOGIN admission, mTLS broker client, immutable
versioned principal vault and private read interface. The source graph
contains only three allowed builtins (Node-compatible built-ins in Bun):
`node:crypto`, `node:https` and `node:tls`.

The independent
`build-backend16-native-source-cyclonedx-ci.mjs` first executes the
existing fail-closed reviewed source-closure verifier. It then
**independently re-opens every source file** with `O_NOFOLLOW`
and checks its inode/device/size, filesystem permissions and
Git blob ID, and reconstitutes the complete source-inventory
SHA256 receipt (including all import edges and hard-stop flags).
If the two reads differ, generation is refused.

The deterministic in-memory JSON has `bomFormat:'CycloneDX'`,
`specVersion:'1.6'`, seven `type:'file'` components, exact path
and SHA256 for each source, Git blob IDs and lengths in properties,
and seven source-level import-graph entries. The graph **includes
TypeScript type-only imports**, so it is expressly *not* the
compiled runtime dependency graph. Metadata links the JSON to the
reviewed source-inventory SHA256 and explicitly marks
`NOT_A_PRODUCTION_SBOM=true`, `serverArtifactBuilt=false`,
`stableRuntimeApproved=false` and `productionAuthorized=false`.

No timestamp, random serial number, mutable lock metadata or
runner filesystem path enters the canonical JSON. The generator
returns a SHA256 of the complete JSON bytes and can be
reproduced against a second independent copy of the reviewed
seven files. No third-party library, network fetch, executable
runtime, npm/bun install, API listener, persistent package,
artifact upload or new production dependency is introduced.

On CI-only direct invocation, after the new adversarial unit tests,
the allowed stdout is limited to:

`B16_NATIVE_BUN_SOURCE_CYCLONEDX_CI_PASS`

`B16_NATIVE_BUN_SOURCE_CYCLONEDX_SHA256=<observed_64_hex>`

`B16_NATIVE_BUN_SOURCE_CYCLONEDX_NOT_PRODUCTION_SBOM`

`NO RELEASE AUTHORIZATION`

The observed hash is NOT a release fingerprint, reviewer signature
or trusted upstream package checksum. Do not automatically update
source blob pins or expected fingerprints to force green CI.
No CycloneDX upstream-schema validation is claimed by this step;
a future independently audited **complete runtime SBOM** must
verify its schema and cover the final executable, all runtime and
transitive dependencies, build tools, binary hashes, sources,
licenses, vulnerabilities and signed provenance.

## Acceptance and safety boundaries

The independent Native TLS workflow triggers on this script,
tests and documentation and runs this source-only inventory
**before** installing its SHA512-pinned CI-only canary.
The full disposable PG16/RLS workflow must also rerun, including
wrong-root, CA-valid wildcard, always-deny callback, two tenant
exact-session mTLS broker → vault → physical PG16 admission,
COMMIT/PID release and backup/restore acceptance.
Unit tests prove deterministic copies, exact edge shape,
failure on source mutation/symlink/world-writable inputs,
unauthorized direct invocation and CI trigger coverage.
Never skip negative TLS tests or use `continue-on-error`.

**P1 stable Bun runtime is still unavailable** (latest observed
stable 1.4.3 fails the required same-socket TLS tests).
The fixed `1.4.4-canary.1+6bb5dc195` remains CI-only.
The user-selected Native Bun.SQL transport is NOT authorized for
production, and Node24 `pg` remains CI-only comparator.
The frontend `bun@1.3.14` and `bun.lock` are untouched.
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false`
remains the physical pool release hard stop. All ten real
staging operator gates are `LIVE_UNVERIFIED`.

No Railway, production Core/Gateway, IAM/credentials/volumes,
permanent SQL0008 replay, custom-no-apikey-fun, deployment,
GitHub Release, built server entrypoint or production packaging.
