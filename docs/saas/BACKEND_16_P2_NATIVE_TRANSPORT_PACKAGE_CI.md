# Backend16 P2: isolated Native Bun transport package (CI only)

Base: PR #105, `3b82a99e2798e2d0b05cbd3f70bef815ab01ea1a`.
**BLOCKED_RELEASE / NO RELEASE AUTHORIZATION.**

## What is new

`scripts/saas-staging/backend16-native-transport-package-ci/` is a private,
zero-external-package library template with its own `package.json`, text
`bun.lock`, explicit namespace exports, Bun build recipe and emitted-code smoke.
It is NOT a root workspace and does not import the frontend's dependencies.
The seven existing manually reviewed transport/vault/mTLS/private-read source
modules are copied byte-for-byte into a fresh temporary package. Existing
source-closure validation runs against both the checkout and each copied tree.
No source review pins are regenerated. Root `bun@1.3.14` and `bun.lock` stay intact.

The mandatory extra step in the official-stable TLS workflow runs only AFTER
all original stable mTLS and native peer TLS positive/negative probes succeed.
It reuses the unchanged official Bun 1.4.4 installer. Before running the binary,
the parent rechecks its release ZIP integrity and compares the installed ELF's
SHA256 to the exact ZIP member. This is byte consistency, NOT publisher signing
or approval of the runtime.

## Actual recipe and independent checks

1. Exact PR-HEAD, Node24, Linux/x64 and disposable-only environment checks run
   before staging. Railway contexts and production are refused. The five package
   template filenames are closed; manifest/lock have explicit review SHA256 pins.
2. Two separate cold temporary directories each receive only the package inputs
   and the unchanged seven-module source closure. Each has a fresh HOME, config,
   install cache and transpiler cache. No loader flags, proxy settings, database
   credentials, GitHub tokens or arbitrary inherited environment enter Bun.
3. Each Bun subprocess runs as the original NON-root runner user in a newly
   created Linux network namespace. There are no uplink interfaces. The build
   and smoke assert that the namespace differs from the supervisor and only `lo`
   exists. Missing sudo/unshare/setpriv capability is a hard failure, not fallback.
4. `bun install --frozen-lockfile --ignore-scripts --dry-run` validates the
   checked-in zero-package lock. The parent verifies that both input files remain
   byte-identical and `node_modules` was not created. This is deliberately a
   **frozen dry run, not a dependency installation**: there are zero packages to
   install. Do not infer a general-purpose package installation proof from it.
5. `Bun.build` emits one ESM transport library, using target `bun`, no splitting,
   no source map, no plugins and disabled environment injection. The compiler's
   metafile must contain exactly the entrypoint and seven copied modules, their
   actual byte sizes, and only reviewed internal imports or `node:crypto`,
   `node:https`, `node:tls`. Unknown input/output files, package imports, dynamic
   imports, `require` edges, path escapes and mismatched sizes fail closed.
6. The entire staged package, including source, manifest and lock, is deleted
   before a fresh Bun process imports ONLY the emitted module from a separate
   directory. Smoke exercises exported functions: malformed read configuration,
   invalid principal with zero pool acquisitions, SQL sequence rejection, and
   the unchanged staging facade's release hard stop despite forged staging flags.
7. Both builds must have identical manifest, lock, recipe, normalized import-graph,
   source-inventory and emitted-bundle SHA256 values. The root inputs, original
   source inventory and installed binary are checked again before the final
   structured receipt and PASS markers. Temporary bundles and metadata are erased.

This is process/environment/network separation on ONE GitHub runner, NOT a hostile
filesystem sandbox, independent administration or a signed build attestation.
The receipt reports `transportBundleBuilt=true`, `serverArtifactBuilt=false`,
`stableRuntimeApproved=false`, `stagingAuthorized=false`,
`productionAuthorized=false`, and `releaseState=BLOCKED_RELEASE`.

## Regression routing and preservation

New executable/package paths remain under `scripts/saas-staging/**`, so the
unchanged full physical PostgreSQL16/RLS workflow watches them. The new template,
verifier, tests and documentation also explicitly trigger stable TLS, pinned
canary TLS and Native source cross-runner workflows. Stable packaging additionally
watches its reused source-closure policy and verifier.

Nine dependency-free Node tests exercise metadata injection, duplicated JSON
keys, concealed whitespace, hooks/workspaces, file aliases/permissions/limits,
environment allowlisting, graph tampering, receipt substitution, release claims,
and workflow routing. Removing only the newly added paths and final stable step
recovers each of the three previous workflow blobs byte-for-byte. No old canary,
Node pg, stable, SQL0008, mTLS or revocation assertion is removed or weakened.

## Explicit gaps -- do not promote this receipt

This is the first emitted transport-library package, not an HTTP server or a
standalone executable. It does not implement OIDC session authority, off-host
mandatory audit, ingress, full server composition or deployment. The existing
17-field full-server evidence contract remains untouched with null evidence and
all release permissions false. A CI-only subset manifest/lock cannot satisfy the
full server's manifest/lock gates by renaming a field or copying these hashes.

The two emitted builds are on the SAME runner and SAME candidate binary; their
byte match is not independently reproducible executable evidence. The original
cross-runner checks still attest SOURCE inventory only. The three builtins and
empty npm graph are not a complete runtime/transitive SBOM for Bun's executable.
No signing root, publisher provenance, independent human security/operations
approval or production runtime support claim is introduced.

The pre-existing physical TLS/mTLS/SQL0008 tests still exercise their original
source entrypoints. This increment does NOT claim that the emitted ESM bundle
has passed the full composed mTLS -> vault -> PostgreSQL16 scenario. That bundle-
level physical acceptance is a distinct next test before expanding server
composition. Live staging, SQL0008 installation/replay, real credentials, Railway,
Core/Gateway, tags, releases and merging remain outside this change.

## Verification

Local Node22: nine tests, syntax checks and YAML/byte-preservation checks.
No local Bun, Docker or PostgreSQL execution is claimed. Actual frozen-lock,
network-namespace, two-build and emitted-only smoke results must come from a
fresh exact-HEAD GitHub Actions run; the PR record stores those results separately.
