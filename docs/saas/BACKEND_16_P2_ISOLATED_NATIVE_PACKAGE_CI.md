# Backend16 P2-a - isolated Native transport library packaging candidate

**Status: PATCH / NATIVE_BUILD_UNVERIFIED / BLOCKED_RELEASE.**

Prepared against PR #105 HEAD `3b82a99e2798e2d0b05cbd3f70bef815ab01ea1a`.
This change adds a CI package template, a build supervisor, an emitted-bundle
smoke test and an A/B workflow. It is NOT a bootable Bun server, approved runtime,
complete dependency lock, full SBOM, signed provenance or release permission.
No GitHub branch/PR was created and no native build was run during preparation.

## Scope and inputs

The existing seven-file source closure remains the review boundary. The new
input lock repeats those exact Git blob IDs, not freshly generated replacement
pins, and binds to the existing source inventory SHA256:

`9a0e30c78d1c2d07ee3b4695cdfa1d570f5c8f0e2f75f2371b010a8edad5687c`

The supervisor invokes the existing source-closure inspector before copying
those seven modules to a private temporary directory outside the repository.
No original modules are moved, rewritten or vendored into this patch. The
checked-in `index.ts` is a template; its `./src/` exists only after the supervisor
materializes the verified inputs. Running that template directly is unsupported.

The private package manifest pins `bun@1.4.4` ONLY for this CI candidate and has
no external, optional, peer or development packages, lifecycle scripts or
workspace links. The four copied template files are `package.json`,
`transport-inputs.lock.json`, `index.ts` and `smoke.mjs`.

### Source input lock is NOT a Bun dependency lock

`transport-inputs.lock.json` has the explicit scope
`SOURCE_INPUTS_ONLY_NOT_A_PACKAGE_MANAGER_LOCK`. It records seven fixed modules,
three permitted built-ins, zero external packages, and false approval flags.
It is not a second package manager's lockfile and is never passed to Bun install.

A handcrafted empty `bun.lock` was deliberately excluded from the final patch.
Upstream source at the pinned candidate revision
`38afee6c84fcf48c0edb2466aa4b27d287a59c30`, file
`src/install/PackageManager/PackageManagerDirectories.rs`, function
`save_lockfile`, has an empty-lock deletion branch. A claimed Bun-generated
lock without executing that exact runtime would be unsupported. No dummy
external dependency is added to force a lockfile to exist.

This dependency-free library needs no package-manager install. A genuine
server dependency lock, including any future OIDC/session/audit composition,
remains a separate P2 requirement. The receipts REQUIRE
`packageManagerLockVerified=false`; this change closes none of the 17 approval
slots in the historical all-null P2 evidence plan.

## Intended CI execution (not yet observed)

The workflow runs on `pull_request`, with `contents: read`, no real secrets,
no `pull_request_target`, no deployment and no manual release path. Two fresh
Ubuntu jobs check out the EXACT PR head, not GitHub's synthetic merge commit.
Node24 supervises only; the package is built and loaded using the existing
SHA256-pinned official stable Bun candidate installer, unchanged.

Each job MUST run the existing official candidate pin regression, frozen
source-closure inspector, historical all-null P2 evidence gate, and original real disposable PostgreSQL16 peer-TLS
positive/negative probe before attempting the new package build. The original
full physical RLS, mTLS, revocation and canary suites are not replaced by this
workflow. Their existing workflow definitions remain unchanged.

For the new build, only explicitly allowed environment variables reach Bun.
They include a new HOME/cache/tmp, fixed locale and PATH, but no application
LOGIN credentials, PG password, GitHub token, Railway variables, preloads,
proxy settings or parent environment options. Runtime transpiler caching and
automatic crash-report uploads are explicitly disabled. Ancestor frontend manifests,
node_modules, dotenv and compiler config files cause refusal.

The fixed recipe is:

```sh
bun build ./index.ts --target=bun --format=esm \
  --packages=bundle --outfile=./dist/transport.js
bun --no-install --no-env-file smoke.mjs
```

The supervisor calls the pinned binary by absolute path, never `bun` from
PATH. It verifies its revision and hashes its bytes before and after execution.
No `bun install`, `npm install`, lifecycle scripts or executable compilation
occurs. The emitted output must be exactly one bounded library file, without
source maps, extra packages or additional output files.

The smoke test imports the emitted bundle, checks its seven exported namespaces
and exercises default staging denial with zero credential lookups. This is NOT
PG acceptance of the bundle and does not isolate every staging-gate predicate.
In particular, its invalid configuration alone could also cause denial. The
unchanged seven-file byte pins, checked separately, retain the actual immutable
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` source hard stop.

All copied input bytes, the root manifest/lock and the prior P2 policy are read
back after the build. A malformed manifest, extra import, changed pin, symlink,
path escape, writable input, size overflow or unexpected file fails closed.

## A/B receipts and boundaries

Only a small unsigned JSON hash receipt leaves each build job; the temporary
library and its copied inputs are removed. No bundle is uploaded or published.
The compare job downloads only A and B artifacts from the current run/attempt.
It requires distinct lanes and equality of head, runtime revision/binary hash,
source inventory, copied inputs, build recipe, manifest, source input lock,
bundle hash and bundle byte count.

Missing or additional fields, a stale run/head, lane substitution, mismatched
bytes or approval flags all cause refusal. Matching receipts show same-run
byte agreement only. They do NOT authenticate a publisher, independently
approve code, prove reproducible upstream Bun compilation, or establish
independent administrative trust. Both jobs use GitHub-hosted infrastructure.
Actions follow the existing repository's `@v4` conventions; hardened,
SHA-pinned build provenance is not established by this patch.

Filesystem/environment isolation here is NOT an OS sandbox, network-denied
build, supply-chain attestation or complete hermeticity proof. A hostile native
runtime or compromised runner is outside this test's assurance. Built-in
runtime/native/transitive components are NOT covered by a full SBOM merely
because the package lists no npm dependencies.

Every successful receipt still states:

```json
{
  "packageManagerLockVerified": false,
  "serverEntrypointBuilt": false,
  "stableRuntimeApproved": false,
  "productionAuthorized": false,
  "releaseState": "BLOCKED_RELEASE"
}
```

## Verification actually performed during patch preparation

On local Node 22.16.0, 30 new guard/contract tests passed, with zero failures,
zero skips and zero cancelled tests. JavaScript syntax checks and the TypeScript
entry template syntax check passed. The YAML parsed and its exact PR trigger,
read-only permission, two build lanes and required comparison were checked.

No local Bun executable, full repository checkout, PostgreSQL16 or Docker run
was available. Thus the native recipe, emitted-bundle smoke, real TLS probe,
GitHub Actions behavior and cross-runner byte agreement remain UNVERIFIED.
Successful guard tests are not evidence that any of those native steps ran.
The supplied patch is add-only; full-repository apply/build/verify and independent
review are required before calling the candidate ready for integration.

## Preserved hard stops

No change to root `bun@1.3.14`, root `bun.lock`, existing source modules, prior
P2 all-null policy, original TLS negatives, canary, or deployment configuration.
No real IAM/OIDC/PKI, durable session authority, off-host audit, full runtime
SBOM, signed source-to-build provenance or independent security/operations
approval is supplied. No Railway, live database, permanent SQL0008 replay,
Core/Gateway modification, release, tag, merge or runtime opt-in is authorized.

Related existing contracts:
[seven-file closure](BACKEND_16_P2_NATIVE_SOURCE_CLOSURE.md),
[P2 artifact evidence plan](BACKEND_16_P2_NATIVE_SERVER_ARTIFACT_CONTRACT.md),
[PR105 composition](BACKEND_16_P1_STABLE_144_COMBINED_MTLS_PG16.md).
