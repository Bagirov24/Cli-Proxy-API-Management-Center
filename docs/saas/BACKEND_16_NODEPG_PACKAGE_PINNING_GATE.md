# Backend16: candidate Node24 PostgreSQL package-lock gate (source only)

> **Post-merge status (2026-10-21):** The Draft/unmerged remarks below describe earlier checkpoints. Main `b0fd2b66fba5fc93c4e669ba4240fe38aef9c40e` has merged the dual independent lock resolutions, observed 14-package `pg@8.23.1` graph fingerprint gate, two `npm ci --ignore-scripts` installs and separate full E2E. The observed canonical SHA256 stays unchanged and is **not** a signed production package approval. See [owner integration](BACKEND_16_OWNER_INTEGRATION.md).

**Status:** repository source-only candidate for independent review; not
approved, packaged, merged, staged or released. This prepares a verifiable part of a future
production transport decision. It does NOT change the unsafe native Bun.SQL
PostgreSQL TLS behaviour and must NOT disable its failing negative tests.

## Why

The isolated Node24 / node-postgres `pg@8.23.1` exact SAN, real PostgreSQL16
and mTLS -> pinned-vault -> tenant RLS tests were positive on the previous
checkpoint. The project currently installs this package temporarily under
`/tmp` in disposable CI. A production candidate needs an independently
reviewed **server-only** runtime package and a generated, reproducible lock;
adding `pg` to the React/Vite frontend or handcrafting an npm lock is unsafe.

The root `AGENTS.md` requires Bun 1.3.14 and expressly prohibits another
package manager's lockfile. This offline validator DOES NOT authorize a new
npm lockfile in the current repository. Such an isolated Node-only package
requires an independently approved packaging boundary before any lockfile
or runtime dependency is introduced.

The separate `verify-backend16-nodepg-runtime-lock.mjs` does **offline input
validation only**. It refuses candidate packaging unless:

- the isolated package is private and targets exactly Node 24;
- its only direct runtime dependency is `pg` version **8.23.1** (not a range);
- `package-lock.json` is v3 and agrees with the runtime manifest;
- every locked package is at an exact version, has canonical SHA-512 SRI and
  an HTTPS `registry.npmjs.org` tarball source, and has no install hook;
- native `pg-native`, implicit build addons, file/git/http sources or
  lifecycle scripts cannot enter the candidate packaging;
- the existing frontend manifest contains no `pg` package.

## Required follow-up when GitHub/Node24 workspace is available

1. Independently review the transport choice and registry package/tarballs.
2. Decide and document an isolated package-manager boundary consistent with
   project-wide AGENTS.md (existing frontend uses Bun 1.3.14). If npm is
   approved for the isolated Node24 server package, generate an authentic
   `package-lock.json` using a clean, disposable Node24 CI runner with the
   approved npm version. **Never invent lock digests.**
3. Run this offline check on that manifest + actual lock + root frontend
   manifest, then clean-install reproducibly with lifecycle scripts disabled.
4. Extend E2E to use the installed *server* package and exact locked client
   instead of `/tmp` install. Preserve all wrong-root, wildcard-SAN and async
   socket-error negative tests and actual physical backend PID checks.
5. Obtain independent supply-chain/security review, codeowners and current-
   head green CI. Complete live PKI, private mTLS/IAM, OIDC, off-host audit,
   restore/PITR/DR, canary/rollback and signed release gates separately.

**This check never grants production authorization.** No Railway access,
permanent SQL0008 replay, production Core/Gateway, `custom-no-apikey-fun`,
`/data`, credentials, volumes, releases or deployments are permitted by it.


## Next CI-only increment вЂ” genuine ephemeral dependency lock proof

A separate stacked Draft runs one new **isolated GitHub Actions Node24**
experiment. It writes a minimal private, Node24-specific server manifest into
a mode-restricted OS temp directory, asks npm to resolve a genuine
`package-lock.json` **only in that disposable directory**, applies the
existing offline fail-closed validator against the repository's frontend
manifest and then executes `npm ci --ignore-scripts` from that exact lock.

Both commands run with an isolated HOME/cache, fixed public npm HTTPS
registry, disabled lifecycle scripts, disabled audit/fund network calls and
without inherited tokens or Railway credentials. The script checks the
installed pg version, proves the generated lock was not rewritten and
deletes all manifests, package files and lock data after the job.

**No npm lock, npm dependency, server package or package manager selection
is committed or authorized by this CI experiment.** The repository continues
to require Bun 1.3.14 and `bun.lock`. The experiment is not a substitute
for inspecting actual tarball content, supply-chain review, reproducibility
across separate runners, future registry re-resolution drift or vendor
signatures. It is NOT production certification. Real server-only packaging
needs independent owner approval and a separately reviewed release decision.

The previous known native Bun.SQL same-socket wrong-root/wildcard TLS
negative MUST remain RED and cannot be skipped to make stacked CI green.
No staging/prod Railway operations, live credentials, permanent SQL0008,
public endpoint or migration are allowed.


## Independent ephemeral registry resolution (CI only)

The stacked Draft now checks two **independently generated** genuine Node24
npm v3 locks in two different one-use directories. Each uses its own
HOME, empty user/global npm configs and cache. Both locks are separately
verified against the existing exact `pg@8.23.1` dependency/HTTPS registry/SRI
contract. A stable, order-insensitive comparison of the complete JSON graph
(including all resolved origins and tarball integrity fields) must match
before *either* clean installation can proceed.

Only then does CI run `npm ci --ignore-scripts` independently against each
lock, ensure the original bytes were not modified, and inspect the installed
`pg` package metadata. The proof marker and canonical lock SHA-256 contain no
credentials. Both installations and locks are deleted with the disposable
workspace. No npm runtime package, npm lock, live secrets, staging SQL or
production deployment is added to the repository.

This is **short-window same-runner reproducibility evidence** and is not a
reviewed or independently signed production lock. Registry/tarball review,
cross-runner temporal reproducibility, Node server packaging approval,
security/codeowner sign-off, and real operator PKI/IAM remain OPEN.
The known native Bun.SQL PostgreSQL TLS wrong-root/wildcard failure remains
a blocking RED finding and must not be disabled.


## Historical cross-run drift gate (CI-only; unapproved observation)

A later Draft observes the successful **independently resolved** v3 npm
dependency graph from PR #84, workflow
[39422435534](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39422435534),
HEAD `471454fc05e180cfc0952f33e256e66288d128a1`.

- Canonical JSON SHA-256: `b5e2aa1735babcbca40748c0983a73c36c57488f96d857fd4087ae4e7a5341fa`.
- Direct dependency: `pg@8.23.1`, entire installed tree: **14 packages**.
- Both previously independent clean installs passed; these are observable
  historical CI facts, **not** a signed artifact or approved package set.

The CI runtime now checks both new independent lock resolutions against each
other **and then against this prior-run observed fingerprint**. Any SRI,
tarball URL, transitive version, graph structure or package-count change
fails closed **before either clean npm install**. Normal JSON key ordering
does not affect the canonical digest. Adjusting the observed fingerprint
must be treated as a reviewed dependency supply-chain change, never a
routine way to make CI green. One observed CI snapshot is not a release
authority, security audit, package provenance attestation or a substitute
for a separately approved immutable production server lock.

No production packaging, Railway access, permanent SQL0008, release
promotion, or mitigation claim for the known native Bun.SQL TLS failure is
introduced. Project-wide Bun lockfile rules stay unchanged.

## Stacked isolated locked-package PostgreSQL16 TLS proof (CI only)

An independent Draft pairs the **actual verified npm-lock installations** with
a different, throwaway `postgres:16.6` GitHub Actions service. After verifying
both independently resolved locks against each other and the observed graph,
CI authenticates a restricted synthetic PostgreSQL LOGIN using `pg@8.23.1`
*from each of the two installed directories*. The same physical authenticated
connection must verify CA chain, fixed `postgres.railway.internal` SNI and
**exact SAN without wildcard or CN fallback**, then return a backend PID and
`pg_stat_ssl.ssl=true`. Both connections must close, with PID disappearance
observed on the disposable service. Wrong-root CA and a CA-signed wildcard
SAN each must refuse authentication before any query.

CA/leaf private keys are generated in a one-use runner directory and
installed **only** into the disposable GitHub PostgreSQL16 Docker service,
which is deleted by Actions. No permanent SQL0008, tenant migration or
production database is touched. The script uses no public SaaS listener,
no Railway configuration and no live workload identities. It is intentionally
a narrow authenticated TLS transport proof and **does not claim an integrated
tenant RLS or mTLS secret-broker E2E**: those remain separately tested in the
unmerged Backend16 Node transport stack, pending independent review and
a separately approved runtime packaging decision.

This is source-only, opt-in, disposable CI evidence, not an approved
server runtime or staging/prod deployment. The RED Bun.SQL wrong-root/
wildcard TLS outcome remains a hard production blocker.
