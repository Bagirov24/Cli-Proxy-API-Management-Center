# Backend16: candidate Node24 PostgreSQL package-lock gate (source only)

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
