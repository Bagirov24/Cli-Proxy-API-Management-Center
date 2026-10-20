# Locked Node24 full-chain CI composition (Draft, no release)

Parent: PR #86, `7a479fd64b28f19b5300439fcb639ae62df29463`.
Verified main at start: `268c09f56b676eb5d222ed23c012ccfff862e652`.

## Reuse and provenance

All #75–86 are still open Draft PRs at inspection. #75 and #82–86 have
successful reported workflows. #76–81 retain failed native TLS acceptance.
This branch composes existing source; it does not merge any PR:

- #75–78: exact authenticated TLS SAN, disposable native/Node comparison,
  physical per-principal PG16 exact-session RLS adapter.
- #79: parallel combined experiment, deliberately not copied over the later #80.
- #80: existing synthetic mTLS broker, immutable-version vault and two-tenant E2E.
- #81 (`37b2b87d92ad54149874b6e936f0f35ba81929d1`): reuse the source/test
  snapshot including asynchronous socket quarantine and physical PID-death proof.
- #82–86: preserve dual independent npm resolution, SHA512 tarball integrity,
  historical canonical graph fingerprint and two frozen installs. Preserve #86
  isolated physical TLS job as a separate regression.

The source snapshot from #81 includes its original native Bun.SQL tests and
comparison workflows unchanged. Those RED gates remain release blockers.
No second broker, vault, SQL authorization implementation or new npm root lock
is introduced. Root `package.json` and `bun.lock` remain unchanged.

## New connection between existing tests

The existing exact-session PG16 shell fixture invokes the genuine-lock runner
instead of its old ad-hoc `npm install --package-lock=false`. Only after both
independent locks and both `npm ci --ignore-scripts` installs pass does the
runner invoke the existing full-chain E2E once per verified install.
The temporary directories are passed explicitly and validated as canonical,
distinct siblings. Each subprocess loads its own pg.Client from that directory;
there is no fixed `/tmp/b16-nodepg-peer` fallback in the combined path.

Both executions must finish successfully and print every required positive,
preauthentication denial, cancellation and PID-death marker exactly once.
Missing markers, timeout, nonzero exit or signal fail closed. Raw child logs
are captured and never forwarded by the new composition. Both installs are
removed by the lock runner's existing finally block, including on failure.
The original SQL0008 fixture is initialized once on throwaway GitHub PG16;
the second driver pass reuses the same valid sessions without replaying SQL.

New aggregate CI markers (not evidence until observed on exact HEAD):

- `B16_LOCKED_FULL_CHAIN_INDEPENDENT_A_PASS`
- `B16_LOCKED_FULL_CHAIN_INDEPENDENT_B_PASS`
- `B16_LOCKED_DUAL_INSTALL_MTLS_VAULT_PG16_EXACT_RLS_PASS`

The inherited native Bun.SQL wrong-root/wildcard test runs afterwards with
its original nonzero failure behavior. A successful aggregate Node marker
therefore does not imply globally green CI. Bun 1.4.3 comparison remains
separate and may also fail.

## Boundaries

Only synthetic local mTLS and GitHub's disposable postgres:16.6 service.
No permanent SQL0008, Railway, deployment, release, volumes, real IAM or
credentials, production Core/Gateway, or custom-no-apikey-fun changes.
No production server factory or frontend database package. Real operator trust,
IAM, credential rotation, durable audit/DR and signed-release gates remain
unverified. Production remains NO-GO. No merge is authorized.
