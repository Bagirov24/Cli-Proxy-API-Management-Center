# Backend16 owner-authorized source integration

The owner explicitly authorized merging all open PRs on 2026-10-20.
This integration includes the commit ancestry of #75вЂ“87. #79's first combined
runner is superseded by #80/#81 and the dual-locked #87 implementation; it is
removed instead of leaving two divergent broker/RLS paths. Its security cases
(exact mutual client authentication, immutable secret versions, preauthentication
revocation and physical tenant RLS) remain covered by the later E2E.

## Verified post-merge checkpoint and remaining gates (2026-10-21)

GitHub main HEAD was independently rechecked at
`b0fd2b66fba5fc93c4e669ba4240fe38aef9c40e`, with zero open PRs.
Its eight post-merge workflow runs completed successfully on 2026-10-20.
Main [CI 39486680786](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39486680786)
reported 2138 pass, 43 skip and 0 fail, with lint/typecheck/build successful.
The disposable [PG16/RLS run 39486761812](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39486761812)
logged `B16_LOCKED_FULL_CHAIN_INDEPENDENT_A_PASS`,
`B16_LOCKED_FULL_CHAIN_INDEPENDENT_B_PASS`,
`B16_LOCKED_DUAL_INSTALL_MTLS_VAULT_PG16_EXACT_RLS_PASS`,
`B16_NATIVE_SQL_TLS_ALWAYS_DENY_CALLBACK_ENFORCED`,
`B16_NATIVE_SQL_TLS_WRONG_ROOT_DENIED` and
`B16_NATIVE_SQL_TLS_CA_SIGNED_WILDCARD_DENIED`.
The independent [native probe 39486765495](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39486765495)
also completed successfully. These are **existing exact-SHA GitHub CI runs**,
not a new local execution or independent live-service attestation.

The preceding stacked Draft/RED paragraphs in some Backend16 documents are
historical records of earlier source and runtime snapshots, not a claim that
the merged CI-only canary still fails. Stable Bun 1.3.14/1.4.3 remain
unapproved for native same-socket peer identity. The staging factory keeps
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false`, while Node pg is a
disposable CI-only adapter, not an approved production server package.

**Next repository-local safety increment:** make
`.github/workflows/saas-staging-rls-ci.yml` pull-request path filters include
every principal transport, TLS trust, broker, vault and session-read module
used by the physical Backend16 acceptance. A source-only change to those
modules must rerun the **real disposable PG16/RLS workflow**, not rely
exclusively on unit tests or earlier green workflow runs. Guard the path list
with `tests/saasBackend16IntegrationWorkflow.test.ts`.
This coverage improvement cannot itself prove transport trust or allow rollout.

Still **unverified as live operator/release gates**: independently approved
private PostgreSQL root CA and verified-full authenticated staging socket,
independent real mTLS secret broker and per-LOGIN IAM/version rotation,
live OIDC/session revocation, durable independently witnessed off-host audit,
recoverability/PITR and restore drill, a reviewed stable server-runtime lock
and executable packaging, private two-tenant E2E with genuine identities,
canary rollback, archived signed technical receipts and independent security
and operations release approvals. The installed permanent SQL0008 readback
is a historical staging observation, not a fresh signed one-hour release proof.
Do not replay SQL0008, provision Railway, touch Core/Gateway or `/data`,
publish a release or flip the native TLS hard stop to obtain green CI.


## CI host toolchain drift observed on PR #89 (2026-10-21)

Candidate `bfab6533f71bbc388ffb7a12f87a5980a9ba49b7` activated the
physical PG16 workflow as intended and passed Main CI, private read,
locked Node24 physical TLS, Demo and Management verification.
Two independent workflow failures were diagnosed from full job logs:

- [Browser QA 39553481948](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39553481948):
  Playwright 1.55.0 could not install Chromium on newly selected
  `ubuntu26.04-x64`.
- [PG16/RLS 39553481996](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39553481996):
  a newer host `pg_dump` generated `SET transaction_timeout = 0;`,
  causing genuine `pg_restore --exit-on-error` against the unchanged
  `postgres:16.6` service to fail. Earlier PG16 checks passed; all
  subsequent physical tests were **not reached**, not skipped-successful.

The proposed source-only correction pins those two workflows to
`ubuntu-24.04`, and adds a **fail-closed PostgreSQL 16 client setup**
that checks the actual `psql`, `pg_dump`, `pg_restore`, `createdb` and
`dropdb` executable versions before any PostgreSQL acceptance.
The versioned bin directory is propagated to subsequent steps, including
the Node child processes that perform real two-database dump/restoration.
No dump filters, SQL changes, expected failures, test skips, permanent DB,
Railway changes or identity/trust bypasses are allowed. This correction is
not accepted until all exact-head GitHub workflows, especially genuine
restoration and full Backend16 physical PG16/mTLS/TLS markers, pass.

## Native TLS blocker resolution candidate

Stable Bun 1.3.14 and 1.4.3 genuinely failed the same-socket security negatives.
The tests and their assertions remain mandatory; they are not expected-failure
checks, skipped checks, continue-on-error jobs or changed trust requirements.

Upstream fix: oven-sh/bun commit
`017b2439a7a75c82c7a86a294badd8ef2fc30e28` (SQL consolidation, 2026-10-17).
The publicly published immutable npm package
`@oven/bun-linux-x64@1.4.3-canary.20261019.1` contains native runtime
`1.4.4-canary.1+6bb5dc195`, full source revision
`6bb5dc1956505dd1113455f58d4757c924f3ad54`.

A CI-only installer downloads that exact tarball, verifies a checked-in SHA512
BEFORE extraction/execution, checks the exact executable revision, and exposes
its absolute temporary path only to the native PostgreSQL acceptance scripts.
It refuses non-GitHub, non-Node24, non-Linux-x64, production, Railway and
TLS-verification-disabled environments. There is no global install, PATH change,
frontend runtime upgrade, root npm lockfile or npm dependency added to the app.
Normal build/test/production package pin stays `bun@1.3.14`.

The native acceptance scripts reject any runtime other than this source revision.
The original wrong-root, CA-valid wildcard and always-deny-callback assertions
must all PASS against physical PG16 before integration is mergeable.
The separate no-migration native probe must independently PASS too.
Actual exact-HEAD results belong in the integration PR's evidence section.
A canary passing CI is not production runtime approval.

The staging factory's `NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false`
release hard stop remains. Its removal requires a stable reviewed server runtime
and real operator/release evidence. Source integration does not enable staging.

## Windows verification

Quota rendering tests previously assumed American dates/currency despite using
locale-dependent formatting. Their expectations now respect the host locale,
retaining exact amounts, dates, percentages and unavailable-data checks.
No user-visible quota behavior or translations change.

## Merge and release boundaries

Before merge: exact candidate SHA, every applicable CI workflow completed
successfully, MERGEABLE/CLEAN and unchanged main. Merge with matching-head
protection, preserve ancestry for the original PRs, then verify actual main CI.
No production readiness is inferred from test success. No Railway, deployment,
release, permanent SQL0008, IAM/credentials/volumes, Core/Gateway or
custom-no-apikey-fun mutation is part of this source integration.
