# Backend16 owner-authorized source integration

The owner explicitly authorized merging all open PRs on 2026-10-20.
This integration includes the commit ancestry of #75вЂ“87. #79's first combined
runner is superseded by #80/#81 and the dual-locked #87 implementation; it is
removed instead of leaving two divergent broker/RLS paths. Its security cases
(exact mutual client authentication, immutable secret versions, preauthentication
revocation and physical tenant RLS) remain covered by the later E2E.

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
