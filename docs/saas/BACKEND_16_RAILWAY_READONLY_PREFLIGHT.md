# Backend16.16 — Railway staging SQL0008 INSTALLED-mode read-only postflight

**Intent:** independently reconcile the permanent `saas_staging` PostgreSQL16
catalog to exactly **eight** pinned receipts (`0001–0008`), with the SQL0008
function installed and migrator resealed. This is an installed-state diagnostic,
**never a migration installer, unsealer, retry mechanism, or production release approval**.

## Source and boundaries

- One-file Bun source: `scripts/saas-staging/backend16-railway-readonly-preflight.ts`.
- The `DO $b16_readonly$ … $b16_readonly$;` SQL is a byte-for-byte
  copy of the catalog verification body in
  `scripts/saas-staging/backend16-0008-readonly-reconcile.sql` from main
  `0df48301c16e29a23c5df56d5ed456cb03b8ec13`.
  CI asserts exact equality. Do not edit this body as part of deployment.
- The read-only Function sets the transaction-local, fixed
  `saas.staging_only=true` label after `BEGIN READ ONLY`, reproducing the
  **reviewed operator runbook** `PGOPTIONS='-c saas.staging_only=true'`.
  This label alone is **not authorization or trusted evidence of database
  identity**; the Railway IDs, private PostgreSQL hostname/database,
  authenticated postgres superuser, SQL0001–0007 immutable receipt provenance,
  force RLS, NOLOGIN seal and data emptiness are independently verified.
  Never set `saas.tenant_id`, change roles, or rely on this GUC to grant access.
- The Function is not the SQL0008 one-shot installer. It cannot apply any
  migration or unseal the migrator: the only transaction is
  `REPEATABLE READ READ ONLY`, with the fully reviewed SQL catalog probe.
- It requires Railway project `a9703851-6eb1-406c-bb15-7d3a89359fb7`,
  environment `b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b`, environment
  name `staging`, and Function name
  `saas-b16-0008-readonly-preflight`. It must not run in production.
- DB connection is accepted **only** for
  `postgres.railway.internal:5432/saas_staging` as `postgres`.
  Use the **private** Railway reference
  `STAGING_POSTGRES_PRIVATE_URL=${{Postgres.DATABASE_URL}}`;
  never a public TCP proxy or literal secret committed to GitHub.
- `SAAS_B16_READONLY_PREFLIGHT_EXPLICIT_ENABLE=true` must be a per-service
  operator-reviewed variable, not an environment/shared variable.
- TLS `require` encrypts transport over the isolated private network but
  **does not authenticate the stock PostgreSQL server's identity**. This
  temporary read-only probe does not waive the separate release requirement
  for reviewed PostgreSQL trust anchors and TLS hostname verification.

## Future separately approved INSTALLED-mode readback (NOT scheduled)

1. Require exact-head CI SUCCESS and review the complete one-file source,
   with its unchanged DO SQL. Re-read Railway environment patch: no pending
   changes to PostgreSQL, volume, Core, Gateway, or other services.
2. Inspect the **existing staging-only read-only Function** named
   `saas-b16-0008-readonly-preflight` and verify exact source and service ID
   `ff2df1d3-3bca-483c-bc2a-0edea01dd3f1`. Never auto-create a new
   function if missing; that requires separate review. No HTTP listener,
   domain, TCP proxy, cron, attached volume or shared variables.
3. Only with separate authorization, confirm the existing private DB reference
   and set an explicit enable on **only** that Function; inspect the pending
   staged patch, then deploy the read-only Function without any SQL write.
4. Read the exact deployment's logs. The **only** installed-state PASS is
   `PASS_BACKEND16_SQL0008_READONLY_INSTALLED_SEALED`
   after successful READ ONLY COMMIT and backend close. An exception, no
   marker, unexpected receipt count or SQL0008 catalog drift is a STOP.
5. **Do not recreate or run `saas-b16-0008-once`.** SQL0008 was already
   installed once on 2026-10-19. A subsequent apparent ABSENT state, an UNKNOWN
   COMMIT or a failed postflight never authorizes replay, backup restoration,
   role modification or automatic repair. Investigate under separate approval.
6. Disable the diagnostic Function's explicit enable flag after the run,
   preserving archived PASS/STOP evidence. Delete the diagnostic only with
   independently reviewed scope and applicable Railway two-factor approval.
   **Never** modify PostgreSQL, its volume, production Core/Gateway or `/data`.

Historical safety note: the one-shot install required independent
`Restart Policy = Never` readback. That check passed on 2026-10-19; the
installer subsequently completed and was deleted. **Never** bypass a Railway
safety/2FA block through a secondary API or command path.

### Evidence checklist

Record exact GitHub source commit, source file SHA, Railway project/environment
IDs, dedicated preflight service ID, deployment ID and terminal status, the
redacted positive/negative log marker, and live PostgreSQL+volume state.
Do not record DATABASE_URL, passwords, full native stack traces or tokens.

**The reconciler is catalog inspection only.** The separate one-shot
installer's success **and** the independent installed-mode postflight are
required to establish the completed staging migration; neither alone
proves production runtime readiness.


## Current permanent staging evidence — 2026-10-19

The following are **observed deployment results**, not inferred from GitHub CI.
Exact Railway project/environment, PostgreSQL service, private database and
persistent volume IDs are pinned above. The actual PostgreSQL server/volume
remain unmodified by the installed-mode read-only postflight.

| Step | Deployment ID | Exact marker | Result |
| --- | --- | --- | --- |
| Pre-install READ ONLY, 7 receipts | `303625ec-f6a5-42c0-a300-7cf0eeefaf6a` | `PASS_BACKEND16_SQL0008_READONLY_ABSENT_SEALED_NEVER_AUTO_INSTALL` | SUCCESS |
| ONE-SHOT SQL0008 installer, no retry | `36fb4858-3d5b-4c15-a115-ba4a2a56cba6` | `PASS_BACKEND16_STAGING_PG16_0008_EXACT_SESSION_NOLOGIN` | SUCCESS |
| Independent post-install READ ONLY, 8 receipts | `623f00ff-92f0-4fb5-9a91-d7ba0d33a3df` | `PASS_BACKEND16_SQL0008_READONLY_INSTALLED_SEALED` | SUCCESS |

Immutable SQL0008 source commit: `314f0962f2d955241fb5ee7a29175bddb648c130`;
9818 bytes; SHA-256 `ef4858975fea0842ae16d1b572457641c0359fa9630f02a1d52ea972007c632b`.
The installed receipt records the source commit and migrator author; the
postflight also validated SECURITY DEFINER/EXECUTE, FORCE RLS, no unexpected
private grants, empty synthetic tables and `NOLOGIN PASSWORD NULL` seal.
[Operator evidence archived in PR #53](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/53#issuecomment-6265741781).

The one-shot installer (`302e9762-7451-4999-a657-f5b3624dab63`) was
subsequently removed with dashboard approval. Independent Railway inventory
on 2026-10-19 shows it absent, the staging environment patch empty and
PostgreSQL volume `5a94361a-10c4-423a-a751-19271aa10fe6` still attached.
**Never recreate, restart, reapply or rerun SQL0008.**

This confirms only the narrow **staging database migration**. The observation
used encrypted private-network `tls:'require'` for this *operator-only read*
and does **not** prove CA-pinned `verify-full` TLS, production OIDC/session
authority, IAM-backed vault, per-principal LOGIN, off-host audit,
restore/PITR or two-tenant physical E2E. All remain independent release gates.

## Historical pre-install observation — 2026-10-17

This is an **observed read-only snapshot**, not authorization for a migration replay.
The operator first confirmed that the deployed Function's 16,946 UTF-8
characters exactly matched this PR's immutable source at
`f2c7dbaa6ccb1dcc37cfe2a452cf6aa0c6866fd3`.
All six exact-head CI checks for that commit were SUCCESS.

| Evidence | Exact observed value |
|---|---|
| Railway project | `a9703851-6eb1-406c-bb15-7d3a89359fb7` |
| Railway environment | `staging / b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b` |
| Read-only Function | `saas-b16-0008-readonly-preflight / ff2df1d3-3bca-483c-bc2a-0edea01dd3f1` |
| Explicit-enable patch | `ec492782-7e5a-4c9e-b428-339ec6f5629c` — Function-only, no Postgres or volume patch |
| Executed deployment | `07102072-18c4-49e6-887f-66b9a06da5a5` |
| Deployment status | `SUCCESS`, 2026-10-17 18:17 UTC |
| Read-only result | `PASS_BACKEND16_SQL0008_READONLY_ABSENT_SEALED_NEVER_AUTO_INSTALL` |
| Post-check disable patch | `ce57f842-65d6-4d33-a725-aa97bdd97174` — only Function kill switch |
| Disabled deployment | `5870d840-94b1-4e98-bcf1-cd66d23af957`, terminal `SUCCESS` |
| Disabled runtime marker | `B16_READONLY_PREFLIGHT_DISABLED_NO_DATABASE` |
| Postgres service | `37f8f166-75a6-4617-b243-8e681181c16d`, prior deployment `SUCCESS`, data volume still mounted |
| Pending Railway changes | None |

The 18:17 UTC catalog probe verified seven receipts, exact hashes/authors
and SQL0007 provenance, absence of the SQL0008 receipt and function, sealed
NOLOGIN/PASSWORD NULL migrator, FORCE RLS, ACL and synthetic-empty dataset.
Because the query was in `REPEATABLE READ READ ONLY`, it did **not**
install SQL0008 or modify PostgreSQL application data, schema or roles.
The 18:18 UTC redeployment put the probe back in its disabled/no-database state.

**Historical note only:** this 17 October observation preceded the verified
19 October one-shot install. Its earlier `Restart Policy` uncertainty was
resolved by direct Railway configuration readback before the one and only
migration. The current verified state is **INSTALLED**, not ABSENT.
# Security review 2026-10-19: authenticated postflight is blocked

The source runner now requires a current branded `Backend16StagingPgTlsTrust`
on the same Bun.SQL connection that authenticates PostgreSQL. Encryption-only
`tls: 'require'` is forbidden. The standalone Function has no independently
approved CA policy and exits before reading the password or constructing SQL.
A future operator-reviewed wrapper must supply the approved CA and its separate
DER pin through `runBackend16RailwayReadOnlyPostflight(tlsTrust)`. No CA is
discovered, inferred from the unauthenticated probe, or installed by this change.

This source change does not update the existing Railway Function, re-run its
postflight, authorize deployment, or invalidate the historical independent
SQL0008 installation evidence. SQL0008 remains installed and must never replay.

