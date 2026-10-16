# Backend 12 private one-shot RLS installation: Railway staging

Status at authoring: **reviewed code, not deployed**. This is an isolated one-off migration runner, **not SaaS API**. It must never have a public domain, TCP proxy, cron, restart retry, or secrets from CPA Core/Gateway.

## Existing verified state

- Isolated Railway project `cliproxyapi-saas-staging` `a9703851-6eb1-406c-bb15-7d3a89359fb7` / environment `staging` `b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b`.
- PostgreSQL16 service `37f8f166-75a6-4617-b243-8e681181c16d`, private DNS `postgres.railway.internal:5432`, database `saas_staging`, isolated persistent volume `/var/lib/postgresql/data`, no public TCP proxy/domain.
- Backend11 migrations `0000–0002` were applied/read back, with `saas_schema_migrator NOLOGIN`. The tenant/project tables were empty and RLS FORCE-enabled with zero policies. Before this run, an independent preflight **rechecks** those facts.
- Backend12 migration SQL `0003`/`0004` lives at immutable reviewed commit `8b06c308d2fe52abb17b44fa09451db0994d3850`. Hash pins: `0003_operator_runtime_roles.sql` = `8bd26bb1e798e1196f64546a0bfd554cfe46c6a5cd9d4414d369bc1cbf98124e`; `0004_principal_bound_read_rls.sql` = `4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980`.

## Explicit risk waiver and limits

User explicitly waived **backup/PITR only for disposable staging tests** and accepts complete staging data loss. This waiver does NOT cover production, real user data, CPA Core/Gateway branches, volume `/data`, persistent credentials, or weakening the private network. Revisit PITR+tested restore before real tenants/irrecoverable data.

## Execution contract

Source: `scripts/saas-staging/backend12-private-rls-once.ts`. Runtime Bun Function, pinned `pg@8.16.3`. It reads only the reviewed immutable two SQL files, validates byte lengths and SHA256 **before any PostgreSQL connection**, strips only the `\\set ON_ERROR_STOP on` meta command and binds only fixed hex SHA/commit psql variables. No arbitrary HTTP SQL, no wildcard imports.

Require exact Railway environment/project and service name `saas-b12-rls-once`. Explicit variable flags `SAAS_B12_APPLY_EXPLICIT_ENABLE=true`, `SAAS_B12_ACCEPT_NO_BACKUP=true`, and private DB reference `STAGING_POSTGRES_PRIVATE_URL=${{Postgres.DATABASE_URL}}`. Refuse public URL/host, query overrides, wrong user/database/port. The Function must be created **staged**, with `restartPolicyType=NEVER`, no cron, no HTTP domains/TCP proxy, and verified unchanged source blob. Reject any patch containing other changes, especially to production.

One run:
1. Preflight PG16 `saas_staging` operator, exact 0001/0002 receipts, NOLOGIN migrator, zero new roles/ACL/policies, FORCE RLS, no tenant/project data.
2. Execute `0003` **once** as isolated postgres, wait for acknowledged COMMIT; never retry on error.
3. Temporarily activate `saas_schema_migrator` with random **in-memory** 64-hex password and `VALID UNTIL` ~5 minutes. It is not saved in GitHub, Railway variables or user logs. Connect through the private network as the *real* restricted migrator login.
4. Execute `0004` **once** as restricted migrator; do not retry after any ambiguous COMMIT.
5. PostgreSQL catalog readback verifies four exact source-hash/commit receipts, correct author for 0003/0004, two NOLOGIN non-superuser templates, no memberships, neither runtime role may write, private map not selectable, both tables FORCE RLS with exactly one SELECT policy each, private mapping table and tenant/project tables still empty.
6. Return `saas_schema_migrator` to `NOLOGIN PASSWORD NULL`, confirm using privileged role catalog. Only then emit `PASS_BACKEND12_STAGING_READ_ONLY_ROLE_RLS_0003_0004_NOLOGIN`. If any step fails, emit only `BACKEND12_STOP_UNKNOWN_COMMIT_RECONCILE_NO_RETRY`. One best-effort credential-seal attempt may run in failure cleanup; **no reissue of migrations**. Password validity expires in minutes even if the network fails during cleanup.

## Operator evidence and cleanup

Check all five PR GitHub workflow SUCCESS on one exact final SHA before any staging apply. After staging patch apply, require terminal `SUCCESS` and the **positive marker in deployment logs**; a deployment event alone is not proof. Preserve non-secret deployment ID, reviewed merge SHA and success/failure result in PR Conversation. Then delete only the one-shot Function and verify that Postgres, its volume and the disabled `saas-control-api` remain untouched and no public domain/proxy was created. Never redeploy/retry on an ambiguous outcome.

No live runtime principal memberships, customer data, OIDC login, API write grants or actual public SaaS are created by this stage. Real customer access requires separately reviewed per-session authorization, revocation, signed scope, audit/unknown-COMMIT reconciliation and production backup.
