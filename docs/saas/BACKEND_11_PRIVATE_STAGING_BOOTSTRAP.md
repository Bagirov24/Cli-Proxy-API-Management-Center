# Backend 11 — private one-shot staging migration runner

**16 October 2026.** This operator-reviewed runner is **not** SaaS API. It has no HTTP handler, HTTP domain, public TCP proxy, cron, queue, browser cookie, IdP, tenant write path or production connectivity. Stage it only as a separate `saas-bootstrap-once` Railway Function in the isolated project `a9703851-6eb1-406c-bb15-7d3a89359fb7`, environment `b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b`.

## User-authorized testing boundary

The user waived backups/PITR for **disposable staging test data only**. This does not permit production DDL, Core/Gateway access, any real tenant credentials, imported pilot SQL001–027, SQL019 or public database exposure. It also does not claim recoverability. Reinstate backup+restore requirements before valuable data.

## Sources and review

One-file TypeScript executor: `scripts/saas-staging/backend11-private-one-shot.ts`, pinned npm `pg@8.16.3`. It retrieves **only three reviewed SQL files** from immutable Git commit `7b2158009b742b47e12fd738c34ae430662803cf`, using direct HTTPS without redirects, and requires SHA-256 matches before connecting. Manifest:

| SQL | SHA-256 |
| --- | --- |
| `0000_operator_migrator_role.sql` | `08047267af4750206d6963b058d2766b4f4f2ea16bb60e90209070aa65a4aab3` |
| `0001_ledger_only.sql` | `7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279` |
| `0002_tenant_projects_baseline.sql` | `80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f` |

Bun executes the reviewed SQL with the official `pg` client, substituting **only** generated 64-hex password and pinned source hashes/commit. No dynamically chosen SQL file or free-form SQL is accepted.

## Railway execution gate

The Function requires Railway's own `RAILWAY_PROJECT_ID`, `RAILWAY_ENVIRONMENT_ID`, `RAILWAY_ENVIRONMENT_NAME` and `RAILWAY_SERVICE_NAME=saas-bootstrap-once`. It also requires two explicit staging-only opt-ins, `SAAS_BOOTSTRAP_EXPLICIT_ENABLE=true` and `SAAS_BOOTSTRAP_OPERATOR_ACCEPT_LOSS=true`. The **only database variable** is `STAGING_POSTGRES_PRIVATE_URL=${{Postgres.DATABASE_URL}}` resolved by Railway at runtime. It accepts only `postgres.railway.internal:5432/saas_staging` with the `postgres` operator. Do not substitute the public `DATABASE_PUBLIC_URL`.

Create the Function **staged**, stage the above variables in the same patch, verify no other staged resources, and apply only after all five GitHub Actions PASS on the reviewed runner SHA. Never attach a domain. Initial startup with unset flags intentionally refuses to run. Function has no HTTP listener; it terminates after success/failure.

## One-shot behavior

1. Fetch and verify all immutable SQL (hashes and allowlist) **before any DB session**.
2. Connect to private PG16, verify the exact database and fresh schema/role, operator superuser, absence of pilot schema; **hard stop** if anything already exists (including partial previous attempts).
3. Generate random 64-hex password **only in memory**. Execute SQL0000 once through the admin connection. Connect as real, non-superuser `saas_schema_migrator`.
4. Execute SQL0001 then SQL0002 **one time each**, in separate commit-acknowledged calls. A lost/ambiguous COMMIT stops processing. Never retry, never drop/repair or automatically reconcile.
5. Read back two exact migration receipts, all catalog entries, FORCE RLS on both empty tables and **zero RLS policies**. Seal the migrator with `ALTER ROLE saas_schema_migrator NOLOGIN` and verify `rolcanlogin=false`.
6. Emit **only** `PASS_BACKEND11_STAGING_PG16_0000_0001_0002_FORCE_RLS_NOLOGIN` on success, or `BACKEND11_STOP_UNKNOWN_STATE_RECONCILE_NO_RETRY` on failure. No password/URL/source SQL in logs. Stop/remove the ephemeral Function after preserving non-secret operator evidence.

**Important:** the Function cannot independently attest Railway's host identity from environment variables or prove external network/backup status. It confirms the expected connection and schema, not production security approval. An UNKNOWN state must be reconciled manually from a separate read-only operator connection. Do **not** restart/redeploy the Function "to retry" after an ambiguous error.

## CI

`tests/saasBackend11PrivateOneShot.test.ts` verifies the TypeScript syntax, pinned three-file checksum manifest, exact project/environment/private host, required flags, no listener or unsafe fallback, and no automatic retry. The existing PostgreSQL16 workflow continues to test actual SQL0000–0002 on **disposable** `saas_staging_ci` with the restricted migrator and deny-all RLS. A green CI does not mean a live Railway migration happened.

## Remaining prerequisites for usable SaaS

Future separate changes: audited signed tenant RLS policies, restricted read/write runtime users, real IdP + session revocation, physically isolated connection pools, externally durable audit evidence, multi-tenant E2E, and backup/PITR+restore before non-disposable data. `saas-control-api` must remain unmounted and explicitly disabled meanwhile.
