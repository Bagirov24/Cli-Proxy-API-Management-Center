# Backend 10 — Tenant/project catalog: deny-all permanent baseline

Status: **code + disposable PostgreSQL16 CI**, not an approval for public SaaS.
Current isolated staging project:
- Railway project `a9703851-6eb1-406c-bb15-7d3a89359fb7`, environment `b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b`.
- PG16 service `37f8f166-75a6-4617-b243-8e681181c16d` deployment `dcb8a17e-bc3e-4985-9663-e012e8048a97`: **SUCCESS**, volume `5a94361a-10c4-423a-a751-19271aa10fe6` on `/var/lib/postgresql/data`.
- Exactly **zero public TCP proxies** and **zero public HTTP domains** on the database. Empty `saas-control-api` remains disabled/unmounted. Production CPA Core and Gateway are excluded.

## Explicit temporary backup deferral

On **16 October 2026**, the user explicitly accepted losing the data in this **isolated, non-production staging environment** and asked to postpone backup/PITR. This removes **only the staging proof-of-backup gate** for disposable test data. The waiver is **not** permission to modify Core/Gateway, destroy shared storage, store real customers' secrets, publish DB endpoints, bypass authentication or deploy production. Before real or irreplaceable data, restore the backup/PITR verification requirement.

Whether the staging database has a recoverable backup remains **unverified**, and schema/bootstrap operations could be lost forever. No backup is claimed by the CI `pg_dump` test.

## New one-shot baseline migration

Path: `staging/saas-bootstrap/0002_tenant_projects_baseline.sql`.

**Order:** isolated PG16 `saas_staging` + reviewed `0000_operator_migrator_role.sql` (fresh login) + reviewed `0001_ledger_only.sql` (record with exact SHA256) → then **once only** `0002`, run as `saas_schema_migrator`, NOT `postgres` or an application login. All schema DDL runs in a single transaction with an appended ledger receipt. `0002` refuses a mismatched 0001 checksum, any preexisting schema, other database, superuser, pilot `saas_rls` schema, wrong role or SQL major !=16.

Creates *only*:
- `saas_data.tenants`: UUID tenant key, validated operator-facing tenant key, display name, lifecycle, revision and timestamps.
- `saas_data.projects`: UUID project key, constrained tenant FK with `ON DELETE RESTRICT`, project key unique *within the tenant*, display name, lifecycle, revision and timestamps.
- One source-hash-attested `saas_bootstrap.schema_migrations` ledger row with ID `0002_tenant_projects_baseline`, exact source SHA256 and reviewed git commit.

**Zero data, zero application grants, zero RLS policies, FORCE RLS on both tables.** Thus even the table owner cannot SELECT other people's rows or INSERT through the SQL table interface; the superuser can bypass RLS, which is why it is never provided to the app. No SECURITY DEFINER, service roles, issuer/session grants, API endpoints, public network or trigger-based privileges are created. Real application reads/writes require a **separate audited RLS-policy migration** with signed tenant authorization and its own tests.

The offline command `node scripts/saas-staging/plan-staging-bootstrap.mjs --plan` computes SHA256 of `0000`, `0001`, `0002` and returns `executionAuthorized=false`. No automatic `--apply`, wildcard SQL001–027 loader or network call is included.

## What CI proves

CI applies 0000 then 0001 then 0002 to a **fresh separate `saas_staging_ci`** on disposable PostgreSQL16. 0001/0002 run as the non-superuser. CI checks:
- Both tables have `relrowsecurity` and `relforcerowsecurity`, **zero** `pg_policy` rows, and `saas_ci_runner` has no SELECT/INSERT/schema USAGE.
- PostgreSQL superuser inserts two **synthetic disposable** rows; the table owner sees **zero** rows and cannot insert, proving FORCE RLS is enforced instead of merely checking catalog flags.
- Neither 0002 replay nor running it against `saas_ephemeral_test` succeeds.
- A custom-format dump of `saas_bootstrap` and `saas_data` restores into another disposable database with the same forced-RLS table flags and exactly two ledger receipts. **This is not a backup of Railway.**
- The repo's existing five GitHub Actions remain required on the exact PR head SHA. Never merge on failed or incomplete checks.

## Applying to isolated staging later (only after operator checks)

The current GitHub and Railway connectors do **not** provide a safe direct SQL execution method with a persistent operator-managed migrator secret. Do not improvise a privileged web endpoint, transmit passwords in chat/PR comments, or automatically replay DDL after a lost acknowledgement. Approved manual migration is allowed with the user's risk waiver, but must be run from a private trusted operator shell on the target database, using independently verified Railway project/environment/service IDs. The operator must provision a 64-hex migrator secret in a protected store, inspect database identity, compare hashes and commit, then execute `0000`, `0001`, `0002` *exactly once* in that order via `psql -X -v ON_ERROR_STOP=1`; the `0002` invoker supplies `expected_0001_sha256`, `migration_sha256`, `source_commit`. The migrator is NEVER exposed to `saas-control-api`.

**Unknown COMMIT = STOP**: inspect schema catalogs, the ledger and external operator audit; NEVER retry "just in case". Actual staging schema is considered **not installed** until read-back from that exact isolated PG16 confirms it.

## Still blocked from real data/public SaaS

No signed RLS policies, runtime DB users, IdP browser login, physical connection lifecycle review, off-host WORM audit/reconciliation, PITR or verified restore. The user waived only staging backup prerequisite, not these security controls; do not put real customer credentials into the database yet.
