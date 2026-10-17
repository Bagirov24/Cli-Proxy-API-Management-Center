# Backend15 Phase B — read-only SQL0007 reconciliation

This is an **independent observation tool**, not a migration runner, automatic recovery command or permission to replay SQL0007. Intended for operator review after failed/UNKNOWN COMMIT and before any decision to enable a migration installer.

## Fixed security boundary

- Only isolated project cliproxyapi-saas-staging (a9703851-6eb1-406c-bb15-7d3a89359fb7) and environment staging (b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b).
- Database saas_staging on private postgres.railway.internal:5432, PostgreSQL major 16; PostgreSQL service ID 37f8f166-75a6-4617-b243-8e681181c16d.
- Execution is restricted to a **separate** operator-only one-shot CLI/Function named saas-b15-reconcile-readonly-once, not the existing saas-b15-binding-once. Use a private-only PostgreSQL URL. Do not deploy into production, Core, Gateway, customer accounts or persistent volumes.
- A future operator-run Function must have restartPolicyType=NEVER, no cron, no public domain/TCP proxy, and must be staged and reviewed on its own before deployment. The current installer Function remains unlaunched until its own gates are satisfied.
- Required variables: STAGING_POSTGRES_PRIVATE_URL referencing private Postgres.DATABASE_URL; SAAS_B15_READONLY_RECONCILE_ENABLE=true; SAAS_B15_APPLY_EXPLICIT_ENABLE **absent or false**. Railway must provide exactly pinned project/environment/service metadata.
- No secret values, raw identities, tenant IDs or SQL errors are printed.

The source is scripts/saas-staging/backend15-readonly-reconcile.ts. It sets PostgreSQL default_transaction_read_only=on, begins REPEATABLE READ READ ONLY and only issues fixed SELECTs plus transaction COMMIT. It does **not** write SQL0007, change roles, seal a leaked password, create a role, mutate data or retry failed migrations.

## What it independently verifies

1. Actual PG16, exact staging DB, authenticated postgres operator, read-only transaction and no standby; the saas_schema_migrator role is already NOLOGIN with rolpassword IS NULL and no dangerous privileges. Both runtime template roles must remain NOLOGIN, NOINHERIT, passwordless, and without SUPERUSER/BYPASSRLS/CREATEROLE/CREATEDB/REPLICATION.
2. No unexpected saas_* roles or role memberships. All six earlier migration ledger rows and hashes exactly match; if 0007 is recorded, its SHA-256 and source commit must match the reviewed SQL:
   - 0007 SHA-256: 1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0
   - source commit: 6cc4a76a0b3144380ccc95f0ca1c275ae312cae3.
3. Tenant, project, grant, grant-audit, session and session-audit rows remain empty. FORCE RLS and both read policies survive. All five Backend14 triggers remain installed; authenticated reader/writer retain intended base SELECT, have **no INSERT/UPDATE/DELETE/TRUNCATE privileges** on tenants/projects, and no identity-schema USAGE.
4. All saas_identity table/function ACL are owner-only. Tenant and ACL tables have no unexpected grants to PUBLIC or unrelated roles; this prevents privilege drift even where the nominal runtime roles are unchanged.
5. Before 0007: subject-binding tables/functions must all be absent and only six receipts exist. After 0007: both private tables, both operator binding functions, three unique indexes, five B15 audit/blocking triggers, the revoke constraint, definer/invoker function ownership and the identity-bound RLS predicate must all be present; binding and audit tables empty, no runtime SELECT/EXECUTE on these private objects.

## Outcomes

| Exact runtime marker | Meaning |
| --- | --- |
| PASS_BACKEND15_READONLY_RECONCILE_0007_ABSENT_SEALED_NOLOGIN | Precisely expected six-receipt baseline, no B15 objects and sealed migrator **at the observed snapshot** |
| PASS_BACKEND15_READONLY_RECONCILE_0007_INSTALLED_SEALED_NOLOGIN | Exactly expected seven-receipt B15 catalogue, digest, ACL and empty data, sealed migrator **at the observed snapshot** |
| BACKEND15_READONLY_RECONCILE_STOP_MANUAL_REVIEW_NEVER_REPLAY | Missing, ambiguous, inconsistent or inaccessible state; **stop** and independently inspect PostgreSQL before any write |

The diagnostic is read-only even after UNKNOWN COMMIT. It **must not** automatically promote an absent classification into migration permission: another operator could change the database after the snapshot. Always redo the live preflight on the separate installer and never rerun after an unknown outcome.

## Review and tests

Run: bun test tests/saasBackend15ReadOnlyReconcile.test.ts

The suite tests both clean states and missing receipts, wrong SHA/source commit, partially present objects, leaked migrator LOGIN/password, non-PG16 or wrong DB, altered role memberships, tenant data, lost FORCE RLS, audit trigger drift and private ACL grants. The suite is isolated from Railway: it uses pure snapshots and does not connect to PostgreSQL.

The immutable installer from PR #44 remains the only allowed one-shot executor after all migration deployment gates. If its restartPolicyType=NEVER cannot be verified, **do not accept the staging patch or enable SQL0007**. Any recovery action affecting the database must undergo a separate manual review and is out of scope for this read-only utility.
