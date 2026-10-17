# Backend16.8.1 — independent Railway staging READ ONLY preflight

**Intent:** verify whether permanent `saas_staging` still has precisely seven
immutable migration receipts (`0001–0007`) with SQL0008 absent, before any
attempt to deploy the separately gated one-shot installer.

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

## Execution and readback

1. Require exact-head CI SUCCESS and review the complete one-file source,
   with its unchanged DO SQL. Re-read Railway environment patch: no pending
   changes to PostgreSQL, volume, Core, Gateway, or other services.
2. Create a **new staging-only Railway Function** named
   `saas-b16-0008-readonly-preflight` with that exact code, no HTTP listener,
   domain, TCP proxy, cron, attached volume or shared variables.
3. Bind the private DB reference and explicit enable on **only** that Function,
   inspect the resulting staged patch, then deploy that read-only Function.
4. Read the exact deployment's logs. A positive proof is solely
   `PASS_BACKEND16_SQL0008_READONLY_ABSENT_SEALED_NEVER_AUTO_INSTALL`
   after successful READ ONLY COMMIT and native backend close. An exception,
   no marker, or unexpected receipt count is a STOP, not proof of absence.
5. An ABSENT marker does **not** authorize replay after any uncertain
   migration COMMIT; the one-shot installer still requires independent
   approval of `Restart Policy = Never`, no cron or retries, matching source
   hash, fresh full preflight, and its own one-time release procedure.
6. Remove the dedicated preflight Function only after its findings are
   recorded and its service identity is verified. **Never** delete or modify
   PostgreSQL, its persistent volume, production Core/Gateway or `/data`.

If `Restart Policy = Never` remains blocked or cannot be read back for the
**separate** `saas-b16-0008-once` installer, stop before SQL0008. No CLI,
GraphQL, secondary API, or config trick may be used to bypass that block.

### Evidence checklist

Record exact GitHub source commit, source file SHA, Railway project/environment
IDs, dedicated preflight service ID, deployment ID and terminal status, the
redacted positive/negative log marker, and live PostgreSQL+volume state.
Do not record DATABASE_URL, passwords, full native stack traces or tokens.

**This phase is catalog inspection, not a completed staging migration.**
