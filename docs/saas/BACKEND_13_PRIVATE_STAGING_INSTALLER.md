# Backend13 — audited one-shot 0005 installation in private Railway staging

**Created 16 October 2026. Status: reviewed code only, NOT applied by merging.** One-off operator Function: no HTTP route, listener, cron, persistent app login, public domain, TCP proxy or production connectivity.

## Trust boundary

Only project `cliproxyapi-saas-staging` `a9703851-6eb1-406c-bb15-7d3a89359fb7`, environment `staging` `b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b`, private PostgreSQL16 service `37f8f166-75a6-4617-b243-8e681181c16d`, private URL host `postgres.railway.internal:5432/saas_staging` (operator username `postgres`). PostgreSQL volume `/var/lib/postgresql/data` remains attached to Postgres and must never be detached/deleted.

This user explicitly waived backup/PITR **for disposable staging test data only**, accepting total loss. Production `cliproxyapi-personal` Core/Gateway, `custom-no-apikey-fun`, `/data`, real customer provider credentials, and exposed SaaS HTTP are not authorized and must not be touched.

## Source attestation

One-file Bun Function: `scripts/saas-staging/backend13-private-lifecycle-once.ts`, pinned `pg@8.16.3`.
- Immutable approved SQL commit: `d9a5a151cd86ff458882032ed2c62fd947a92f07`
- Exactly one allowed file: `staging/saas-bootstrap/0005_principal_lifecycle_revocation_fence.sql`
- Approved byte SHA256: `b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556`
- Previous 0004 SHA256: `4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980`

The Function retrieves the SQL from immutable Git before any DB session, refuses redirects/bad bytes/hash/unexpected `psql` directives, and binds only hex SHA/commit parameters.

## Deliberate execution gate

Operator must stage a **new, separate** `saas-b13-lifecycle-once` Function **only** in the isolated SaaS staging Railway project and verify exact script contents. Variables in the same staging patch:
- `STAGING_POSTGRES_PRIVATE_URL=${{Postgres.DATABASE_URL}}` as an internal Railway reference, NEVER paste a password or point to a public proxy
- `SAAS_B13_APPLY_EXPLICIT_ENABLE=true`
- `SAAS_B13_ACCEPT_STAGING_LOSS=true`

Set `restartPolicyType=NEVER`, no cron, zero volume mounts/domains/proxies, no production or existing service config changes. Check all five GitHub PR workflows `SUCCESS` on exact final reviewed SHA before staging any live DDL. Require the patch to contain **only the new disposable Function** before `accept-deploy`. An unchanged `saas-control-api` must stay disabled.

The Function:
1. Pins PG16 `saas_staging`, postgres operator, sealed `saas_schema_migrator NOLOGIN PASSWORD NULL`, exact receipts for 0001–0004, 2 SELECT-only RLS policies, two FORCE RLS tables, no tenant/project/principal/membership rows, no existing audit tables or 0005 function.
2. Generates an ephemeral 64-hex migrator password **in RAM**, enables that one existing role for only five minutes (`VALID UNTIL`). This is not an application login and is never written to GitHub, logs, PR comments or Railway variables.
3. Connects as the actual restricted `saas_schema_migrator` through the private database URL with `saas.staging_only=true`, executes hash-pinned 0005 **once** and requires acknowledged COMMIT.
4. Uses separate operator SQL read-back to verify exactly five receipts, correct 0005 hash/author, the VOLATILE SECURITY DEFINER RLS predicate and invoker-only access-changing function, two enabled table triggers on mapping and audit, zero public/runtime operator privileges, FORCE RLS and SELECT-only policies, zero actual data/memberships.
5. Seals migrator to `NOLOGIN PASSWORD NULL`, checks physical role catalog; only after that prints `PASS_BACKEND13_STAGING_PG16_0005_CAS_AUDIT_FENCE_NOLOGIN`.
6. On any failure prints only `BACKEND13_STOP_UNKNOWN_COMMIT_MANUALLY_RECONCILE_NO_RETRY`. The only best-effort cleanup is to seal the temporary role; no DDL replay. If acknowledgement or catalog state is uncertain, do not rerun or redeploy, reconcile manually from independent operator read-only evidence.

Do not count deployment `SUCCESS` alone; capture both terminal deployment status and positive deploy-log marker. Record the deployment ID in the reviewed PR without secrets. Delete **only** the ephemeral Function after verifying its exact identity and zero volumes. Confirm Postgres and permanent volume remain healthy, saas-control-api remains disabled, no public TCP/HTTP, and production Core/Gateway status unchanged.

## Security boundary after completion

No runtime credentials, tenant mappings, grants, idempotency keys, real customer data or HTTP API are created. On an empty DB, RLS remains **effectively deny-all**. The local operator audit is transactional but **not external WORM**, and even FOR SHARE revocation fencing cannot cancel an already-active network response. Future production use requires real IdP binding, permissionful login provisioning, connection fencing/timeouts, independent durable audit and backup/PITR+verified restoration before irreplaceable data.
