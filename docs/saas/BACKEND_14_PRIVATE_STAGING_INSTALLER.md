# Backend 14 Phase B — isolated one-shot installer for 0006

**Created 2026-10-16. Code reviewed, not applied by merging.** The runner is a private short-lived Railway Function and is NOT a public SaaS Control API, OIDC login or production release.

## Environment, source and no-backup scope

- Isolated Railway project `cliproxyapi-saas-staging` id `a9703851-6eb1-406c-bb15-7d3a89359fb7`, environment `staging` id `b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b`, dedicated PostgreSQL16 service `37f8f166-75a6-4617-b243-8e681181c16d`, private address `postgres.railway.internal:5432/saas_staging`.
- Source code: `scripts/saas-staging/backend14-private-session-once.ts`; pinned reviewed migration: immutable Git commit `e040f3994106a467e4bf42c1f21b18ca70ed4da2`, only SQL file `0006_principal_session_fence.sql`, SHA-256 `b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505`. The previous 0005 hash is `b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556`.
- User explicitly accepted losing **disposable staging test data** and temporarily waived backup/PITR for that isolated environment only. No waiver for production CPA Core/Gateway or real customer credentials. Restore backup+PITR proof before irreversible data.

## Strict operator execution

Verify all **five** PR GitHub workflows `SUCCESS` on the exact reviewed final SHA. Stage only a new private Railway Function named `saas-b14-session-once`, as a separate service, with exact source code blob from this PR, `restartPolicyType=NEVER`, no cron, no HTTP domain, no public TCP proxy, no volume and no attachment to the existing SaaS API. Provide only three scoped variables:

- `STAGING_POSTGRES_PRIVATE_URL`: Railway internal reference to the isolated `Postgres.DATABASE_URL`, NEVER paste the admin credential or a public TCP connection.
- `SAAS_B14_APPLY_EXPLICIT_ENABLE=true`
- `SAAS_B14_ACCEPT_STAGING_LOSS=true`

Inspect staged patch before applying: it must contain **exactly one new Function**, without changes to Postgres, service variables of an existing app, Core/Gateway project or production. Verify restart NEVER and no domain/TCP proxy.

The Function fetches reviewed SQL over HTTPS without redirects and compares **exact SHA-256 bytes before connecting to PostgreSQL**. Its isolated PG16 admin preflight verifies: database identity/major version; original five ledger receipts; sealed migrator `NOLOGIN PASSWORD NULL`; zero actual tenants/projects/grants/audit and no runtime memberships; two FORCE RLS tables/SELECT policies; prior VOLATILE SECURITY DEFINER RLS; absence of session schema. It then generates a random 64-hex migrator credential *in memory only*, activates the migrator for at most five minutes, connects using that genuine non-superuser role and submits 0006 once. It does **not** replay even if COMMIT acknowledgement is lost.

Only after an independent operator connection reads six exact migration receipts, both private empty session tables, five audit/mutation triggers, RLS function attributes, two forced RLS data tables and zero runtime privileges can the runner re-seal the migrator with `NOLOGIN PASSWORD NULL`. On success it emits only the marker `PASS_BACKEND14_STAGING_PG16_0006_PRIVATE_SESSIONS_FORCE_RLS_NOLOGIN`. On failure it emits `BACKEND14_STOP_UNKNOWN_COMMIT_RECONCILE_NEVER_RETRY`; best-effort temporary role sealing is containment only, not a SQL migration retry.

**Important:** a deployment event/status alone is NOT evidence of completed 0006. Check terminal Railway SUCCESS and the exact positive deploy-log marker. If there is any ambiguity, independently inspect PostgreSQL receipt/catalog before proceeding, never retry blindly.

After a successful run, record the immutable PR head/merge SHA, deployment ID and positive marker **without secrets** in the PR conversation; delete only the ephemeral Function with zero volumes. Confirm the PostgreSQL service and permanent `/var/lib/postgresql/data` volume remain healthy, SaaS Control API stays disabled, and production Core/Gateway deployments remain unchanged.

## What remains explicitly disabled

No actual identity binding or session is provisioned by 0006. There are no real OIDC issuer/client registrations, cookies, PKCE browser login, runtime tenant DB credentials, API endpoint or active tenant grants. **No public SaaS exposure.** An operator-controlled opaque session reference is NOT proof of external OIDC identity; a pinned IdP verifier and independent audit are still required before any client session is issued. Session-revoke acknowledgment fences future database reads but does not guarantee remote HTTP response cancellation or physical connection disposal.
