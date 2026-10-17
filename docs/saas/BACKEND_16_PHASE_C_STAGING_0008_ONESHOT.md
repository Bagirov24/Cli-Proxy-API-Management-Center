# Backend16.5 — SQL0008 staging-only one-shot

**Status 2026-10-17:** installer source candidate, not deployed. SQL0008 **NOT INSTALLED** on permanent Railway staging. Staged Railway service contains only a **non-deployed, no-database placeholder**.

## Exact operator pins

| Parameter | Exact value |
|---|---|
| Railway project | cliproxyapi-saas-staging / a9703851-6eb1-406c-bb15-7d3a89359fb7 |
| Environment | staging / b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b |
| Existing PG16 service | 37f8f166-75a6-4617-b243-8e681181c16d |
| Database/private network | saas_staging / postgres.railway.internal:5432, postgres operator |
| New Function, staged only | saas-b16-0008-once / 302e9762-7451-4999-a657-f5b3624dab63 |
| Staged patch | fb17a10c-2167-4c74-ab07-4caa1f7034fe (only Function placeholder) |
| Immutable SQL0008 source GitHub commit | 314f0962f2d955241fb5ee7a29175bddb648c130 |
| SQL0008 byte size | 9818 UTF-8 |
| SQL0008 SHA-256 | ef4858975fea0842ae16d1b572457641c0359fa9630f02a1d52ea972007c632b |
| Prior SQL0007 SHA-256 | 1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0 |

**Scope:** synthetic isolated staging PostgreSQL only. NEVER production CPA Core/Gateway, branch custom-no-apikey-fun, volume /data, real customer tokens/credentials or any production database. The synthetic-data waiver does not permit production backup/PITR waivers.

## Operator preflight — ALL mandatory

1. Installer PR merged after all exact-HEAD CI SUCCESS (Main CI, disposable PG16 SQL0008 two-principal/revoke E2E, Browser QA, Management release guard, installer contract). Pin the immutable source and inspect every byte; do not run from a draft PR.
2. Fresh independent READ-ONLY SQL check on actual persistent staging proves exactly SQL0001–0007 receipts with pinned authors and hashes, SQL0008 receipt and exact function absent, sealed migrator NOLOGIN and PASSWORD NULL, zero unexpected roles, memberships, client connections, tenants/projects/grants/sessions/bindings, FORCE RLS and two SELECT policies unchanged, no privilege drift. Railway PostgreSQL deployment SUCCESS does NOT prove a migration state.
3. Railway Function Settings: set **Restart Policy = Never** on EXACT service ID 302e9762-7451-4999-a657-f5b3624dab63. Read back and record restartPolicyType=NEVER, cronSchedule=null, no domains, public TCP proxies, HTTP listener or attached volumes. **Prior tooling attempts to set NEVER were blocked by OpenAI safety enforcement; do not bypass that tool block or use alternate commands to evade it.** Until this operator/UI preflight is satisfied, NO database execution.
4. Stage reviewed exact single-file installer source ONLY in this Function. Stage private database reference for STAGING_POSTGRES_PRIVATE_URL (Railway Postgres.DATABASE_URL variable reference, never a plaintext secret). Other Function variables: SAAS_B16_APPLY_EXPLICIT_ENABLE=false while configuring and SAAS_B16_ACCEPT_DISPOSABLE_STAGING=true only after verifying synthetic-only scope.
5. Review pending Railway patch: only this temporary Function source, its own variables and restart policy. No modification to PostgreSQL, volume, saas-control-api, shared variables, production, network or cron. Before the **single** deployment, require explicit true kill switch and independently verified Never, fresh staging-only DB catalog gate and source SHA.
6. Deploy the reviewed staging-only Function once. Never retry, restart or redeploy after UNKNOWN COMMIT or missing deployment marker. No cron/restart permitted.

**CURRENT STOP GATE:** Restart Policy Never has not been confirmed for the staged service. It contains the no-database placeholder only; there has been NO SQL0008 execution on permanent staging. Do NOT accept its patch as the real installer before the listed gates.

## Runtime acceptance

The exact installer code is scripts/saas-staging/backend16-exact-session-once.ts. Before any DB connection it checks the exact service ID, project/environment ID, explicit enable flags and the private PostgreSQL URL, downloads immutable GitHub SQL with no redirects, verifies 9818 bytes and SHA-256.

On an independently preflight-positive schema it temporarily enables the existing **non-superuser** migrator LOGIN with a fresh in-memory 32-byte random password and 5-minute expiry, submits SQL0008 in **one** transaction, reads back the eighth ledger receipt, catalog, old RLS and new SECURITY DEFINER function privileges, then immediately restores NOLOGIN PASSWORD NULL and verifies pg_authid.

Positive marker emitted only AFTER verification and seal:

    PASS_BACKEND16_STAGING_PG16_0008_EXACT_SESSION_NOLOGIN

Any failure (including lost COMMIT ACK) emits only:

    BACKEND16_STOP_UNKNOWN_COMMIT_RECONCILE_NEVER_RETRY

The STOP marker does **not** establish either success or absence. For a successful acceptance require terminal Railway deployment SUCCESS, positive marker in exact deployment logs, PLUS independent read-only SQL readback of eight receipts, SQL0008 definer privileges, and sealed migrator. On any other observation, STOP and manually reconcile without retries. If manual repair is needed for a failed migrator seal, do it only through a separately approved operator action.

Once full evidence is archived in PR Conversation, delete **only** the temporary staging Function; verify the PostgreSQL service and existing persistent volume remain intact.

## Production blockers after SQL0008

The SQL migration is a narrow **boolean** database predicate. It does NOT verify OIDC JWT signatures, bearer-token binding, real IdP sessions, physical PG connection pool, durable off-host audit or cancellation/UNKNOWN COMMIT handling in an actual HTTP API.

A production-ready SaaS still requires real private bearer-bound session authority, per-principal PostgreSQL vault/connection driver, exact SQL0008 with FORCE RLS in the SAME transaction, two-tenant real login and revoke races, connection PID quarantine/discard, private ingress, external audit, backup/PITR/restore and separate canary approval. Do not launch public SaaS based on migration evidence alone.
