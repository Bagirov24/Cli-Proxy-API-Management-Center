# Backend16.5 — SQL0008 staging-only one-shot

**Status 2026-10-19 — INSTALLED, INDEPENDENTLY VERIFIED, NO REPLAY.**
SQL0008 was applied **once** to permanent staging PostgreSQL16, with one-shot
installer deployment `36fb4858-3d5b-4c15-a115-ba4a2a56cba6` (SUCCESS,
`PASS_BACKEND16_STAGING_PG16_0008_EXACT_SESSION_NOLOGIN`) and independent
read-only installed-mode postflight `623f00ff-92f0-4fb5-9a91-d7ba0d33a3df`
(SUCCESS, `PASS_BACKEND16_SQL0008_READONLY_INSTALLED_SEALED`).
The temporary installer has been removed from Railway staging after dashboard
approval. **Never recreate or rerun the one-shot code or SQL0008, even if
subsequent readback is ambiguous or shows ABSENT.** This document preserves
the historical original procedure solely for forensic provenance.

## Exact operator pins

| Parameter | Exact value |
|---|---|
| Railway project | cliproxyapi-saas-staging / a9703851-6eb1-406c-bb15-7d3a89359fb7 |
| Environment | staging / b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b |
| Existing PG16 service | 37f8f166-75a6-4617-b243-8e681181c16d |
| Database/private network | saas_staging / postgres.railway.internal:5432, postgres operator |
| Historical one-shot Function, now deleted | saas-b16-0008-once / 302e9762-7451-4999-a657-f5b3624dab63 |
| Historical installer commit patch | b1a8606b-c9fc-44b9-8bc1-b00afc26b844 (only Function source/variables, already committed) |
| Immutable SQL0008 source GitHub commit | 314f0962f2d955241fb5ee7a29175bddb648c130 |
| SQL0008 byte size | 9818 UTF-8 |
| SQL0008 SHA-256 | ef4858975fea0842ae16d1b572457641c0359fa9630f02a1d52ea972007c632b |
| Prior SQL0007 SHA-256 | 1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0 |

**Scope:** synthetic isolated staging PostgreSQL only. NEVER production CPA Core/Gateway, branch custom-no-apikey-fun, volume /data, real customer tokens/credentials or any production database. The synthetic-data waiver does not permit production backup/PITR waivers.

## Archived 2026-10-17 preflight procedure — historical ONLY; DO NOT EXECUTE AGAIN

1. Installer PR merged after all exact-HEAD CI SUCCESS (Main CI, disposable PG16 SQL0008 two-principal/revoke E2E, Browser QA, Management release guard, installer contract). Pin the immutable source and inspect every byte; do not run from a draft PR.
2. Fresh independent READ-ONLY SQL check on actual persistent staging proves exactly SQL0001–0007 receipts with pinned authors and hashes, SQL0008 receipt and exact function absent, sealed migrator NOLOGIN and PASSWORD NULL, zero unexpected roles, memberships, client connections, tenants/projects/grants/sessions/bindings, FORCE RLS and two SELECT policies unchanged, no privilege drift. Railway PostgreSQL deployment SUCCESS does NOT prove a migration state.
3. Railway Function Settings: set **Restart Policy = Never** on EXACT service ID 302e9762-7451-4999-a657-f5b3624dab63. Read back and record restartPolicyType=NEVER, cronSchedule=null, no domains, public TCP proxies, HTTP listener or attached volumes. **Prior tooling attempts to set NEVER were blocked by OpenAI safety enforcement; do not bypass that tool block or use alternate commands to evade it.** Until this operator/UI preflight is satisfied, NO database execution.
4. Stage reviewed exact single-file installer source ONLY in this Function. Stage private database reference for STAGING_POSTGRES_PRIVATE_URL (Railway Postgres.DATABASE_URL variable reference, never a plaintext secret). Other Function variables: SAAS_B16_APPLY_EXPLICIT_ENABLE=false while configuring and SAAS_B16_ACCEPT_DISPOSABLE_STAGING=true only after verifying synthetic-only scope.
5. Review pending Railway patch: only this temporary Function source, its own variables and restart policy. No modification to PostgreSQL, volume, saas-control-api, shared variables, production, network or cron. Before the **single** deployment, require explicit true kill switch and independently verified Never, fresh staging-only DB catalog gate and source SHA.
6. Deploy the reviewed staging-only Function once. Never retry, restart or redeploy after UNKNOWN COMMIT or missing deployment marker. No cron/restart permitted.

**CURRENT HARD STOP:** SQL0008 is **already installed**. The historical
readback requirement `restartPolicyType=NEVER` was independently confirmed
before the single deployment; this does **not** authorize another run. The
previous staged placeholder patch is obsolete; current Railway staging has
no installer service and no pending patch. Verify current state read-only only.

## Historical runtime acceptance — observed on 2026-10-19

The exact installer code is scripts/saas-staging/backend16-exact-session-once.ts. Before any DB connection it checks the exact service ID, project/environment ID, explicit enable flags and the private PostgreSQL URL, downloads immutable GitHub SQL with no redirects, verifies 9818 bytes and SHA-256.

On an independently preflight-positive schema it temporarily enables the existing **non-superuser** migrator LOGIN with a fresh in-memory 32-byte random password and 5-minute expiry, submits SQL0008 in **one** transaction, reads back the eighth ledger receipt, catalog, old RLS and new SECURITY DEFINER function privileges, then immediately restores NOLOGIN PASSWORD NULL and verifies pg_authid.

Positive marker emitted only AFTER verification and seal:

    PASS_BACKEND16_STAGING_PG16_0008_EXACT_SESSION_NOLOGIN

Any failure (including lost COMMIT ACK) emits only:

    BACKEND16_STOP_UNKNOWN_COMMIT_RECONCILE_NEVER_RETRY

The STOP marker does **not** establish either success or absence. For a successful acceptance require terminal Railway deployment SUCCESS, positive marker in exact deployment logs, PLUS independent read-only SQL readback of eight receipts, SQL0008 definer privileges, and sealed migrator. On any other observation, STOP and manually reconcile without retries. If manual repair is needed for a failed migrator seal, do it only through a separately approved operator action.

Evidence has been archived in
[PR #53](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/53#issuecomment-6265741781).
The temporary staging installer was removed, and independent Railway
inventory confirmed PostgreSQL service `37f8f166-75a6-4617-b243-8e681181c16d`
and volume `5a94361a-10c4-423a-a751-19271aa10fe6` remained intact.
This is a **completed historical operation**, not a pending action.

## Production blockers after SQL0008

The SQL migration is a narrow **boolean** database predicate. It does NOT verify OIDC JWT signatures, bearer-token binding, real IdP sessions, physical PG connection pool, durable off-host audit or cancellation/UNKNOWN COMMIT handling in an actual HTTP API.

A production-ready SaaS still requires real private bearer-bound session authority, per-principal PostgreSQL vault/connection driver, exact SQL0008 with FORCE RLS in the SAME transaction, two-tenant real login and revoke races, connection PID quarantine/discard, private ingress, external audit, backup/PITR/restore and separate canary approval. Do not launch public SaaS based on migration evidence alone.
