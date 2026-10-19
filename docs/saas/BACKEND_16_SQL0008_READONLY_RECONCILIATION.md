# Backend16.8 — SQL0008 independent READ ONLY reconciliation

**Status 2026-10-19: permanent Railway staging SQL0008 INSTALLED and
independently reconciled.** This is a separate operator diagnostic and
disposable PostgreSQL16 E2E, **not** a migration installer, automatic recovery
step, role repair, or permission to rerun SQL0008. The single-use installer
was deleted after successfully completing its operation. Evidence:
[GitHub PR #53](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/53#issuecomment-6265741781).

The existing isolated Railway staging database is `saas_staging`, private endpoint `postgres.railway.internal:5432`, PostgreSQL16 service `37f8f166-75a6-4617-b243-8e681181c16d`, project `a9703851-6eb1-406c-bb15-7d3a89359fb7`, environment `b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b`. Never connect to production Core/Gateway, any customer database, public SQL proxy, or `/data`.

## Exactly two expected states

This is one reviewed SQL file: `scripts/saas-staging/backend16-0008-readonly-reconcile.sql`. It requires an explicit psql variable `b16_expected_state`. It starts `REPEATABLE READ READ ONLY`, checks actual transaction_read_only=on, and uses fixed SELECT statements and a non-writing PL/pgSQL catalog assertion block. PostgreSQL **may not execute any database write** inside this transaction.

- `absent` — exactly seven original migrations (0001–0007), original SQL0007 pinned hash and source commit, SQL0008 function **absent**, migrator sealed NOLOGIN/PASSWORD NULL, runtime role restrictions, private table grants, triggers and FORCE RLS intact. Positive marker: `PASS_BACKEND16_SQL0008_READONLY_ABSENT_SEALED_NEVER_AUTO_INSTALL`.
- `installed` — exactly eight receipts with pinned SQL0008 SHA256 and staging provenance source commit, an exact SECURITY DEFINER VOLATILE boolean function owned by the migrator, EXECUTE restricted to runtime reader/writer, no PUBLIC/other grants, subject/session/binding checks and FOR SHARE lock source present, original baseline unchanged and migrator **again** sealed. Positive marker: `PASS_BACKEND16_SQL0008_READONLY_INSTALLED_SEALED`.

Every unexpected state or privilege drift raises a generic `B16_READONLY_STOP_...` diagnostic **without writing**, and the required PASS marker is absent. Running the script without an expected state intentionally fails before opening a transaction. In permanent Railway staging, the diagnostic additionally rejects any unexpected `saas_*` login/role memberships or nonempty synthetic tables and checks that no second client backend is connected. In *disposable CI only* (`saas_staging_ci`) test-created principals and grants may exist, and source_commit values may equal CI's commit SHA instead of permanent staging's reviewed source commits.

## Operator commands (ONLY within an already authenticated PRIVATE PG16 shell)

**Historical example only (before 2026-10-19 installation, or in disposable CI):** The following `absent` invocation was valid before the one-shot migration. **Do not use this historical ABSENT workflow to authorize a migration retry on permanent staging.** Never paste credentials into GitHub or chat:

```bash
PGOPTIONS='-c saas.staging_only=true' \
  psql -X -v ON_ERROR_STOP=1 -d saas_staging \
  -v b16_expected_state=absent \
  -f scripts/saas-staging/backend16-0008-readonly-reconcile.sql
```

**Current operator expectation: INSTALLED.** For any future, separately
approved, read-only audit on permanent staging, use the same pinned script with
`-v b16_expected_state=installed` through an independently authenticated
private PG16 shell. Archive PASS/STOP only; never print DB URLs or passwords.

On 2026-10-19, the separate installed-mode Railway read-only diagnostic
reported `PASS_BACKEND16_SQL0008_READONLY_INSTALLED_SEALED` in deployment
`623f00ff-92f0-4fb5-9a91-d7ba0d33a3df`, after the **single** one-shot
installer deployment `36fb4858-3d5b-4c15-a115-ba4a2a56cba6`. Both were
Railway SUCCESS; the installed read-only check also verified receipt SHA/source
commit, SQL0008 definer/EXECUTE, FORCE RLS and sealed migrator. Neither CI nor
a deployment's SUCCESS status alone is an acceptable replacement for the
specific verified read-only marker.

**Critical:** an ABSENT observation is historical and does not authorize a retry after an UNKNOWN COMMIT. Another concurrent operator could change the catalog immediately after the snapshot. The single-use installer must still perform its *own* strict preflight just before its one and only SQL0008 submission. If COMMIT acknowledgement, readback, or migrator NOLOGIN seal is unknown, STOP and manually reconcile. Never redeploy, replay or automatically repair the migrator.

## CI and remaining release gates

The real disposable PostgreSQL16 pipeline executes the same exact SQL file twice, with the migrator sealed before each observation: first on seven-receipt SQL0007 state, then after one SQL0008 application on eight receipts, ahead of synthetic two-LOGIN/tenant/session revocation tests. A Bun static contract verifies source pins, absence of DML/DDL statements and required markers. CI results **do not establish the state of persistent Railway staging**.

**Current operational state:** The `saas-b16-0008-once` installer
(`302e9762-7451-4999-a657-f5b3624dab63`) was deleted after the verified
one-time installation. Its historical `restartPolicyType=NEVER` gate was
confirmed before execution. It must never be recreated, restarted or replayed,
including after any future uncertain readback. Railway safety/2FA controls
must never be bypassed. No URL/domain/TCP proxy or public listener is
required for a separately authorized private read-only audit.

Production needs separate live IdP, bearer-bound session authority, private PG credential-vault driver, durable off-host audit, FORCE RLS same-transaction end-to-end, delivery/revocation semantics, backup/restore and canary approvals. Production Core/Gateway and `/data` remain untouched by this increment.
