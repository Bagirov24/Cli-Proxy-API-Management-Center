# Backend16.8 — SQL0008 independent READ ONLY reconciliation

**Status:** separate operator diagnostic and disposable PostgreSQL16 E2E. It is NOT a migration installer, automatic recovery step, role repair, or permission to rerun SQL0008.

The existing isolated Railway staging database is `saas_staging`, private endpoint `postgres.railway.internal:5432`, PostgreSQL16 service `37f8f166-75a6-4617-b243-8e681181c16d`, project `a9703851-6eb1-406c-bb15-7d3a89359fb7`, environment `b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b`. Never connect to production Core/Gateway, any customer database, public SQL proxy, or `/data`.

## Exactly two expected states

This is one reviewed SQL file: `scripts/saas-staging/backend16-0008-readonly-reconcile.sql`. It requires an explicit psql variable `b16_expected_state`. It starts `REPEATABLE READ READ ONLY`, checks actual transaction_read_only=on, and uses fixed SELECT statements and a non-writing PL/pgSQL catalog assertion block. PostgreSQL **may not execute any database write** inside this transaction.

- `absent` — exactly seven original migrations (0001–0007), original SQL0007 pinned hash and source commit, SQL0008 function **absent**, migrator sealed NOLOGIN/PASSWORD NULL, runtime role restrictions, private table grants, triggers and FORCE RLS intact. Positive marker: `PASS_BACKEND16_SQL0008_READONLY_ABSENT_SEALED_NEVER_AUTO_INSTALL`.
- `installed` — exactly eight receipts with pinned SQL0008 SHA256 and staging provenance source commit, an exact SECURITY DEFINER VOLATILE boolean function owned by the migrator, EXECUTE restricted to runtime reader/writer, no PUBLIC/other grants, subject/session/binding checks and FOR SHARE lock source present, original baseline unchanged and migrator **again** sealed. Positive marker: `PASS_BACKEND16_SQL0008_READONLY_INSTALLED_SEALED`.

Every unexpected state or privilege drift raises a generic `B16_READONLY_STOP_...` diagnostic **without writing**, and the required PASS marker is absent. Running the script without an expected state intentionally fails before opening a transaction. In permanent Railway staging, the diagnostic additionally rejects any unexpected `saas_*` login/role memberships or nonempty synthetic tables and checks that no second client backend is connected. In *disposable CI only* (`saas_staging_ci`) test-created principals and grants may exist, and source_commit values may equal CI's commit SHA instead of permanent staging's reviewed source commits.

## Operator commands (ONLY within an already authenticated PRIVATE PG16 shell)

Run the absent inspection **before** any one-shot SQL0008 deployment, after verifying the Railway Function's restart policy, staged patch scope and private database connection. Do NOT paste credentials into GitHub or chat:

```bash
PGOPTIONS='-c saas.staging_only=true' \
  psql -X -v ON_ERROR_STOP=1 -d saas_staging \
  -v b16_expected_state=absent \
  -f scripts/saas-staging/backend16-0008-readonly-reconcile.sql
```

After the single reviewed installer execution and independent migration ledger evidence, run with `-v b16_expected_state=installed` on the same isolated private DB through the privileged operator connection. Preserve only the PASS/STOP marker, never raw database URLs or secret values. In the absence of a private authenticated PostgreSQL shell, this repo cannot run the check and **must not** infer database state from Railway deployment SUCCESS.

**Critical:** an ABSENT observation is historical and does not authorize a retry after an UNKNOWN COMMIT. Another concurrent operator could change the catalog immediately after the snapshot. The single-use installer must still perform its *own* strict preflight just before its one and only SQL0008 submission. If COMMIT acknowledgement, readback, or migrator NOLOGIN seal is unknown, STOP and manually reconcile. Never redeploy, replay or automatically repair the migrator.

## CI and remaining release gates

The real disposable PostgreSQL16 pipeline executes the same exact SQL file twice, with the migrator sealed before each observation: first on seven-receipt SQL0007 state, then after one SQL0008 application on eight receipts, ahead of synthetic two-LOGIN/tenant/session revocation tests. A Bun static contract verifies source pins, absence of DML/DDL statements and required markers. CI results **do not establish the state of persistent Railway staging**.

SQL0008 staging installer `saas-b16-0008-once` (`302e9762-7451-4999-a657-f5b3624dab63`) is still a **staged-only no-DB placeholder** until an operator confirms its `restartPolicyType=NEVER` via Railway UI and independent readback. Previous tool safety blocks may not be bypassed. No URL/domain/TCP proxy or public HTTP listener is required to perform a private DB read-only review.

Production needs separate live IdP, bearer-bound session authority, private PG credential-vault driver, durable off-host audit, FORCE RLS same-transaction end-to-end, delivery/revocation semantics, backup/restore and canary approvals. Production Core/Gateway and `/data` remain untouched by this increment.
