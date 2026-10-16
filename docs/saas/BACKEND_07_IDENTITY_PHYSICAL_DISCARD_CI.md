# Backend 07 — Physical PostgreSQL identity pool discard (CI-only)

**16 October 2026.** This is a non-deployable, bounded physical disconnect experiment on disposable GitHub Actions PostgreSQL16. It is not a Railway production/staging service, durable production database migration or certification of general Bun.SQL connection quarantine.

## What is implemented

- \`scripts/saas-staging/ci-isolated-identity-pool.mjs\` implements the existing \`PgIdentityPool\` port for exactly one CI-only non-superuser login \`saas_identity_ci\`, database \`saas_ephemeral_test\` on loopback \`127.0.0.1:5432\`. Neither HTTP input nor a free-form URL can override the database, role, host, SQL or TLS settings.
- The adapter whitelists the exact SQL026/027 \`PG_IDENTITY_SQL\` statements and their parameter counts. It uses a dedicated \`Bun.SQL\` connection pool with \`max:1\`. Any ambiguous statement error, abort, COMMIT ACK uncertainty or physical-release failure poisons it **synchronously**, before possible reuse.
- Bun \`ReservedSQL.release()\` is not a physical destroy operation. The poisoned adapter releases the reservation and explicitly closes the **entire isolated pool** via \`SQL.close({timeout:0})\`; future reservations are rejected. No retry or operation reissue occurs.
- A disposable CI probe obtains \`pg_backend_pid()\` from the **reserved** connection itself. An independent PostgreSQL16 observer checks \`pg_stat_activity\` before and after clean closure and a synthetic lost local ACK **after a real acknowledged COMMIT**. A fresh separate pool then performs another read without reusing the retired backend.
- A main CI guard test denies constructing the adapter without \`SAAS_ISOLATED_IDENTITY_DISCARD_CI=true\`. The optional lost-ACK simulator exists only inside this CI-restricted driver. The main app and \`saasStagingHttpComposition.ts\` remain unchanged and expose no listener.

## CI and isolation

The PostgreSQL16 workflow runs this probe only **after SQL001–027 and Backend04** within the same disposable service, using the short-lived randomly generated \`saas_identity_ci\` credential. It is prohibited with \`RAILWAY_PROJECT_ID\`, \`RAILWAY_ENVIRONMENT\`, \`RAILWAY_SERVICE_ID\`, non-loopback host, non-ephemeral DB or \`NODE_ENV=production\`. It neither deploys Railway services nor reads secrets or volumes of CPA Core/Gateway.

## What is *not* proven

An intentionally thrown exception **after the local driver received PostgreSQL's COMMIT ACK** is not a network split *during* COMMIT. It does not prove reconciliation, physical discard on all faults, a transactionally consistent multi-replica failover, bounded close under a permanently stalled native driver, or authorization response linearizability.

For production, replace this test-only Bun adapter with a reviewed connection lifecycle; independently test real TCP loss/timeouts and crash/termination, pool acquisition races, operator-managed TLS/least-privilege credentials, persistent staging PostgreSQL migrations, backup/PITR/restore, external WORM audit and security/ops approvals. Never promote the pilot SQL001–027 directly; never auto-retry a 503 after UNKNOWN COMMIT.
