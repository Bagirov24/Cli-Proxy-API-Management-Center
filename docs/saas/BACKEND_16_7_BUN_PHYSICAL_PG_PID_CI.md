# Backend16.7 — real Bun.SQL physical PostgreSQL backend / PID acceptance

**Status:** GitHub Actions disposable PostgreSQL16 proof only. NOT permanent Railway staging, NOT production, NOT HTTP-deployed, no customer users or credentials. This proof is a prerequisite to independently reviewing a real per-principal vault-backed staging driver, not that implementation's production sign-off.

## Security boundary

Backend16.6 already has a source-only exact SQL0008 readAuthorized port with server-owned SQL, four bound session/subject parameters, one READ COMMITTED transaction and FORCE RLS. Fake-pool unit tests can verify protocol ordering but cannot prove that `release(discard)` destroys a **physical PostgreSQL backend**.

This increment creates `backend16CiBunPhysicalPgPool.ts`, which is intentionally hard-pinned to the disposable GitHub PostgreSQL16 service on **127.0.0.1:5432/saas_staging_ci**. It refuses construction without GITHUB_ACTIONS, SAAS_B16_EPHEMERAL_CI and SAAS_B16_PHYSICAL_CI all exactly true; it also refuses Railway metadata or a production NODE_ENV. It MUST NOT be used in persistent staging, CPA Core/Gateway, or any public backend.

The caller passes only an operator-supplied credential resolver. The request's verified LOGIN is compared exactly with the credential record's username and reserved roles are prohibited. The database driver cannot choose host/port/database or accept raw SQL from clients. Every single request allocates its own Bun.SQL PostgreSQL **max:1** pool and reserves a single authenticated physical backend; only eight exact SQL0008 reader statements and their expected bound argument counts are admitted. Before handoff, the driver sets the staging-only marker on the same server connection without SET ROLE or tenant impersonation.

**No connection reuse:** A successful read calls the Bun.SQL pool's close({timeout:0}) before making a response visible. An uncertain acquisition, cancelled query, driver SQL error or unknown COMMIT causes a synchronous pool-wide quarantine and immediate best-effort physical close. All future acquisitions fail closed. The pool has at most three concurrent requests in this disposable probe. Real cancellation/PID and timeout semantics must be tested; a fake interface alone is not acceptable evidence.

## Real two-principal PG16 E2E

The existing PostgreSQL16 workflow executes SQL0001-0008 on a **disposable synthetic fixture database**, then creates two distinct physical LOGINs with separate randomly generated ephemeral passwords, tenant grants, subject digests, binding UUIDs and current sessions. The test script is invoked **before** the fixture's revocation so the exact SQL0008 predicate can succeed.

The Bun.SQL test:
- Acquires separate real PostgreSQL backends for A and B and proves distinct positive backend PIDs in `pg_stat_activity`.
- Releases both and independently checks both PIDs disappear, rather than claiming in-memory discard is physical termination.
- Calls the actual Backend16.6 readAuthorized port over the driver, proves both exact tuples authorized and cross-tenant denied; verifies zero leaked physical sessions after normal results.
- Holds a real concurrent `FOR UPDATE` lock over A's tenant grant, observes A's blocked SQL0008 `FOR SHARE` through `pg_stat_activity`, aborts the request, requires the adapter to fail closed and checks A's backend PID disappears.
- Verifies a quarantined pool is unusable while a fresh fully isolated CI-only pool can still authorize B.
- Rejects an operator credential resolver returning B credentials for a request claiming A.

The test never requests real tokens, secret metadata, internet, Railway credentials, persistent staging or production PG. The fixture's remaining SQL0008 grant-revoke/regrant ABA tests still execute normally after the physical driver experiment.

## Remaining release blockers

This is intentionally **not a production connection pool**. It has no configured Railway private-network credentials, tenant rate limits in a shared deployment, production-secret vault, cross-process revocation audit, durable redacted off-host logging, pinned live IdP issuer/JWKS/PKCE enrollment, external delivery acknowledgement or public/private ingress. It cannot be used to infer the state of the permanent staging database.

Separately, the SQL0008 staging installer staged in Railway remains a no-database placeholder. Deployment is STOP until the exact Function's Restart Policy **Never** is independently confirmed, a fresh seven-receipt read-only preflight passes, and the reviewed one-shot migration is applied and independently reconciled. Never rerun an ambiguous COMMIT. Do not change production Core/Gateway or /data based on this CI result.

After this E2E is green: independently review a dedicated real staging credential vault/physical driver and private network, then repeat the genuine connection lifecycle/PID evidence and prove exact bearer-bound OIDC session, external audit and private HTTP response/revocation behavior before canary production.
