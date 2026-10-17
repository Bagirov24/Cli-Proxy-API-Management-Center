# Backend16.9 — Staging physical Bun.SQL core / actual disposable PG16 E2E

**Status: unmounted and not approved for staging deployment or production.**

## Why an additional E2E exists

Backend16.7's real PostgreSQL16 test exercised an isolated, localhost-only
Bun.SQL driver. Backend16.9 now runs the **same staging physical/query/discard
core** in that disposable PG16 acceptance harness, through a separate
`createBackend16StagingDisposableCiPhysicalPgPool` entrypoint. This makes a
failure in the staging sequence or connection quarantine visible to real
PostgreSQL tests before any use of permanent Railway staging.

The two exported profiles are immutable and selected ONLY by separate,
exact-context constructors:

| | Railway staging candidate | Disposable GitHub PG16 |
|---|---|---|
| Host | `postgres.railway.internal` | `127.0.0.1` |
| Database | `saas_staging` | `saas_staging_ci` |
| TLS | `verify-full` | Bun.SQL default (no TLS override), loopback only |
| Operator gate | Exact Railway project/environment/service and explicit flags | `GITHUB_ACTIONS=true`, disposable PG16 marker, precise PGHOST/PGPORT/PGDATABASE and fixed synthetic PG password |
| Credentials | Injected operator-owned per-LOGIN vault interface | Two synthetic passworded PostgreSQL logins |
| Network | Staging-private ONLY (not mounted) | Ephemeral runner-local PG16 ONLY |

**No caller can choose a hostname, database, transport mode or profile.**
The core builder is private to the TypeScript module. The CI constructor
rejects Railway and production environments and cannot use any Railway
variables, customer credentials or remote database.

## Required disposable E2E assertions

In the existing `verify-backend16-exact-session-pg16.sh` runner, after
one-time SQL0008 installation in ephemeral **GitHub Actions PG16 only**, the
Backend16.9 test exercises:

1. A physically authenticated per-principal LOGIN with independent
   `session_user`, `current_user`, staging-only marker and real
   `pg_backend_pid()` from PostgreSQL.
2. A deliberately discarded unfinished transaction and the backend PID's
   disappearance from `pg_stat_activity`.
3. Successful exact subject/session/binding and FORCE RLS tenant/project
   reads for two distinct synthetic principals.
4. Both cross-tenant requests denied with no private data.
5. A real `FOR UPDATE` writer lock that blocks SQL0008's `FOR SHARE`,
   request cancellation, no publication, and backend PID disappearance.
6. Pool quarantine with no retry, followed by success on a **new** pool for
   an independently authorized principal.

The acceptance marker is:

`PASS Backend16.9: staging Bun.SQL core real PG16 physical LOGIN, locked exact session, cross-tenant deny, cancel/PID death and no retry`

It can be emitted only after all assertions; it does not prove permanent
Railway staging deployment, TLS trust, durable audit, a real vault, live OIDC
session authority, or production readiness.

## Persistent staging and production hard stops

- SQL0008 must be independently reconciled on the **actual** isolated
  `saas_staging` DB; absent/installed are observations, not retry grants.
- `saas-b16-0008-once` must remain a disabled placeholder until the
  operator independently confirms `restartPolicyType=NEVER` via Railway UI,
  migration receipts, approved exact installer hash and all one-shot gates.
  No alternate tool workaround for a blocked Restart Policy update.
- The staging physical driver requires a separately reviewed per-principal
  vault and trusted TLS CA/SAN (Bun's `verify-full`). Neither is implemented
  by this PR.
- A current, token-bound issuer/subject/session authority and durable off-host
  audit must exist before mounting `/internal/saas/v1` or publishing any DTO.
- No modification to Railway production Core/Gateway, `custom-no-apikey-fun`,
  volume `/data` or existing users/tokens is in this PR.
