# Stage 2G.4d.7h — bounded synthetic operation quotas, no tombstone GC

**IMPLEMENTED in the disposable PostgreSQL16 feature-only pilot.**
CI evidence must refer to the exact code HEAD. None of this enables
production, Railway, an HTTP service, a network delivery or a client ACK.

## Why hard tombstone retention is the conservative choice

Migration 016 makes issued UUIDv4 rows immutable. Deleting an expired
row without an independently durable non-reuse registry would allow the
same UUID to be issued again and could associate it with a new logical
009/013 event. Therefore Stage 017 **does not delete, truncate, archive,
reuse or amend 016 tombstones**. There is no GC implementation.

A permanent append-only registry is not operationally sustainable at
unbounded issuance rates. The staging pilot explicitly stops issuing
new identifiers when either lifetime cap is reached:

- **12 total issued IDs per tenant/actor** (including already expired IDs).
- **48 total issued IDs per tenant**, across its actors.

These are **terminal lifetime ceilings**, not a safe retention/GC
policy. The pilot intentionally fails closed after reaching a cap.
Formal archival/non-reuse proof, operational recovery from exhaustion,
storage design and production-scale limits remain SPEC.

## Short-window issuance budgets

A new guarded `017_synthetic_operation_abuse_controls_pilot.sql`
defines a separate signed SQL function for the **new** staging issuer,
`issue_signed_synthetic_operation_bounded`. Every valid use still
reauthorizes signed current actor, tenant, member role, collection,
grant epoch and requested limit. Under a per-tenant transaction-scoped
advisory lock, it checks immutable 016 tombstones before calling the
original 016 issuer.

Two transactional rate windows cap successful issuance:

| Scope | New issued UUIDs | Window |
|---|---:|---:|
| Same tenant + actor | 4 | 5 minutes |
| Entire tenant (all actors) | 16 | 5 minutes |

A rejected issue returns the same generic denial as other staging
request conflicts; it never returns an operation ID and adds no
tombstone/009/013 intent. The successful issuer still creates **only**
an immutable 016 reservation, not a delivery event.

The budgets table holds at most one mutable row per
`(scope_kind, tenant, actor-or-tenant-sentinel, action_kind)`.
A row's counters and deadline roll over **in place** after expiry.
The separate tombstone registry remains append-only. Counting uses
PostgreSQL row-level UPSERT conflict serialization and a tenant-wide
advisory transaction lock for lifetime caps.

## Authenticated read-only status abuse budget

The **new staging status path** uses
`read_signed_synthetic_operation_status_bounded`. After validating a
signed, current PostgreSQL tenant+actor scope it meters **before**
looking up an operation UUID — including guesses and other tenants'
UUIDs — at:

| Scope | Status attempts | Window |
|---|---:|---:|
| Same tenant + actor | 16 | 1 minute |
| Entire tenant (all actors) | 64 | 1 minute |

The signed SQL query returns internal `absent` / `throttled`
sentinels that are **never exposed** to the caller. The trusted
server boundary **COMMITs the status budget debit before mapping
either outcome to the same tenantless `404 NOT_FOUND`**. This matters:
if an unknown-ID lookup generated a SQL denial and automatic
`ROLLBACK`, an attacker could probe unlimited guesses without
consuming the counter.

A known UUID normally yields only `issued`, `committed` or
`expired`. At the limit it also receives generic `404`;
the response does not reveal whether the ID existed, nor whether
the denial was a foreign UUID or an exhausted budget.

Authenticating and authorizing the current tenant precedes budget
consumption. Unknown/cross-tenant UUID probes therefore debit the
**authenticated caller's** bucket, never their target's. Neither
client IP nor bearer fingerprint is saved in the budgets table.

There is deliberately no mutable per-request log. The same two
budget rows for an actor/tenant can be reused across windows.
Short-window limits are **not** per-IP/global controls, and do not
protect the expensive preflight JWT / SQL authorization path.

## Test contract, and what is NOT protected

Adversarial disposable PostgreSQL16 SQL and Bun acceptance cover
issued-UUID cap, status 404 counters staying durable after COMMIT,
foreign-ID/shape denial, lifetime actor + tenant ceilings, quota
window reset, immutable tombstones, migration replay and separate
physical PostgreSQL sessions contending for the last status slot.
Existing RLS/JWT, producer unknown-COMMIT, 012/013/014 receiver and
015 concurrency tests continue to run unchanged.

The new bounded fixed templates are used by the isolated 016 issuer
and status port. For backwards-compatible local fixtures, the older
016 direct SQL issuer/status and legacy 015 unreserved publisher
remain available to their already-authenticated PostgreSQL role.
**The controls are NOT a database-wide/global invariant on every
legacy entrypoint.** Reserved-commit retry bursts are not independently
rate limited by 017, though the first event remains idempotent.
No public API, multi-instance client budget, distributed edge abuse
control, non-reuse archival proof, storage deletion, event payload
hashing, real transport or recipient ACK is implemented.

There is still a pre-COMMIT local handoff hazard on the older
publication boundary; local synchronous Allow observations are not
authoritative proof of a committed audit. 017 changes neither.

## Production readiness

**OPEN / SPEC:** capacity planning and operations when 12/48 caps are
reached, safe non-reusable tombstone archival/GC, per-tenant plan-based
quotas, tenant/actor enumeration and abuse policy, real authenticated
HTTP producer-ID issuance and status API, global and edge rate limits,
status transparency semantics, GDPR/deletion reconciliation,
durable payload and remote ACK, dispatch-time revocation and external
audit. No merge, force push, Railway, production, CPA/Gateway, OAuth,
live network traffic or real credentials are authorized.

## Verification on code SHA

**CODE VERIFIED:** `64d93a034face985d07aa990085d56678e441715`,
[Main CI](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159803),
[ephemeral PG16](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159812),
[Demo](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159923),
[Chromium](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159948).
All four workflows completed SUCCESS. The final documentation commit must pass
its own CI to claim final-head verification. No production readiness implied.
