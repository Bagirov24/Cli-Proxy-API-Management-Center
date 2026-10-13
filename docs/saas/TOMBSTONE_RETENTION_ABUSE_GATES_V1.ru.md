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


## Follow-on 018: common insertion guard for legacy SQL bypasses

017 controlled only the new fixed issuer/status templates.
018 adds private BEFORE INSERT checks to the underlying 016
issues and 015 producer-event tables, so legacy caller paths
cannot append unlimited new identities. 016 caps are still
12/48 lifetime; synthetic producer mappings have 64 actor/256
tenant lifetime ceilings. Both get separate raw successful-insert
budgets (32 actor / 64 tenant per five minutes). Legacy 016
direct issue/status functions now meter via private core wrappers;
their quotas are separate from opted-in 017 budgets.

The new read-only tenant capacity snapshot reports
`gc_permitted=false`; it is NOT a cryptographic archive proof.
There is no tombstone deletion or reuse. Privileged old-migration
replay requires applying 018 last to restore public metering.
The old 009 callback path and rollback-able raw status SQL
request counters remain outside a global abuse guarantee.
[Detailed contract](SYNTHETIC_TOMBSTONE_RETENTION_V1.ru.md).


## Stage 2G.4d.7j — no quota increase or GC from signed hashes

Detached Ed25519 checkpoints are CI-only evidence of monotonic
UUID commitment sets. They do not remove 017/018 lifetime caps
(12/48 issued, 64/256 producer), refill actor/tenant budgets,
allow TRUNCATE/DELETE, or establish a production non-reuse registry.
A stale, forged or incomplete witness is rejected against the
job-local pinned head; true external persistence and
capacity relief remain SPEC.
[Proof-only protocol](SYNTHETIC_ARCHIVE_WITNESS_PROOF_V1.ru.md).

**CODE VERIFIED on `66019cd7602d256148562eafd304e9712a2d907b`:** [Main CI #38363925445](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925445), [ephemeral PostgreSQL16 #38363925442](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925442), [Demo #38363925450](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925450), [Chromium #38363925440](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925440) all SUCCESS. Final docs SHA needs its own Actions. No production release claim.


## 2G.4d.7k — signed restore evidence does not increase capacity

The full PG16 `pg_dump`/`pg_restore` CI proves a stale backup
is missing at least one later committed synthetic UUID. It
does not reset the 017/018 lifetime caps, grant deletion,
change short-window issuance/status quotas, or authorize
a new key on an exhausted tenant. A strict verifier denies
both stale restored backups and uncheckpointed extra UUIDs.
The fsynced head still lives on a single CI runner.
[7k restore witness contract](SYNTHETIC_WITNESS_RESTORE_PROOF_V1.ru.md).

**CODE VERIFIED at `9af3b8d5b29ebceb6a433468c650f01be913a148`:** [Main CI #38367994239](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994239), [ephemeral PostgreSQL16 #38367994247](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994247), [Demo #38367994191](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994191), [Chromium #38367994196](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994196) — **4/4 SUCCESS**. Final docs SHA must be separately verified. No archive or GC authorization.


## 2G.4d.7l — high-water quorum does not refill quotas

An updated pair of Ed25519 signed heads plus local
high-water marker does not remove old 015/016 bindings or
restore the 12/48 issued and 64/256 producer lifetime limits.
It does not enforce edge quotas, authorize new UUIDs,
or provide an independent global idempotency root.
Source PG16 may commit a UUID before the witness observes it;
the exact restore verifier then rejects that unsigned gap
instead of treating it as covered archival history.
[7l contract](SYNTHETIC_WITNESS_HIGHWATER_GAP_V1.ru.md).
