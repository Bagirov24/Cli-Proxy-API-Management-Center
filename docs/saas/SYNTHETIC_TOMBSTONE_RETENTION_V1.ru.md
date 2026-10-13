# Stage 2G.4d.7i — Immutable UUID retention hard stops (staging, no GC)

**Status:** IMPLEMENTED on feature branch; verification is per commit SHA.
**Scope:** Disposable PostgreSQL 16 synthetic tests only. No deployment.

## Decision: no archive without a permanent non-reuse proof

A UUIDv4 can remain the durable identity of a committed 009 audit /
013 delivery intent even after its 016 recovery window closes. Removing
the private 016 issued-UUID tombstone (or a 015 producer binding) without
a separately durable, crash-safe non-reuse registry could permit a
different event to claim the same identifier. That violates producer
idempotency. A local count, hash, or unsigned export is **not** a proof
that a deleted identifier cannot be reused after restart or failover.

**This stage DOES NOT DELETE, MOVE, EXPORT, COMPRESS, TRUNCATE OR ARCHIVE
ANY TOMBSTONE.** It introduces no GC entrypoint. The private,
read-only health snapshot returns `gc_permitted=false` unconditionally,
never UUID values. This is an in-database observation only, **not**
external attestation or operator permission to discard rows.

Migration `018_synthetic_retention_legacy_hardstop_pilot.sql`
adds the conservative protections below.

## Cross-entrypoint immutable insert ceilings

New PostgreSQL `BEFORE INSERT` triggers apply to the private
`synthetic_operation_issues` and `synthetic_producer_operations`
tables, regardless of which signed function inserted the row.
Both acquire a tenant-scoped transaction advisory lock before
capacity checks. Each successful insert also consumes an atomic
per-actor and per-tenant private budget. If the budget/cap is
exhausted, the insertion raises a `check_violation`; **its entire
publication transaction, including 009 audit and derived 013 intent,
must roll back**. No partial ACK or tombstone can survive it.

| Table / insert class | Actor/tenant lifetime cap | Tenant lifetime cap | Shared successful-insert rate |
|---|---:|---:|---|
| 016 issued UUIDs | 12 | 48 | 32 actor / 64 tenant per 5 min |
| 015 producer event mappings | 64 | 256 | 32 actor / 64 tenant per 5 min |

The 016 issuer's previously verified tighter *front-door* limits
(4 actor / 16 tenant per 5 min) remain for its opted-in port. Table
triggers add separate `raw_issue` and `producer_event` budgets.
These limits count successful immutable inserts; a failed operation
that rolls back has no durable insert to meter.

The existing row-level UPDATE/DELETE rejection remains in force.
018 additionally installs `BEFORE TRUNCATE` rejection on both
tables; TRUNCATE would otherwise bypass UPDATE/DELETE row triggers.

Only an isolated CI `postgres` session with **no SET ROLE** may seed
the privileged static SQL fixture rows without consuming insert
budgets. All signed `SET LOCAL ROLE saas_rls_reader` operations and
the non-superuser Bun `saas_ci_runner` connections use the guard.
PostgreSQL superusers/table owners may still change DDL, disable
triggers, copy the database or alter records: this is **NOT**
tamper-evident archival, a production migration or trust
against privileged administrators.

## Close legacy SQL bypasses without public recursion

Original 016 direct `issue_signed_synthetic_operation` and
`read_signed_synthetic_operation_status` signatures remain
available to the previously authorized staging reader, but are now
**metered legacy facades**. The reviewed 015/016 implementations are
copied to schema-private, non-reader-executable core functions.
The opted-in 017 bounded issuer/status functions invoke those cores
directly, avoiding recursion back into the legacy facades.

The legacy 016 direct issuer now has a separate **8 per actor and
32 per tenant, per 5 minutes** budget and rechecks the immutable
12/48 lifetime ceilings. The legacy direct status has a separate
**16 per actor / 64 per tenant per minute** budget and returns
SQL NULL for unknown/denied/exhausted status. The original fixed
017 Bun status still commits its own attempts and returns one
uniform generic 404 for `absent` and `throttled`.

These distinct budget classes are **not** an aggregate global
tenant/API rate limit. A direct SQL caller who is deliberately
allowed to run a transaction and then ROLLBACK it can undo
its status debit; the supported Bun request boundary is the
committing path. These legacy facades are not production endpoints.

015 unissued synthetic producer requests do not require issuance,
but new producer-event insertions are now guarded by the common
immutable table trigger. Exact 015 replay remains idempotent and
does **not** consume a new-insert budget. This does not limit
attempt bursts for old existing UUIDs or the separate older 009
local publication route without a 015 producer mapping.
The pre-COMMIT local handoff issue is STILL unresolved.

## Out-of-order privileged migration replay

Older 015/016/017 migrations use `CREATE OR REPLACE FUNCTION` and
can restore older SQL facades if a privileged operator reruns them.
The 018 table INSERT/TRUNCATE triggers remain installed, but
the legacy direct status metering can be overwritten. Therefore
**018 must be applied last** after any privileged replay.
The updated PostgreSQL CI deliberately replays older migrations,
reinstalls 018, checks the final function definitions, runs the
adversarial acceptance, and replays 018 again to prove idempotence.

No migration rollback plan or downgrade authorization is implied.
Using out-of-order privileged SQL in a live database is NOT approved.

## Non-destructive operational visibility

The private, role-restricted function
`saas_rls_private.synthetic_operation_retention_health(tenant)`
returns ONLY total issue mappings, total producer mappings, expired
issue count, remaining tenant capacity for each mapping class, and
`gc_permitted=false`. It never returns operation IDs, actor IDs,
JWTs, tenant metadata rows, event payload or worker receipts.
It is a convenience capacity snapshot on this SAME PostgreSQL
instance, not an immutable external witness.

Tests cover tenant/actor capacity exhaustion, exposure ACLs,
bounded direct 016 status and issuance, 015 new-event quota
rollback without leaving an audit/intent, surviving idempotent
replay, denied TRUNCATE/UPDATE, snapshot GC=false, and
correct wrapper restoration after privileged old-migration
replays. Existing Bun unknown-COMMIT/ROLLBACK, producer concurrency,
fencing, revocation and read RLS suites remain enabled.

## What remains SPEC / production gate OPEN

There is no archival action in 018. A safe future archive would need
at least an independently durable, versioned and authenticated
non-reuse registry; atomic producer cutover; crash/failover recovery;
reconciliation of issued and producer-linked identities; retention,
privacy and deletion semantics; capacity monitoring and human
settlement on exhaustion; external integrity proof; authorization
and keys; and adversarial restoration/roll-forward testing.

Also unresolved: real authenticated producer HTTP endpoints,
client state persistence, a consolidated per-actor/tenant + edge
rate policy, legacy request-attempt throttling, semantic payload
hashes, real remote transports/ACK, dispatch-time revocation,
OIDC/Vault, audit, privacy retention, and security approvals.

**No merge, force-push, production/Railway, Core/Gateway/CPA/OAuth,
real credentials, /data, management.html or live network dispatch.**
This is strictly a limited synthetic CI proof.

**CODE VERIFIED:** `8659e3c091bb4f6b3f03a8ea444ad319e73cbfe6` — [Main CI #38360039654](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38360039654), [PostgreSQL16 #38360039690](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38360039690), [Demo #38360039733](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38360039733) and [Chromium #38360039704](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38360039704) all SUCCESS. The final docs SHA needs its own Actions verification.


## Stage 2G.4d.7j — detached checkpoint, no archive transfer

A job-local Ed25519 witness now signs canonical SHA-256
commitments for the current immutable 015/016 UUID sets and
links each checkpoint to its predecessor. The verifier pins
the last signature digest outside PostgreSQL and rejects a
simulated older restored projection missing a committed ID.
A terminated physical PostgreSQL transaction cannot appear
in the witness until COMMIT. The signing key and pinned head
are deleted after the ephemeral GitHub Actions test.

This is NOT a durable external witness. No real backup restore,
archival, GC, capacity refill, hostile owner-proof mechanism
or validation on actual future UUID issuance exists.
`gcPermitted=false` always, and migration 018 remains
the final SQL retention hard stop. No migration 019.
[Details](SYNTHETIC_ARCHIVE_WITNESS_PROOF_V1.ru.md).

**CODE VERIFIED on `66019cd7602d256148562eafd304e9712a2d907b`:** [Main CI #38363925445](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925445), [ephemeral PostgreSQL16 #38363925442](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925442), [Demo #38363925450](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925450), [Chromium #38363925440](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925440) all SUCCESS. Final docs SHA needs its own Actions. No production release claim.


## 2G.4d.7k — actual restore proof, NOT tombstone reclamation

A complete synthetic PG16 backup is taken before and after an
additional committed issue UUID. Both dumps are restored via
`pg_restore` into distinct scratch databases. The old copy
fails strict verification against the new fsynced offline
signed witness head; the current copy passes. The witness
head and pinned anchor survive *verifier process restarts
within one CI runner*, NOT replacement of the runner host.

Physical archive/GC remains unimplemented; `gcPermitted=false`.
The restore-only test does not alter, delete or reissue any
original 015/016 tombstone and does not grant capacity relief.
[Full 7k contract](SYNTHETIC_WITNESS_RESTORE_PROOF_V1.ru.md).

**CODE VERIFIED at `9af3b8d5b29ebceb6a433468c650f01be913a148`:** [Main CI #38367994239](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994239), [ephemeral PostgreSQL16 #38367994247](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994247), [Demo #38367994191](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994191), [Chromium #38367994196](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994196) — **4/4 SUCCESS**. Final docs SHA must be separately verified. No archive or GC authorization.


## 2G.4d.7l — local high-water is NOT safe tombstone retention

Even a three-file witness arrangement detects only partial
rollback or an unsigned COMMIT when a fresh authoritative
projection is supplied. The CI deliberately demonstrates
that jointly reverting witness A/B, high-water journal and
the presented projection can recreate a valid old head.
Therefore lifetime 016/015 UUID rows remain immutable;
no GC/archive delete, reset of 017/018 caps or reissue
permission is added. `gcPermitted=false` remains fixed.
[7l proof](SYNTHETIC_WITNESS_HIGHWATER_GAP_V1.ru.md).


## 2G.4d.7o — signed PG snapshot does NOT release tombstones

The restricted SQL projector reads 015/016 issued and
producer operation UUIDs inside one PG16 read-only
transaction and signs hashed commitments. Its distinct
public key and challenge are pinned only within one CI
runner. The proof detects a mismatched source projection
but offers no external immutable history, authorized
archive, safe GC, UUID deletion/reuse or cap restoration.
`gcPermitted=false` remains unchanged.
[7o proof](SYNTHETIC_PG_PROJECTION_ATTESTATION_V1.ru.md).
