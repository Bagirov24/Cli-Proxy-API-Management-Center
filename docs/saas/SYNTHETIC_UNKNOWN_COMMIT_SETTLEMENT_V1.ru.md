# Stage 2G.4d.7m — UNKNOWN PostgreSQL COMMIT / detached witness settlement (CI-only)

**IMPLEMENTATION SCOPE: disposable PostgreSQL16 + offline Node adversarial tests.**
**Production readiness: OPEN.** This is a fail-closed *evidence check*,
not a real external witness, real producer, archival mechanism or ACK.

## Problem being tested

An attempt may COMMIT an immutable issued-UUID row while the caller
never receives a reliable COMMIT reply, and a detached Ed25519 witness
may still reflect an earlier snapshot. Issuing a new UUID, publishing
another 009/013 event or deleting the old tombstone based only on the
missing reply would break idempotency. In the current staging pilot,
015/016 already have their own authenticated operation logic. This
stage does NOT change them or grant a new production retry path.

7m adds:

- `scripts/saas-staging/archive-witness-settlement.mjs`: an **offline**
  verification-only CLI. It has no PostgreSQL credentials, no SQL
  issuer/transport dependencies and cannot return a customer-facing
  event, network ACK, deletion token or GC approval.
- `scripts/saas-staging/verify-archive-witness-settlement.mjs`:
  disposable PG16 end-to-end fault injection using actual transaction
  COMMIT/ROLLBACK and administrative termination of two test sessions.
- A new independent GitHub Actions step **after** the unchanged 7j,
  7k, 7l witness tests, not a migration 019.

## Prepared local candidate, *not* a signed production authorization

The test creates a candidate containing only the protocol identifier,
kind (`issued`/`producer`), SHA-256 UUID commitment, and the
sequence/digest of a **preexisting signed baseline checkpoint**.
The candidate is an UNTRUSTED fixture, not signed issuer approval.
The original UUID is not sent to the offline verifier. All JWT,
tenant, actor, scope, payload, outbox and receiver metadata are
excluded from this candidate and from the signed witness files.

The offline verification requires all of the following, fail-closed:

1. Exact candidate shape, domain-separated committed UUID hash and
   a baseline signed checkpoint bound to the advertised digest.
2. The baseline PostgreSQL projection must exactly match the
   authenticated Ed25519 baseline snapshot.
3. No earlier commitment may disappear in the current projection.
   The difference must contain **exactly one** newly observed UUID
   commitment, in the requested kind, equal to the prepared one;
   the other registry must not change.
4. Both separately verified, locally fsynced Ed25519 witness
   histories (7l) must agree with the current UUID projection,
   alongside their two pinned heads and third high-water journal.
5. The current witness checkpoint must be the direct signed
   successor of the prepared baseline checkpoint and include
   exactly the current UUID projection.

Anything else is DENY. In particular, absence of the UUID after
a lost response is **UNKNOWN/NOT OBSERVED**, NOT a determination that
the logical operation is safe to retry or replace with a new UUID.
Likewise, a committed UUID which has not yet appeared in both signed
histories and the high-water tip is **OBSERVED BUT NOT SETTLED** and
is DENIED by this offline test gate.

When all conditions match, the proof prints only a synthetic
`LOCALLY_OBSERVED_SIGNED_ONLY`-style acceptance. That is a local
identity-continuity observation — **not** an externally
acknowledged delivery, real independent attestation, publication
authorization, valid issuer consent or exactly-once guarantee.
`gcPermitted=false` without exception.

## Physical fault injection and adversarial tests

The PG16 CI scenario projects the existing 015/016 immutable UUID
registries and signs an initial Ed25519 checkpoint under the 7l
two-replica/third-journal local high-water proof.

- A candidate alone cannot settle without a database insert.
- **ROLLBACK after lost connection:** a physical PG16 session
  INSERTs a synthetic issued UUID inside `BEGIN`, blocks on
  `pg_sleep` **before COMMIT**, and is terminated with
  `pg_terminate_backend`. Its process returns failure and the
  separate database reader finds no issued UUID. Settlement DENIES;
  the test does not invent a retry entitlement.
- **COMMIT with lost response:** another physical PG16 session
  completes a real `COMMIT`, then waits on `pg_sleep`
  **after COMMIT**, before the test deliberately terminates the
  connection. The caller observes connection failure (UNKNOWN),
  while a separate reader confirms the exact prepared UUID now
  exists. Before witness publication, settlement DENIES.
- Sign a successor snapshot: updating only replica A DENIES;
  updating A+B without the high-water journal DENIES;
  only a matching signed successor and the high-water journal
  yields local identity reconciliation PASS.
- Negative paths: mismatched prepared UUID hash, forged baseline
  digest, wrong registry kind, old database projection, unanticipated
  additional commitment, and unexpected request field all DENY.
- A fresh PostgreSQL projection never yields a 009 signed audit or
  013 delivery intent from these fixture-only operations. The
  private `synthetic_operation_retention_health` still reports
  `gc_permitted=false`.
- All proof keys and files are private to the ephemeral CI runner,
  neither uploaded to job artifacts nor kept after the test.

The 7k **real `pg_dump` / `pg_restore` into scratch databases**
and 7l high-water negative rollback counterexample remain enabled.

## Limits (not independently durable external service)

7m still relies on a single GitHub runner and one PostgreSQL16
service. The two witness directories and the third journal are
**local and jointly rollbackable**, as proven by 7l. The baseline
candidate is untrusted, and PG truth is projected by a test
administrator with no cryptographic live-DB binding. There is no
separately owned root, WORM storage, physically independent host,
production credential, timestamp trust, actual network partition
or independent object-store versioning.

The gap between PostgreSQL COMMIT and witness update is **detected
but not closed atomically**. A missing/not-visible UUID after a
connection error could still be present on another/partitioned node
or COMMIT later. This proof does not grant retries and does not
gate real issuance or replay. The local signed snapshot is not
proof of an external receiver ACK.

## Production gates that remain OPEN / SPEC

1. An independently operated, durable, rollback-resistant external
   witness and monotonic high-water root across hosts/runners, with
   verified availability, key custody, rotation and revocation.
2. Authenticated tenant/actor/collection and issuer-grant binding
   on every production prepared UUID and non-reuse validation,
   including after physical PITR/failover and partitions.
3. A **fenced producer COMMIT → witness settlement protocol** with
   an atomic/durable intent boundary, unknown-outcome resolution,
   protection from competing writers, and formal idempotent
   recovery semantics after service and witness restarts.
4. Real disaster/backup/WAL/PITR, corrupted witness, storage
   partition, multi-host quorum and stale-read adversarial tests.
5. External delivery, recipient authentication and ACK, removing
   the older pre-COMMIT handoff hazard, production edge quotas,
   privacy/legal retention, operational capacity policy and
   independent security/release sign-off.

**No operation tombstone DELETE, TRUNCATE, GC, UUID reuse, capacity
recycling, migration 019, Core/Gateway/CPA/OAuth change, production
or Railway deployment, public SaaS API, real credentials/payload
or live traffic is authorized.**

## Verified code evidence

**CODE VERIFIED on SHA `040e861b84b0ab485ae6144896e9d3e1375b00e8`**, 4/4 workflows SUCCESS:
[Main CI #38373532532](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38373532532),
[ephemeral PostgreSQL16 #38373532610](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38373532610),
[Demo #38373532630](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38373532630) and
[synthetic Chromium #38373532525](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38373532525).
The final documentation SHA requires its own checks. This evidence
does not authorize independent durable witness, remote ACK, GC or production.


## Follow-on Stage 2G.4d.7n — witness ACK may also be UNKNOWN

The new long-lived Unix-socket signer can sign and fsync
a checkpoint, publish its head, and then lose the IPC ACK
before the client learns the result. Restarting from the
same unmodified local signed state and re-sending the same
128-bit request ID, predecessor and projection returns the
same signed receipt. It does NOT create another operation
or authorize a retry of a real producer UUID. A changed
idempotency request or stale expected head is denied.
The 7m lost PostgreSQL COMMIT response remains separate:
the new IPC daemon is not transactionally bound to SQL.
[7n proof](SYNTHETIC_IPC_WITNESS_LOST_ACK_V1.ru.md).


## Follow-on 2G.4d.7o — source-backed snapshot verification

The 7o proof signs an actual repeatable-read PG16 projection
under an ephemeral UUID-column-only database role, not a
client's invented commitment array. A newly committed UUID
cannot match an older signed witness checkpoint; a fresh
direct successor and matching projector signature are needed.
The verification remains offline and CI-only: no real
producer prepared candidate is issuer-authenticated and
the PG16 source is not independently trusted across
PITR/host rollback. Nothing settles an external ACK or
authorizes another issuance.
[7o contract](SYNTHETIC_PG_PROJECTION_ATTESTATION_V1.ru.md).
