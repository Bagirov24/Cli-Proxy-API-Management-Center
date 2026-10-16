# Stage 2G.4d.7j — Detached synthetic UUID archive witness (proof only)

**Status:** IMPLEMENTED as a CI-only, non-destructive experiment.
**Do not infer production archive readiness or permission for GC.**

The previous 015–018 SQL migrations retain every synthetic UUID and
strictly prohibit UPDATE, DELETE and TRUNCATE of their private immutable
operation registries. This stage deliberately adds **no migration 019**,
no public endpoint and no database archiver.

## Why this is a witness candidate, not a safe archive

A database-local count, hash or snapshot cannot prevent a restored
older database from reusing an identifier previously recorded in a
later snapshot. The earlier D-066 decision therefore keeps
`gc_permitted=false` permanently.

The new script
`scripts/saas-staging/archive-witness-protocol.mjs` defines a
canonical and strictly parsed detached checkpoint envelope, while
`verify-archive-witness.mjs` tests it against an isolated PostgreSQL16
job. A separate **offline Ed25519 witness child process** receives
only hashes of the UUID records. Its environment contains no PGHOST,
PGUSER, PGDATABASE, PGPASSWORD, bearer, scope signer or Railway values.
The signer never executes PostgreSQL, client HTTP or any network request.

Only one job-local ephemeral signing key is used. The public key and
latest accepted checkpoint digest are pinned **outside PostgreSQL
for the duration of this single CI process**. They are deleted after
the test. The sidecar is neither durable nor independently operated,
and does NOT attest that a signing service, hardware root, safe remote
storage or external trusted operator exists.

## Canonical privacy-minimized manifest candidate

The read-only projection reads operation UUIDs from both registries
on an independent PostgreSQL connection:
- `synthetic_operation_issues` — `issued` commitments
- `synthetic_producer_operations` — `producer` commitments

Each individual UUIDv4 is transformed to a SHA-256 commitment over a
domain-separated tuple (`protocol`, `kind`, `UUID`). The witness
receives ONLY sorted, unique lower-case 64-hex commitments and counts.
**No raw UUID, actor, tenant, event ID, payload, JWT or transport
metadata is present in the signed file.** Commitments are linkable
across snapshots; metadata minimization is not a privacy audit or
irreversibility guarantee if UUIDs are disclosed elsewhere.

The signed payload is a strictly canonical JSON object with:
`protocol`, fixed CI `audience`, `sequence`, `previous`
checkpoint digest, `projectionRoot` and the complete commitments.
The Ed25519 signature covers the canonical payload and protocol
domain separator. The attestation records the algorithm and
fingerprint of the offline public key.

Verification independently:
1. Parses and validates the exact schema and canonical array ordering,
   counts, projection root, algorithm and pinned key fingerprint;
2. Verifies detached Ed25519 signature and predecessor checkpoint
   signature and exact hash link;
3. Requires strictly increasing sequence and that every earlier
   commitment still exists in the later signed checkpoint;
4. Compares the latest signed checkpoint against a fresh independent
   PostgreSQL projection, rejecting a missing issued/producer UUID;
5. Requires the **trusted, out-of-database head digest** for the same
   sequence, to reject a valid but stale or competing signed checkpoint;
6. Returns `gcPermitted=false` unconditionally.

A newly committed but not yet signed UUID may be present as a
superset in PostgreSQL. That does **not** make the old witness an
authorization to archive, and it must be checkpointed under a fresh
signed successor before it can be considered covered by the candidate
evidence chain.

## Fail-closed adversarial CI acceptance

All tests run on disposable PostgreSQL 16. No production secrets or
data are fetched or transmitted. The new GitHub Actions step:

- Generates an ephemeral offline Ed25519 keypair, signs checkpoint 1,
  and validates its signature and externally pinned head;
- Stages an INSERT in a real PostgreSQL transaction while another
  connection independently projects the pre-COMMIT rows; verifies
  the uncommitted UUID is NOT included in checkpoint 1;
- Commits the staged INSERT, observes exactly one new commitment,
  signs checkpoint 2 with a chain link to checkpoint 1 and verifies;
- Kills a different PostgreSQL backend while it holds another
  uncommitted UUID INSERT; verifies the pending row was rolled back
  and checkpoint 2 still covers all committed rows;
- Tests a **simulated old-database restore** by supplying an earlier
  projection to the verifier (WITHOUT deleting anything from PostgreSQL);
  rejects the missing committed UUID;
- Rejects a valid old signed checkpoint against the newer pinned
  head, a missing predecessor, tampered signed projection, tampered
  observed projection, wrong public key, separately signed competing
  checkpoint, malformed/torn witness file, and incorrect counts;
- Checks the witness artifact contains no plain UUID, tenant,
  actor, event ID, SQL payload or access token;
- Confirms `synthetic_operation_retention_health` still reports
  `gc_permitted=false` and no deletion/archival routine was invoked.

The signer and verifier run as separate OS processes from the
projector; the signer/verifier environment is stripped down to
generic CI variables. This is a **single ephemeral runner test**,
NOT a cryptographically separate legal entity, network service or
production-grade independent verifier.

## Explicit non-goals and unsolved production conditions

The test cannot establish independent durable trusted-head
persistence across separate CI runners, true cross-region failover,
network partitions, hostile PostgreSQL owners, key compromise,
timestamp trust, uninterrupted history, hardware-backed identity,
transaction-atomic external witness publication, multi-database
consensus, append-only external storage, recovery and key rotation,
safe capacity reclaim, end-user erasure policy, or non-reuse against
arbitrary unaudited writers.

The supplied old-DB restore is an **offline projection simulation**.
A real PITR/backup restore, crash/restart of all signing components,
or live writer switchover is NOT tested. A signed hash chain alone
does not make the old private UUID table safe to delete or reuse.
The signing key and head are ephemeral and disappear when CI ends.
There is no archive destination, retrieval, data deletion, external
publication or client-visible witness.

**This stage never changes 009/012/013/014/015/016/017/018 migrations,
production RLS/CPA/Gateway/Core, public SaaS APIs, Railway, OAuth,
real payloads, sender/recipient authentication or remote ACK.**
The old pre-COMMIT local handoff issue is still a production blocker.

## Required next-stage approval gates (SPEC)

Before implementing any actual archive/GC, a future design needs:
- a non-ephemeral independently owned, authenticated, append-only
  witness and pinned latest head with tested key custody/rotation;
- canonical per-ID inclusion and *non-reuse* checks on every issuance,
  including after database restore, failover and network partition;
- an atomic producer/archive cutover ensuring no gap between database
  commit and external witness checkpoint;
- tamper-evident reconciliation of both issued and committed IDs,
  backed by backup restoration, replica lag and corruption tests;
- binding to tenant data retention, privacy, legal deletion and
  operational capacity exhaustion policies, plus security approval.

**Gate: SPEC / PROPOSED; `gcPermitted=false`.**
No archive/GC release authorization is implied by passing CI.

**CODE VERIFIED on `66019cd7602d256148562eafd304e9712a2d907b`:** [Main CI #38363925445](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925445), [ephemeral PostgreSQL16 #38363925442](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925442), [Demo #38363925450](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925450), [Chromium #38363925440](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925440) all SUCCESS. The final documentation SHA needs its own Actions; this does not authorize archive or GC.


## Follow-on 2G.4d.7k: actual logical restores, not external durability

Stage 7k adds a stricter, file-fsynced signed-head
publisher/verifier using a separate pinned anchor outside
PostgreSQL, still on the *same* disposable GitHub runner.
Full old and fresh PostgreSQL backups are restored to two
separate scratch databases with real `pg_restore` instead
of using only an old in-memory projection. A missing
later UUID DENIES an old restored database, whereas a
fresh restored database exactly matching checkpoint 2
passes. A COMMIT before head update, SIGKILL before rename
and torn/stale heads DENY.

No proof of atomic PG→external witness publication,
independent trusted-head survival, physical PITR or live
non-reuse guard is produced; the single-runner state
and signing keys disappear after CI. `gcPermitted=false`
and all 015–018 immutability remain unchanged.
[Detailed 7k test contract](SYNTHETIC_WITNESS_RESTORE_PROOF_V1.ru.md).

**CODE VERIFIED at `9af3b8d5b29ebceb6a433468c650f01be913a148`:** [Main CI #38367994239](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994239), [ephemeral PG16 #38367994247](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994247), [Demo #38367994191](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994191), [Chromium #38367994196](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994196) — **4/4 SUCCESS**. The final documentation HEAD must pass its own CI; no archive/GC/deployment authorization.


## Follow-on 2G.4d.7l — third local high-water journal

The offline Ed25519 checkpoint format of 7j remains unchanged.
7l adds two local fsynced witness copies, independently spawned
verification and a third local high-water sequence/digest journal.
Partial mirror publication and a real uncheckpointed PG COMMIT
fail closed. Two rolled-back witness copies are denied if the
separate journal remains newer.

**Critical negative case:** all three local copies rolled back
together with a stale supplied PG projection can still pass.
No independent durable off-host root, globally immutable log,
cross-system atomicity, hardware key, remote delivery or
new UUID reuse/GC is provided.
[7l details](SYNTHETIC_WITNESS_HIGHWATER_GAP_V1.ru.md).
