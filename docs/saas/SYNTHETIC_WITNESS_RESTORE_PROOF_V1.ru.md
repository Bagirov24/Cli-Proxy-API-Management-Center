# Stage 2G.4d.7k — fsynced witness head + real PostgreSQL16 restore (CI proof only)

**Status:** IMPLEMENTED as an isolated staging-only CI adversarial acceptance.
**This is NOT independent durable external attestation and NEVER authorizes GC.**

## Purpose and safety boundary

Stage 7j established a detached, canonical, Ed25519-signed chain of
SHA-256 commitments over the UUIDs in the immutable synthetic
`synthetic_operation_issues` (016) and
`synthetic_producer_operations` (015) registries. It used a job-local
head in memory and only simulated a restored database through an older
projection. Stage 7k strengthens the **test evidence** in two ways:

1. A separate offline witness process persists its signed history and
   latest trusted head using file fsync and atomic rename, then
   **completely exits**. Fresh OS processes must reopen those files
   and check the entire chain against the separately stored pinned head.
2. The ephemeral PostgreSQL16 service is backed up using an actual
   full **`pg_dump` custom-format snapshot** both before and after a
   synthetic COMMIT. Each backup is restored using **`pg_restore`**
   to a different, newly created **scratch database on the same CI
   PostgreSQL instance**. No restoration overwrites the original
   `saas_ephemeral_test` database. The older copy is rejected against
   the newer signed trust head; the newer copy passes.

Both features are **strictly test-only**. No migration 019, live sender,
server API, application code, archive writer, GC, or capacity reset exists.

## Three distinct trust compartments

- **PostgreSQL projector** runs with the disposable GitHub Actions
  `postgres` test-only credentials. It reads only the operation UUID
  sets, creates domain-separated SHA-256 commitments in memory and
  queries the restored scratch databases. It never supplies PG access
  to the witness. Custom-format database backups remain only inside
  a private 0700 temporary directory and are deleted after CI.
  The full backup can include other *synthetic* SQL fixture data, so
  this is NOT an approved customer data export method.
- **Offline Ed25519 signing/verification child process** receives
  only canonical hashed commitments and checkpoint files. Its process
  environment explicitly lacks PGHOST, PGPORT, PGUSER, PGDATABASE,
  PGPASSWORD, Railway variables, SQL connection strings and client
  credentials. A private signing key is generated only for one CI
  test and is erased after it.
- **Witness state and pinned anchor** are two separate private file
  locations, outside PostgreSQL backup/restore, on the **same GitHub
  runner**. The state directory holds numbered signed checkpoint
  files plus a `head.json`; the anchor file separately pins
  `sequence` and signed-envelope SHA-256 digest. Both are
  fsynced and published by atomic rename. Every verifier invocation
  reopens the files, checks exact schemas, all sequential signatures,
  monotonic coverage, and that state head equals the pinned anchor.

Neither witness state nor anchor are hosted outside the runner.
File fsync protects a local write ordering; it does **not**
provide independent physical durability, trusted external time,
cross-run persistence, or operator-independent custody.

## Stricter restored-database acceptance

`archive-witness-head-store.mjs` adds a *strict restoration gate*
on top of 7j's signature and older-ID coverage verification:
the new PostgreSQL projection must **equal the latest signed
projection exactly**, including both commitment arrays and counts.

- Missing previously signed UUIDs => **DENY** (old backup restore).
- Extra UUID committed after the latest checkpoint but not signed
  yet => **DENY** (unknown signing gap; cannot claim restored
  snapshot is sealed).
- Identical latest signed set, authenticated history, persisted
  latest head and separate matching anchor => PASS, but returns
  only `gcPermitted=false` and never a deletion credential.

The externally anchored head sequence guards against *replacing
only* the signed history with an earlier one. Reverting **both**
the witness directory and the separately pinned anchor together
can still bypass this same-runner proof: an independently durable
monotonic trust root is not present. This is an explicit production
blocker, not an exception that can be waived by CI success.

## Crash and tamper failure modes

The CI-only publisher writes a new signed history entry through
exclusive open + fsync, then writes a temporary head, fsyncs it,
renames it atomically and fsyncs its containing directory. It
updates the separate pinned anchor in the same manner.
These writes are **NOT atomic as a group** and are NOT atomic
with the originating PostgreSQL COMMIT. A mid-publication crash
can leave an extra history entry, a pending temporary file or
a publisher lock. Verification must fail closed and require
explicit operator adjudication; the code deliberately has no
automated tombstone repair/GC.

Tests SIGKILL an offline publisher after the staged head's fsync
but **before rename**, while operating on a clone of valid
witness-state files. On restart, the orphan and lock prevent
verification; an intact primary job-local trusted state still
passes. A malformed/torn pinned anchor also fails. No operation
UUID table is mutated to simulate any of these attacks.

## Real PostgreSQL backup/restore acceptance

`verify-archive-witness-restoration.mjs` runs **after** the
previous 7j tests on the same disposable service:

1. Project existing issued/producer sets and create the first
   pinned signed witness head using a new offline OS process.
2. Create an actual full custom-format PostgreSQL `pg_dump`
   of the untouched source into a private test temp directory.
3. COMMIT exactly one new **synthetic** UUID issue fixture in
   source PostgreSQL, without deleting/updating any earlier
   UUID or creating a delivery intent.
4. **DENY** source recovery under the old checkpoint because
   there is now an uncheckpointed committed UUID.
5. Sign checkpoint 2 with an exact predecessor link, publish
   new witness head and separate anchor, and verify the new
   source projection from a fresh child process.
6. Create a second full `pg_dump` of the updated source.
7. Restore the old dump into
   `saas_ephemeral_witness_old_7k` and the new dump into
   `saas_ephemeral_witness_fresh_7k`. These names are fixed
   and must NOT already exist; creation refuses to overwrite
   a database. Each `pg_restore` runs with
   `--exit-on-error --no-owner --no-acl`.
8. Project from both real restored databases. The older
   backup has exactly the original UUID set and must **DENY**
   against the latest pinned head. The fresh backup has
   exactly the newly signed set and must PASS.
9. Clone a valid witness state, SIGKILL a publisher between
   fsync and head rename, and verify the orphaned state
   fails closed on restart. Restore of a stale trust-state
   clone against the current independently stored job-local
   anchor and verification with a torn anchor also DENY.
10. Confirm `saas_rls_private.synthetic_operation_retention_health`
    still reports `gc_permitted=false` and that source
    UUIDs remain untouched. Drop **only** the two newly
    created ephemeral scratch databases and delete the
    local private test directory after verification.

This is a **real logical PostgreSQL full dump/restore**, not
PostgreSQL physical PITR, WAL replay, replica promotion, service
failover, cross-node recovery or independent storage failure.
It does not prove crash-consistent atomicity between PostgreSQL
commit and witness publication. The two scratch databases use
the same disposable PG16 service and roles, not separate nodes.

## Still SPEC / PROPOSED — production gate OPEN

- An independently administered, non-ephemeral append-only
  witness and **externally rollback-resistant** latest head
  with audited key custody, rotation and revocation.
- An authenticated issuance-time non-reuse query against that
  durable witness on **every** producer path, including after
  PITR, database restart, partition and failover.
- A cross-system commit/fencing and settlement protocol that
  can prove no UUID was committed but missed by a checkpoint.
- True backups/physical PITR, WAL/replica lag, corruption,
  multi-host failure, disaster restoration and adversarial
  host/DB-owner compromise testing.
- Verified privacy/legal retention, durable external archive
  availability and separately approved safe deletion/capacity
  reclaim. No GC algorithm or archive deletion is built.
- Production HTTP, global quotas, real payload, external ACK,
  dispatch-time revocation, Vault/OIDC and security release
  reviews remain OPEN.

**Invariant:** `gcPermitted=false`. Stage 7k is a fail-closed
disposable CI acceptance, NOT a production non-reuse service.

No merge, force-push, Core/Gateway/CPA/OAuth modifications,
Railway, production credentials/traffic, `/data`,
`management.html`, public SaaS endpoints or real delivery.

**CODE VERIFIED on `9af3b8d5b29ebceb6a433468c650f01be913a148`:** [Main CI #38367994239](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994239), [ephemeral PG16 #38367994247](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994247), [Demo #38367994191](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994191), [Chromium #38367994196](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994196) — **4/4 SUCCESS**. The final documentation SHA requires independent CI; GC and production remain forbidden.
