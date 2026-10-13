# Stage 2G.4d.7l — Local high-water witness quorum and COMMIT-gap denial

**Scope:** ephemeral PostgreSQL16 / offline Node acceptance ONLY.
**Gate:** SPEC / NOT production. No signed checkpoint, mirrored head or
local high-water file permits physical UUID deletion, GC, archiving, or reuse.

## Threat model and deliberately bounded claim

Earlier stages proved signed SHA-256 UUID commitments (7j) and an exact
logical PostgreSQL restore check against a separately pinned head (7k).
The remaining problem is that **a witness head and its independent
job-local pinned anchor could both be rolled back to the same historical
state**. Another failure gap is COMMIT reaching PostgreSQL while an
off-database witness has not yet published a corresponding signature.

7l adds an *extra local simulated trust compartment*, not an external
organization or production independent storage. The new scripts
`archive-witness-highwater-gate.mjs` and
`verify-archive-witness-highwater.mjs` exercise:
- Two distinct fsynced witness-history directories, two separately
  pinned latest-head files and two **fresh offline verifier child
  processes**. The same ephemeral CI Ed25519 signing key signs both;
  these are two replicas, NOT separately governed signers.
- A third private `highwater.log` directory, separate from the
  histories and PostgreSQL. It records only canonical
  `sequence`, `digest`, `previous` SHA-256 links. This log is
  append-only **as a convention inside this CI helper**, not
  physically WORM, hardware-backed, immutable to its owner or
  independently escrowed across machines.
- Every verification requires both separately authenticated chains
  to agree, their two heads to match, the high-water tip to match both
  heads, and the actual supplied PostgreSQL UUID projection to match
  their latest signed snapshot **exactly**. Any replica loss, journal
  loss, malformed record or incomplete publication is a DENY.
- Publishing uses a temporary exclusive writer lock with file/dir
  fsync; crash after high-water append and before lock release leaves
  a pending marker and requires operator adjudication. It never
  automatically truncates/reconstructs an incomplete history.

There is NO claim of fault independence here: all three directories,
their key and subprocesses remain on the SAME ephemeral GitHub Actions
host. The tester can replace or reset the three folders; no
independent durable or monotonic external root exists.

## COMMIT-to-witness coverage gap

CI performs a true PostgreSQL COMMIT that writes a new synthetic
issued-operation UUID (via disposable postgres fixtures, never through
customer traffic). The supplied independent PostgreSQL projector
then sees the extra committed UUID. Because both witness replicas
and the high-water log still certify the earlier set, verification
returns DENY. This models a lost/delayed producer-witness publication;
the test does **NOT** roll back or delete the committed UUID.

The test then signs a second checkpoint. It publishes this checkpoint
to the FIRST witness replica but not the second: DENY. Publishing to
the second but NOT the high-water journal: DENY. Only after both
signed replica heads and a matching appended high-water record exist
does the strict verifier pass for the updated set.

A second real committed UUID tests the same unsigned gap again. A
third checkpoint is staged on cloned replica directories and
`SIGKILL` interrupts the high-water writer after file fsync but
before releasing the pending lock. Restarted verification against
that journal DENIES. Publication to the original intact replica
directories + high-water journal can then complete normally.

These are NOT distributed commits, consensus transactions or fencing
tokens. The replica updates and high-water append are NOT atomic
with each other or with PostgreSQL COMMIT. A network partition or
unreachable independent signer is not exercised. Production must
require actual issuer-side hold/fence or settlement to prevent an
unaudited commit from being accepted after failover.

## Adversarial acceptance including explicit negative result

The disposable PostgreSQL16 job checks:
1. Initial genesis checkpoint and high-water pin verified by two
   distinct offline processes with no PG/production credentials.
2. A newly committed UUID not present in the last signed snapshot is
   DENIED.
3. One signed replica updated but not the other is DENIED.
4. Both replicas updated but high-water journal still old is DENIED.
5. Both replicas and high-water tip agreeing at sequence 2 PASS.
6. Rewinding BOTH replica histories+anchors to the old signed
   sequence 1 while retaining the high-water seq 2 is DENIED.
7. Missing or malformed/torn high-water journal is DENIED.
8. **Explicit limitation proof:** rewinding BOTH replicas AND
   their independent-looking **third local journal together**
   recreates an internally consistent old view and can PASS with
   the correspondingly old supplied UUID projection. This is the
   unavoidable local failure exposed by the test, NOT a success
   criterion for anti-rollback protection.
9. Killing the journal writer after fsync leaves a pending lock and
   verification DENIES. A non-crashed signed head still needs an
   accurate fresh PostgreSQL projection.
10. Applying the next valid signed checkpoint to all replicas and
    the high-water journal restores strict verification of the
    new committed PostgreSQL UUID set.
11. Replaying a committed high-water sequence is denied. The
    immutable PostgreSQL source still returns
    `gc_permitted=false`; no UUIDs are removed.

The earlier actual full `pg_dump` and separate scratch
`pg_restore` checks from 7k remain enabled and unchanged.
The new proof uses the same disposable service with additional
synthetic UUIDs; it neither replays WAL nor manipulates production
databases or real ID mappings.

## Why this does NOT satisfy independent durable trust

The journal and two witness histories use the same local filesystem
and administrative trust domain. An attacker who can roll back the
whole runner, replace all files and provide a correspondingly old
database projection can make a locally self-consistent historical
checkpoint appear valid. A signed JSON chain can only establish
what the pinned trusted head already knows; it cannot independently
create that trusted latest-head knowledge.

The journal's append behavior and fsync are demonstrable local
write ordering, not external WORM. Furthermore, source projection
authenticity, identity of the actual active database, and the
completeness of POST-COMMIT capture are not attested by this helper.
It cannot itself guard production issuance, guarantee recovery after
key loss, re-create a deleted audit record or prevent operator-level
tampering. Even an exact restore PASS never returns GC authorization.

## Required SPEC gates for any later archive/release

- A separately administered, actually persistent, rollback-resistant
  high-water root (ideally geographically and physically independent)
  with key custody, rotation, revocation, audit and backup recovery.
- A transactional/fenced protocol for EVERY producer/issuer path
  that closes the gap between PostgreSQL COMMIT and external witness
  publication, plus explicit settlement of uncertain outcomes.
- Verification against an authenticated, authoritative database
  snapshot after physical PITR/WAL recovery, replica promotion and
  network partition, including withheld/unsigned committed UUIDs.
- Durable non-reuse checks before each real new UUID is accepted,
  true data retention and authorized privacy erasure semantics,
  multi-actor capacity policy, anti-abuse, and human security review.
- No deletion/GC/capacity recycling unless those conditions are
  separately proven and explicitly approved.

**Unchanged barriers:** pre-COMMIT local handoff, remote delivery/ACK
absence, production HTTP, identity/role/revocation policy, Railway,
Core/Gateway/CPA/OAuth, `/data`, `management.html` and live traffic.

**Decision:** Stage 7l is a reproducible fail-closed CI experiment,
with a deliberately recorded all-local-copies rollback counterexample.
`gcPermitted=false` remains mandatory. No SQL migration 019,
deployment, public SaaS endpoint, force push or merge.
