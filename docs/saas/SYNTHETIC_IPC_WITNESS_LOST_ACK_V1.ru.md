# Stage 2G.4d.7n — Unix-socket signed witness and lost-receipt recovery (CI only)

**Status: staging-only proof. Production readiness remains OPEN.**

This stage is not an independently operated witness and cannot be used
for real producer issuance, archival or network delivery. It extends
earlier disposable PostgreSQL 16 stages 7j–7m by running the detached
signer as a **long-lived second Node process** reachable only through
a private local Unix-domain socket. The application/test driver still
runs on the SAME GitHub Actions runner, with the SAME OS identity and
administrator. There is no separate host, organization, WORM device,
network consensus, trusted timestamp or actual external service.

## Implementation

The scripts are:
- `scripts/saas-staging/archive-witness-ipc-server.mjs`: offline
  process which owns an ephemeral Ed25519 private signing key, verifies
  signed predecessors and serializes one synthetic append at a time;
- `scripts/saas-staging/verify-archive-witness-ipc.mjs`: disposable
  real PostgreSQL 16 integration and attack fixtures;
- the additional `saas-staging-rls-ci.yml` acceptance step.

The daemon receives a stripped environment with **no PG variables,
Railway, DATABASE_URL, bearer, signing scope, payload or production
credentials**. The Unix-domain socket and private witness storage
are under one private temporary directory, removed at test end.
The daemon does NOT import PostgreSQL drivers, connect to any SQL
service, host an HTTP endpoint or produce delivery/outbox messages.

The client sends only the canonical, domain-separated SHA-256
commitment arrays from existing immutable 015/016 synthetic UUIDs,
a random 128-bit request ID, and the expected checkpoint head.
Raw UUIDs, tenant IDs, actors, collection or client payloads never
enter the IPC messages or signed response.

The witness signs each canonical `saas-synthetic-uuid-witness-v1`
Ed25519 checkpoint with protocol/audience, sequence, hash link to
the predecessor, projection digest and complete hashed commitments.
Additionally it signs a detached **IPC receipt** binding request ID,
checkpoint sequence and signed checkpoint digest. A client must pin
and independently verify the public Ed25519 key and signatures;
the response has **no** GC permission, issuer authority or external
recipient acknowledgement.

## Durable publication and idempotent ACK replay within the runner

The daemon stores each new request, expected predecessor, signed
checkpoint and signed receipt as an exclusive, fsynced file.
After that it publishes the new `head.json` via fsynced temporary
write and atomic rename. There is **no transaction atomicity with
PostgreSQL COMMIT**. The first request after startup may create a
genesis checkpoint from the supplied synthetic projection. Every
following new checkpoint must be the direct successor and add
**exactly one** committed UUID commitment while preserving all old
issued/producer identities.

If the IPC process is killed after fsync and head publication but
**before** the response, the caller gets a transport failure, not
an accepted result. A fresh daemon process re-opens its complete
signed history and verifies every predecessor, receipt signature,
request ID and latest pinned head. Submitting the **same** request
ID, predecessor and projection returns the **identical original**
signed checkpoint and receipt; it does not create another UUID or
append another head. Reusing the ID with altered content or creating
a different ID against a stale head is denied. A concurrent attempt
with the same expected head cannot produce two signed successors:
the single Node process serializes them.

A crash after fsyncing a new checkpoint file but BEFORE publishing
the new head leaves an orphaned sequence. The next daemon startup
fails closed, including when a valid former head exists; no
automatic "repair", reset, replay, GC or operation deletion occurs.
A separate operator adjudication protocol is still SPEC.

A local socket disconnect, server pause or process termination
must fail closed. The client is never authorized to infer
"the issuer did not COMMIT" or initiate a new UUID from a missing
IPC reply.

## Physical PostgreSQL tests

The new E2E step:
1. Verifies that the disposable `saas_ephemeral_test` database
   reports `gc_permitted=false`. It records the existing local
   signed audit row count to ensure the witness creates no 009/013.
2. Starts the separated signer with no PG credentials, obtains and
   pins its public key, signs genesis and verifies the detached
   checkpoint and receipt from the client.
3. Commits a new **synthetic** UUID INSERT in actual PostgreSQL.
   Its later projection is refused against the still-old signer
   head (**unsigned COMMIT → DENY**).
4. Stops the signer so that the Unix socket is absent; the test
   observes failure. A fresh signer process reopens the same key
   and history, but still rejects the uncheckpointed PG UUID.
5. Forces a process crash AFTER durable checkpoint+head commit
   but BEFORE the response. The caller has an unknown result.
   A fresh signer process replays precisely the same signed
   request ID/receipt once. A changed replay, same UUID with
   new request ID against stale head and a zero-delta append
   are all denied.
6. Commits a second UUID. Two independent IPC requests race with
   the same signed old head: exactly one signed successor is
   accepted, the other denied; replay of the winning ID is
   stable and the head does not increment twice.
7. Commits a third UUID. On a CLONE of the witness state,
   SIGKILL after checkpoint fsync but before head update leaves
   an orphan. Restart of this clone refuses to serve clients.
   The original intact witness can still publish and verify
   the third UUID normally.
8. Demonstrates the critical **negative limit**: an old clone of
   the witness state can still serve a historical signed head
   using the same Ed25519 key. If a caller's pinned latest head
   ALSO rolls back, the two together may look valid. Therefore
   off-host trusted anti-rollback is not implemented.
9. Tries to start a witness with PGHOST present; it refuses to
   run. Neither raw UUID nor tenant/actor is in signed responses.
   The private retention view still returns GC=false and no
   synthetic 009 audit/013 event was generated by this step.

All temporary signed files and keys are removed by the runner.
None is uploaded as a CI artifact, used for a real customer
or written to a production database.

## What the step does NOT prove

The daemon receives an UNTRUSTED canonical projection from
a caller; it does **not** independently attest the real
PostgreSQL snapshot or signed actor/grant identity. A malicious
client able to supply a plausible projection can ask the
daemon to sign an uncommitted identity. The current synthetic
driver does not model an authenticated independent projector
or trusted PG COMMIT certificate.

A signed append and a PostgreSQL COMMIT still occur in
separate failure domains with **no atomic/fenced settlement**.
The receipt acknowledges a **local checkpoint signature**, not
database commit, user authorization, delivery or remote ACK.
No production issuer uses this IPC daemon, no exposed HTTP
or TLS networking exists and no UUID reuse prevention is
installed on restored producer databases.

The disk files are **only local to a single ephemeral CI runner**.
They are writable by its owner and can be replaced together
with the public key/trust pin. The daemon owns a private key
in the same OS account for test convenience: it is not
hardware-backed or separately administratively controlled.
A clone of all local state can roll back to an older
self-consistent snapshot. fsync does not make that external
durable, tamper-evident or WORM.

True multi-host service isolation, durable off-host latest
trusted head, key custody/rotation, fork/partition consensus,
read authenticated identity binding, real WAL/PITR failover,
fenced PostgreSQL COMMIT→witness settlement, issuer-side
non-reuse checks and operational unknown-outcome recovery
are still **SPEC / PROPOSED**. No tombstone archive, deletion,
TRUNCATE, GC or lifetime-cap reset is authorized.

**Guardrails:** No migration 019, Railway/production, real
credentials, network delivery, Core/Gateway/CPA/OAuth, `/data`,
`management.html`, force push or merge.


## Verified code evidence

**CODE VERIFIED at `2c5dc866adf7e028b4a7f5510e953e4ccc773714`**
with **4/4 GitHub Actions SUCCESS**:
[Main CI #38376602616](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38376602616),
[ephemeral PG16 #38376602658](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38376602658),
[Demo #38376602675](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38376602675),
[Chromium #38376602646](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38376602646).

The physical PG16 job reports separate-process signed genesis, unsigned
PG COMMIT denial, socket outage + restart, lost IPC ACK returning the
**same signed receipt**, serialized competing writers, orphan checkpoint
startup DENY, PG-env credential guard, no audit/intent/GC, and an explicit
counterexample that local trust state plus lost pin can be rolled back.
This is **NOT** an independently durable external witness. The final
documentation SHA must pass its own 4/4 CI before marking final VERIFIED.
