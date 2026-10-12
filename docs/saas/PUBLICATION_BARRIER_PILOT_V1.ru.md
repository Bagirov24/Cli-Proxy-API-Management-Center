# Stage 2G.4d.4c — кооперативный publication barrier: PostgreSQL proof

**Staging-only IMPLEMENTED; VERIFIED only on exact GitHub Actions SHA.**
This is a database *ordering experiment*, NOT a production HTTP
revocation-delivery guarantee.

## Proposed consistency semantics

A future SaaS read may be accepted only under a transaction that locks the
private authorization revision row `FOR SHARE`, validates its signed
actor/tenant/role/collection and holds the lock until a precisely defined
server-side publication event. All cooperating revocation writers update
that same revision row transactionally, and therefore cannot COMMIT
while a pre-existing reader holds its shared row lock.

The migration `007_read_publication_barrier_pilot.sql` exposes a
`SECURITY DEFINER` function `acquire_authorized_read_barrier` to
`saas_rls_reader` only, after signed HMAC/txid and current
membership/collection checks. It checks `READ COMMITTED`,
locks its verified tenant epoch row using `FOR SHARE`, then repeats
the DB permission gate after acquiring the lock. Invalid/foreign/paused
scope returns NULL; SQL failure fails closed. No raw grants/epoch table
privileges are granted to reader.

The adversarial SQL acceptance denies forged scope, wrong role,
cross-tenant context, suspended tenant and auditor forbidden collection.

`verify-publication-barrier.sh` opens an actual signed reader session
and intentionally holds its transaction across a synthetic publication
delay. A separate writer updates North's Pool grant and is REQUIRED to
wait on the revision-row lock. The third observer sees the old committed
status and revision until the reader commits. After the reader COMMIT,
the writer COMMIT becomes visible with exactly one version increment.
Orbit is unaffected; restoration is also versioned.

## Why this does NOT close the HTTP gap yet

The existing trusted TypeScript read path is NOT wired to hold such a
transaction across a response-send callback. It still finishes four
signed transactions and returns data after its final check; a revoke
can race afterwards. A proof that an HTTP handler has handed bytes
to an OS socket is also not proof of when a remote client receives
those bytes. Protocol owners must define whether revocation completion
means no **newly authorized reads**, all in-flight publication callbacks
drained or remote receipt (the latter cannot be guaranteed by DB locks).

A production design must bind request cancellation, server crashes,
transport backpressure, lock timeouts, deadlocks, pool exhaustion and
idempotent retry semantics to release/ROLLBACK. It must not leave a
long-running transaction open for an arbitrary slow client. An explicit
separate bounded publication lease or transactional outbox may be
needed. No unbounded locks or live network transports are implemented.

No production OIDC/session store, HTTP handlers, Gateway/Core changes,
secret storage, egress, Railway deploy or merge is authorized.

## Additional adversarial cancellation check

A second independent signed reader is held at the same epoch barrier
while another writer tries to grant/revoke an unrelated North Egress.
The CI fixture deliberately terminates the **disposable PostgreSQL
backend** holding the read transaction using `pg_terminate_backend`.
It asserts that the reader is rolled back, the pending writer can
commit and the epoch advances exactly once; fixture restoration is
separately versioned. This is a database crash/disconnect property,
NOT a proof that cancellation from a real HTTP client reliably closes
an individual Bun.SQL physical connection.
