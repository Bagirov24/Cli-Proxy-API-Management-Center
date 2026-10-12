# Stage 2G.4d.5a — Bounded Signed Local Publication Handoff

**IMPLEMENTED / VERIFIED only in isolated synthetic transport and disposable
PostgreSQL16. Not production HTTP revocation or remote client receipt.**
Code SHA: `02f5db4dddeabddf099ae9d98d49c13421d759a8`.
Evidence: [Main CI #38290101997](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38290101997)
(1,802 unit tests PASS, 0 fail; ESLint, tsc, default-off Vite 3,305.72 kB),
[PostgreSQL #38290101971](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38290101971)
(real non-superuser signed lease and concurrent revocation),
[Demo #38290101951](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38290101951),
[Browser #38290101996](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38290101996):
**4/4 SUCCESS** on the exact code SHA.

## Server-owned callback contract

`withSignedScopedPublicationBarrier` reuses the SAME
`executeSignedScopedRead` HMAC/txid transaction executor as metadata
and signed revision reads, not a separate unsigned SQL implementation.
It takes a server-held `AuthorizedReadScope` and branded
`ServerAuthorizationRevision` captured from the trusted revision
reader. Public requests, JWT claims, client actor IDs or HTTP headers
cannot be used to mint that baseline.

Within one reserved, bounded signed `READ COMMITTED` transaction:

1. Verify the transaction-local signed scope and exact current PostgreSQL
   tenant/actor/role/collection using the existing database read gate.
2. Acquire migration-007's `FOR SHARE` lock on the private tenant epoch
   via fixed, parameterized `acquire_authorized_read_barrier`.
3. Compare locked epoch against the **pre-metadata** server revision
   baseline, then verify the signed DB epoch+earliest grant expiry
   (migration 006). A mismatch => generic 404 and confirmed ROLLBACK,
   never invoke the publication callback.
4. `handoff.prepare(signal)` may asynchronously stage **private local
   bytes** under a short backend timeout (default 2 seconds), but MUST
   NOT send data or schedule external network I/O. The executor
   prevents late completion after abort from invoking the handoff.
5. Recheck the exact PostgreSQL read gate and earliest expiry against
   the current server clock. Only on success call the returned
   **synchronous, non-throwing, atomic local `commit()`** while still
   holding the tenant epoch lock.
6. COMMIT the PostgreSQL transaction and release the reservation.
   Cooperating revocation writers cannot COMMIT before this local handoff.
   Ambiguous driver, timeout/cancel or cleanup states quarantine the
   entire disposable SQL pool before discarding the connection.

The function returns no metadata, tenant or revision token. The signed
publication SQL is explicitly allowlisted in the disposable Bun.SQL E2E
driver; no new HTTP listener or public service is introduced.

## Adversarial acceptance

Synthetic tests in `tests/saasScopedSqlBoundary.test.ts` cover:
fixed SQL params, double DB gate, private prepare-before-handoff order,
replayed/changed epoch, null SQL denial, malformed lock/expiry state,
changed grant deadline, role/cross-tenant spoof, cancellation while
prepare is pending, a never-resolving prepare that ignores AbortSignal,
DB denial after staging, and invalid handoff values.

The real `verify-trusted-pg-e2e.mjs` additionally obtains an epoch from
a non-superuser signed PostgreSQL revision lookup, passes a sanitized
North projects response through the local handoff, launches a separate
privileged fixture revocation writer after the FOR SHARE lock, verifies
the writer waits on that lock, then verifies the handoff occurs first.
After writer COMMIT, reuse of the old revision is a safe 404 without
`prepare`, while Orbit remains independently authorized.

## Deliberate limitations and release blockers

This is a **separate internal publication primitive**, not yet wired
directly to the high-level `createTrustedSqlReadBoundary` as an atomic
request-to-transport flow. The E2E obtains sanitized output from the
existing trusted reader, but the internal scope is still a synthetic
fixture; identity/session storage and audit are not serialized by the
publication lock.

The short timeout cannot preempt synchronous CPU work in a supplied
`commit()`. If that callback sends bytes and then throws, or if its
external transport commits asynchronously, bytes cannot be retracted.
If a PostgreSQL COMMIT fails after a successful local handoff, the
handoff may already have happened. This design **does not** implement
durable, transactional or exactly-once publish semantics.

For future HTTP integration a separately reviewed transport adapter
must define the synchronous linearization event (e.g., durable,
bounded server-side buffer acceptance), backpressure and crash
semantics; whether in-flight older responses may arrive after a
revocation acknowledgement must be explicit. A DB COMMIT/lock cannot
prove end-user receipt. Current tests intentionally don't open a
network port or touch production routing.

Readiness remains blocked on audited trusted-scope integration,
server-side session revocation, multi-process SQL driver discard
proof, operational bounded leases, secrets/vault, data-plane egress
enforcement and explicit release approval. See
[PRODUCTION_READINESS_GATES_V1.ru.md](PRODUCTION_READINESS_GATES_V1.ru.md).
