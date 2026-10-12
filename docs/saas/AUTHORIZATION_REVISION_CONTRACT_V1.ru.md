# Stage 2G.4d — Server-Owned Authorization Revision Contract v1

**Status: IMPLEMENTED as an opt-in isolated TypeScript guard; SYNTHETIC
acceptance only until the exact new SHA has passed CI.** This is NOT a
production revocation protocol or a linearizable authorization decision.

## Why the contract exists

Stage 2G.4c compares two signed PostgreSQL transactions, but matching
LIMITed metadata results cannot prove the authorization state was unchanged.
For example a grant may be removed from a resource outside the returned page.
There is also an unavoidable interval between the final read and delivery.

The opt-in `ServerAuthorizationRevisionSource` separates authorization
state versioning from metadata projection, SQL driver and UI. It is selected
only by server-held dependencies inside `createTrustedSqlReadBoundary`.
The request/JWT has **no revision field with authorization semantics**.

## Implemented server read path

1. Validate pinned synthetic access JWT → issuer/subject → actor → membership/RBAC.
2. Capture a **server-owned canonical decimal BIGINT revision** for verified
   `actorId + tenantId`. Null, malformed, overflow, failure and cancellation
   fail closed as generic 503 before SQL.
3. Keep both signed PG metadata reads from 2G.4c unchanged.
4. Reverify JWT/actor mapping and membership/RBAC after the second COMMIT.
5. When opt-in is configured, compare a fresh server-owned revision to the
   captured baseline. A mismatch gives generic 404 + tenantless
   `authorization-changed` audit, discarding rows. A failure to read the
   revision is generic 503 + tenantless audit. No revision value is sent to
   callers or audit. No extra metadata SELECT is introduced.

Without the optional `revisions` dependency the existing 2G.4c path
remains unchanged; **that omission is NOT revision enforcement**.
The current synthetic map used by adversarial tests is not authoritative
or suitable for multi-instance production.

## Required future authoritative writer/storage protocol (SPEC)

- One monotonically increasing **tenant-scoped** revision covering tenant
  status, active membership, role and Pool/Account/Egress grants visible to
  that tenant. A global grant shared with multiple tenants MUST invalidate
  every affected tenant or use a provably equivalent dependency epoch.
- The revision and authorization mutation MUST commit atomically in the same
  authoritative database transaction. Avoid partial invalidations and
  non-transactional in-memory pub/sub as the sole source of truth.
- A PostgreSQL-backed read provider must return the actual current revision
  from the trusted database with bounded cancellation and no stale cache.
  Multi-instance readers and writers MUST use the same authoritative state.
- No external caller may choose or overwrite revision, actor or tenant.
  Revisions themselves are not user-visible, cache keys or bearer proofs.
- Revision wrapping, deletion/recreation, fixture reset, out-of-order
  updates and any unavailability MUST be handled fail-closed. The pilot
  decimal range 0..9223372036854775807 is a transport constraint, not an
  implemented allocator or guarantee of monotonicity.
- Pool grants do not imply Account/Egress grants. RLS and explicit DB gate
  still protect each metadata SELECT independently.

No migration `004` is added yet: there is no authoritative SaaS write
pipeline to attach atomic invalidation to. Creating an unused table would
pretend to provide a consistency guarantee it does not enforce.

## Linearization and concurrency (not implemented)

**No linearization point has yet been proven.** A revocation that commits
after the final revision query can still precede HTTP delivery. Additional
retries do not eliminate this gap.

Next investigate a database-backed read/writer protocol with an explicit
order: e.g. a transactionally pinned decision/lease or serialization barrier
around the point at which a read is considered authorized; define how an
already-authorized read may finish after revoke and what completion of
revocation means. Test concurrent readers/writers across separate processes
and backend instances, including cancel, crashes and deadlock prevention.
Do not describe the current double read plus revision query as atomic.

## Security acceptance matrix

| Scenario | Current verification |
| --- | --- |
| Stable North scope, cross-tenant IDOR, forged claims | SYNTHETIC unit + previous PG16 RLS regression for base behavior |
| Revision changes during first SQL or after first COMMIT | SYNTHETIC adversarial unit |
| Revision changes immediately before final Allow | SYNTHETIC actor-lookup hook |
| Forged client revision, stale revision replay | SYNTHETIC unit |
| Missing/invalid/overflow revision, store exception, abort | SYNTHETIC fail-closed unit |
| Safe SQL pool reuse following revision-only Deny | SYNTHETIC unit |
| Concurrent PG writer/read with atomic revision bump | SPEC — not tested |
| Real PG tenant/membership/grant revision triggers | SPEC — no migration |
| Cross-instance linearization after final check | PROPOSED — not proven |

No new HTTP endpoint, real OIDC, Core/Gateway, CPA settings, live keys,
proxy/VPN, management.html publication or production DB access.

See [POST_COMMIT_REVALIDATION_V1.ru.md](POST_COMMIT_REVALIDATION_V1.ru.md),
[ROADMAP.ru.md](ROADMAP.ru.md), [DECISIONS.ru.md](DECISIONS.ru.md).

## Next implemented increment: ephemeral PG writer/storage proof (2G.4d.2)

[TRANSACTIONAL_AUTHORIZATION_REVISIONS_V1.ru.md](TRANSACTIONAL_AUTHORIZATION_REVISIONS_V1.ru.md)
adds a guarded private PostgreSQL epoch table, transactional triggers,
signed revision read attestation and concurrent SQL acceptance. This is
**not yet wired** to the optional TypeScript `revisions` port; therefore
the old synthetic limitations and the response/revocation race remain.

## Stage 2G.4d.3 — trusted signed SQL reader

The server-held revision scope now contains actor, tenant, verified role,
correlation ID and exact collection. The optional
`createSignedPgAuthorizationRevisionSource` reads migration-004
`authorized_revision` through the same signed PG transaction executor.
This replaces synthetic-only revision reads **inside ephemeral PG16 E2E**
but does not create a production backend, OIDC or atomic response barrier.
See [SIGNED_REVISION_READER_V1.ru.md](SIGNED_REVISION_READER_V1.ru.md).
