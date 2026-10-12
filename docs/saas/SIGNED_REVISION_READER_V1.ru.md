# Stage 2G.4d.3 — staging PostgreSQL revision adapter and final post-COMMIT check

**IMPLEMENTED: isolated server-only code and adversarial tests.**
**VERIFIED** is reserved for successful GitHub Actions on the actual commit SHA.

## Implementation

`signedPgAuthorizationRevision.ts` wires the server-authorized
`actorId/tenantId/role/correlationId + collection` to the same
`ScopedSqlPool` and `SignedTransactionIssuer` as the metadata reader.
The revision port now accepts **full server-owned scope** plus collection
rather than only actor+tenant. No role/collection from JWT, request headers
or UI can grant access. This is a feature-branch contract expansion, not a
production public API.

`signedSqlBoundary.ts` uses one shared signed transaction executor for
both metadata and revisions. Each revision lookup:

1. Reserves one non-superuser connection under the existing deadline and
   abort propagation, captures a new `txid_current()`, signs HMAC scope,
   sets only allowlisted transaction-local GUC and local RLS reader role.
2. Validates current active tenant, membership, **exact** role and collection
   with `SCOPED_READ_GATE_SQL`.
3. Calls exactly
   `SELECT saas_rls.authorized_revision($1::text, $2::text, $3::text, $4::text) AS revision`
   with parameterized trusted values. The migration-004 SECURITY DEFINER
   function checks the same signed scope again.
4. Validates one canonical positive PostgreSQL BIGINT revision string;
   NULL or explicit DB denial rolls back and becomes generic 404,
   malformed/overflow/missing rows and SQL errors produce generic 503 and
   quarantine. Requires the **second** DB gate before COMMIT.
5. A completed release permits reuse. Any ambiguous abort, timeout,
   release or driver state fails closed, synchronously quarantines the
   entire affected CI pool before bounded cleanup.

`trustedSqlReadBoundary` captures revision after pinned JWT/actor/RBAC,
performs both existing signed metadata transactions, revalidates
JWT/actor/membership and compares the final signed PostgreSQL revision.
Any difference returns tenantless 404 and discards metadata rows.
A missing/failed DB source is a tenantless 503. The read source is
explicitly opt-in; without it 2G.4c behavior remains unchanged.

## Acceptance

- Synthetic SQL boundary tests: fixed SQL, exact actor/tenant/role/
  collection, dual DB gates, NULL denial, malformed/duplicate/overflow
  attestation, driver failure/quarantine and abort.
- Existing trusted boundary tests: stable/mutated revisions, spoofed
  caller claims, role membership changes, storage failure and cancellation.
- Real disposable PG16 (migrations 001–004): same least-privilege
  `saas_ci_runner` Bun.SQL pool, signed revision source and metadata.
  Stable North/Orbit, caller revision spoofing, real tenant suspension,
  membership revocation and Account grant revoke **after the second
  metadata COMMIT** but before final revision lookup. Both project
  SELECTs stay unchanged for the grant case, yet stale rows are denied.
- Default-off build, Chromium QA and legacy PostgreSQL RLS regression.

## Unimplemented guarantees

There are four signed PostgreSQL transactions per revision-guarded read:
initial epoch, two metadata reads, final epoch. This is an expensive
staging security experiment, **not a production SLA** or a consistent
distributed snapshot. The revision can change after final COMMIT/audit
before any HTTP response: no proven linearization point.

Time-only grant expiry does not advance the epoch; changes to
links/routing/projects/applications are not fully epoch-versioned.
No production OIDC/session revocation, durable audit, multi-instance
cache-invalidation proof, safe physical discard for individual Bun.SQL
connections or public SaaS HTTP surface is implemented. The PG16
driver used here quarantines the **entire pool** on uncertainty and
must not be used for live credentials or production SaaS traffic.

See [TRANSACTIONAL_AUTHORIZATION_REVISIONS_V1.ru.md](TRANSACTIONAL_AUTHORIZATION_REVISIONS_V1.ru.md),
[AUTHORIZATION_REVISION_CONTRACT_V1.ru.md](AUTHORIZATION_REVISION_CONTRACT_V1.ru.md),
[ROADMAP.ru.md](ROADMAP.ru.md).
