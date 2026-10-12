# Stage 2G.4d.4b — clock-only grant expiry: signed next-deadline attestation

**Staging-only pilot; IMPLEMENTED code, CI verification pending.**
Requires disposable migrations 001..006, pinned synthetic keys and non-superuser SQL.
No production OIDC, Core/CPA, Gateway, Railway, HTTP or real credentials.

## Why time is not a transactional writer

Even with complete PostgreSQL row triggers, when `expires_at` is reached
without UPDATE, no epoch changes. Two identical metadata page snapshots and
two identical revision values can therefore mask a grant expiration.

## New signed state contract

Migration `006_time_aware_revision_pilot.sql` adds
`saas_rls.authorized_revision_state(actor, tenant, role, collection)`.
It validates a server-issued HMAC/transaction ID, active tenant, exact
DB actor membership and collection capability (same as revision 004).
The result is one canonical decimal BIGINT revision plus a
`not_after_ms`: the earliest future `expires_at` of an active grant
for the verified tenant, or NULL when none exist. It is floor-rounded
to milliseconds (fail earlier, never late due to rounding).

It is deliberately conservative: one expiring unrelated grant may
cause an entire metadata request to fail, rather than risk returning
information that lost permission between snapshots. The query never
returns resource/grant IDs or timestamps to an external caller.
Private grant and epoch tables remain invisible to `saas_rls_reader`.

The `readSignedScopedAuthorizationRevision` uses fixed parameterized
SQL, signed transaction, before/after DB gate, bounded deadlines and
pool quarantine. Its returned internal object is
`{revision, notAfterMs}` validated as canonical strings. The
high-level trusted boundary compares both fields and additionally
checks the deadline against the trusted server clock immediately
before metadata leaves the function; passed deadline gives generic
404 and tenantless Deny audit. Malformed or absent fields result in
generic 503 and SQL pool quarantine. An ordinary synthetic string
revision source is retained only for isolated prior tests.

## Acceptance cases

- SQL test: signed/unsigned/foreign/role scope and private table ACLs;
  future deadline exists; `pg_sleep` crosses expiration without
  another write; deadline disappears while BIGINT epoch stays equal;
  ROLLBACK restores the grant state.
- Bun unit tests: malformed timestamps/missing fields/overflow,
  frozen server scope, no response leak, deadline equality and expired
  deadlines denied before metadata.
- End-to-end: real PostgreSQL grant is given a short-lived expiry,
  trusted read's initial epoch captures it, and the fixture waits after
  the second metadata COMMIT without ANY authorization SQL write.
  Real SQL epoch remains unchanged; final signed deadline differs and
  existing project rows are denied with generic 404.

## Remaining limitations

Not a globally consistent authorization snapshot or revocation barrier.
Clock skew may produce conservative false denials; no time sync/clock
attestation is built. The earliest future expiration deliberately
over-invalidates. An expiry after the final check but before actual
HTTP delivery still races. No multi-instance session consistency,
physical Bun.SQL connection discard proof, production token authority,
durable audit or public SaaS interface. A formal read/revocation
linearization protocol is still SPEC/PROPOSED.
