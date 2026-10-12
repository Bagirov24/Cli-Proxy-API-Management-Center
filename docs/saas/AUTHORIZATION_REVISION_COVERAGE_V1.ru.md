# Stage 2G.4d.4a — полное покрытие metadata-dependent tenant revision в PG16 (pilot)

**IMPLEMENTED staging-only SQL; VERIFIED only after Actions on exact SHA.**
No Railway, Core, Gateway, live AI traffic, SaaS HTTP or real credentials.

Prior 004 covered tenant status, membership role/status, independent
Pool/Account/Egress grants and resource catalog but **omitted metadata
projection and link writes**. A mismatch of row sets catches some changes,
but LIMIT or two matching snapshots can hide updates between them.

The guarded disposable migration `005_metadata_revision_coverage_pilot.sql`
adds transaction-local row triggers for `projects`, `applications`,
`key_bindings`, `routing_bindings` and `resource_links`. All writes
bump the same private tenant epoch from 004, in the **same transaction**
as the change. Updates that are byte-for-byte unchanged are ignored.
Tenant-scoped metadata changes advance both old and new tenant epochs
when tenant_id moves. Resource link changes bump owners and all current
explicit grantees of both OLD and NEW endpoints, even for shared
platform resources; over-invalidation is intentional to avoid leaks.

The migration requires database `saas_ephemeral_test`, explicit
`saas.staging_only=true`, `postgres` fixture login and the least
privileged owner role; it is replayable and leaves the reader without
private schema privileges. All queries use fixed SQL; there is no
public write or data-plane endpoint.

The standalone SQL acceptance checks all five tables, North/Orbit fan-out,
link endpoint changes, no-op updates, INSERT/DELETE, role-signed tenant
isolation and atomic rollback of metadata + version updates. Old SQL
security E2E and concurrent writer tests remain mandatory CI regressions.

**Remaining limitations:** Time-only expiration of grants does not
execute a DB writer trigger, even when expiry changes effective access.
There is still a final revision check → response gap and no formally
specified read/revoke linearization. Physical Bun.SQL connection discard,
production identity/session storage, durable audit, HTTP gateway and
multi-instance safety remain SPEC/PROPOSED. Tests of these SQL triggers
are not a claim of production-ready authorization.
