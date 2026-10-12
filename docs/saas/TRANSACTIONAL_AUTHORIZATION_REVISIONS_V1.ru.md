# SaaS Blueprint B — Stage 2G.4d.2: transactional authorization revisions in disposable PostgreSQL

**IMPLEMENTED: staging-only migration 004, signed revision attestation, SQL
adversarial acceptance and independent-session concurrency tests.**
**VERIFIED in ephemeral PG16 CI** on code SHA
`6ea4546a6953d10baa42f7dcdc6ec5495f9f9517`, not in production.
[Main CI #38284819714](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38284819714),
[PG16 #38284819774](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38284819774),
[Demo #38284819723](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38284819723)
and [Chromium #38284819716](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38284819716)
are 4/4 SUCCESS. Bun unit tests: 1,777 pass, 0 fail.
Not production auth or a linearizable HTTP revocation barrier.

## Boundary and schema

Migration `staging/saas-rls/004_tenant_authorization_revisions_pilot.sql`
refuses any database other than `saas_ephemeral_test`, requires an explicit
`saas.staging_only=true` session setting, the `postgres` fixture login
and non-superuser owner role. It runs after 001–003 and disposable fixtures.

Private `saas_rls_private.tenant_authorization_revisions` contains a
monotonic positive PostgreSQL `BIGINT` per tenant and its active flag.
No credential, grant details or tenant metadata are copied. Counters are
initialized without reset on migration replay; delete keeps a tombstone so
recreating an ID cannot restart the epoch. Overflow aborts the write.

Row triggers atomically bump affected tenant epochs for:
- tenant insert/delete and status changes;
- membership inserts/updates/deletes including exact role/status changes;
- independent Pool, Account and Egress grant inserts/updates/deletes,
  including expiry *field mutations*, old and new grantees;
- catalog inserts/updates/deletes: owner and ALL current explicit grantees,
  including a platform resource shared with multiple tenants.

Every bump UPDATE takes a tenant-epoch row lock held through transaction end.
Concurrent writers for the same tenant serialize at the private row and
cannot lose increments; a rollback undoes both the authorization write
and the revision increment. Multi-tenant affected IDs are bumped in sorted
order to reduce deadlock probability. A missing epoch aborts the write.

`saas_rls.authorized_revision(tenant,actor,role,collection)` returns a
canonical string `BIGINT` only when signed transaction scope is verified,
tenant is active, exact DB actor/role membership is current and collection
access is allowed. Invalid/foreign/unsigned/paused/auditor-forbidden
scope yields SQL NULL, not another tenant's epoch. The reader cannot
SELECT/UPDATE private revision rows or execute writer functions.
The privileged fixture writer does not belong to the SaaS read API.

## Verified tests vs unproven claims

`tests/sql/saas_authorization_revisions.test.sql` checks signed North
vs Orbit, suspended tenant, auditor denial, forged unsigned scope, exact
role, independent Pool/Account/Egress changes, shared-resource fan-out,
tenant tombstones, rolled-back writes and a grant revoked between two
signed transactions with unchanged LIMITed project rows.

`scripts/saas-staging/verify-revision-concurrency.sh` launches two
separate disposable `psql` writer sessions plus a third observation
session. Writer 1 holds the North revision row; writer 2 updates a
different North grant and is REQUIRED to wait on a PostgreSQL lock.
An observer sees no uncommitted epoch, and two commits increase North by
exactly 2 without incrementing Orbit. Fixture rights are restored.

At the 2G.4d.2 checkpoint this was only a writer/storage proof, without a
live signed revision adapter. The following 2G.4d.3 increment subsequently
implemented `createSignedPgAuthorizationRevisionSource` and verified it in
disposable PG16 E2E through the existing fixed-SQL signed read boundary.
The runtime guard remains opt-in, is not connected to production and
still has no response/revocation linearization guarantee.

**Important limitations:** A grant expires due to time passage without a
write/trigger; revision does not advance at its expiry instant. Metadata
links/routing/app/project changes are not part of this epoch. A multi-row
mutation can take many locks and would need deadlock/retry/timeout QA.
Out-of-band privilege bypass, disabled triggers, cross-database stores or
an unversioned writer invalidate guarantees. Reader storage and actor
directory are not one production authoritative store. Bun individual
physical connection discard is still unproven. There is still a race
AFTER final revision query and before response delivery; no proof of
response/revoke linearizability or concurrent HTTP correctness exists.

No public HTTP endpoint, real identity, production credentials, Core,
Gateway, CPA settings, Railway deploy or UI dependency is introduced.
See [AUTHORIZATION_REVISION_CONTRACT_V1.ru.md](AUTHORIZATION_REVISION_CONTRACT_V1.ru.md).

## Stage 2G.4d.3 — adapter follow-up

A fixed-query `createSignedPgAuthorizationRevisionSource` is now
implemented for the isolated staging security chain, with full signed
actor/tenant/role/collection state. See
[SIGNED_REVISION_READER_V1.ru.md](SIGNED_REVISION_READER_V1.ru.md).
No production physical-connection discard or final response
linearizability is implied.
