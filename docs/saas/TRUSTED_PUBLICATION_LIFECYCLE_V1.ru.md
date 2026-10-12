# Stage 2G.4d.5b — Trusted Receipt-Only Local Publication Lifecycle

**IMPLEMENTED / VERIFIED only for synthetic identities and disposable PostgreSQL 16.**
No HTTP endpoint, no actual remote delivery or production security release.

Code SHA: `71688ebe6d17a0139a2363609f807ce49640e8be`. Evidence:
[CI #38291187218](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38291187218)
(1,809 tests PASS, 0 FAIL, ESLint, TypeScript, default-off Vite),
[PostgreSQL #38291187422](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38291187422)
(real non-superuser signed publication integration),
[Demo #38291187093](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38291187093) and
[Chromium #38291187313](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38291187313):
**4/4 SUCCESS on code SHA**.

## New internal server-only entrypoint

`createTrustedSqlPublishedBoundary` shares the exact existing
`createTrustedSqlReadBoundaryEngine` with the read-only API. A
server-injected `TrustedLocalPublicationSink` is mandatory; its
`stage(payload, signal)` MUST privately prepare data and return a
synchronous, non-throwing local `commit()` callback.

The entrypoint still validates the pinned synthetic JWT and trusted
issuer+subject mapping; resolves server-held actor and membership;
applies collection RBAC; captures the earliest pre-read trusted
authorization revision+expiry; executes both existing independent
signed SQL metadata snapshots and their current RLS gates; rechecks
issuer/subject and server actor state; and compares signed revision
after the second metadata COMMIT.

**Only then** it enters `withSignedScopedPublicationBarrier`:
signed PostgreSQL transaction, current membership+role+collection,
private tenant epoch `FOR SHARE`, revision and expiry snapshot
comparison, private asynchronous stage, another JWT/directory/actor
membership check after stage, DB read gate and clock check, mandatory
synchronous redacted audit, synchronous local handoff and COMMIT.

The outer published-mode API returns only
`{ok:true,status:200,source:'staging-local-publication',
correlationId,published:true}`. It never returns tenant ID, revision,
raw actor, SQL rows, tokens, grant metadata or staged payload.
The original `createTrustedSqlReadBoundary` remains unchanged in
its return shape and does NOT silently become an HTTP publisher.
No request controls the actor, role, epoch, SQL template or sink.

## Fail-closed contract

- Wrong issuer/subject/JWT, tenant or role is denied before SQL.
- Missing/expired/mismatched revision or permission after signed
  `FOR SHARE` refuses handoff (generic 404, tenantless deny audit).
- Directory or membership changes DURING local private stage abort
  publication (generic 503, tenantless error audit).
- A synchronous audit sink failure prevents the handoff and returns
  generic 503; uncertain SQL state quarantines the entire CI pool.
- Client cancellation, hung preparation, malformed SQL and deadline
  failures also refuse local publication and expose no rows.

Adversarial synthetic tests cover all of these and ensure the audit
Allow event is present **before** the local handoff. The real
PostgreSQL16 E2E proves that signed HMAC transactions and a synthetic
JWT/actor/RBAC request produce a receipt with no SQL rows. Earlier
2G.4d.5a E2E independently proves a cooperating revocation writer
cannot commit ahead of a local handoff while `FOR SHARE` is held.

## Important residual gaps

- Actor/directory/JWT test stores and synchronous audit buffer are
  NOT authoritative production state or a durable audit outbox.
  A membership mutation in a separate actor store can race between
  last actor recheck and commit without bumping PostgreSQL epoch.
  Production MUST version or serialize that state in the same
  authoritative revocation protocol, or formally reject the design.
- Audit `read-allowed` is a synthetic authorization record, not
  proof of remote delivery. If local handoff or later DB COMMIT fails
  after synchronous audit, the audit event may exist without a
  successful receipt; durable outbox and idempotent delivery are
  NOT implemented.
- A local synchronous `commit()` callback is assumed atomic and
  non-throwing but that property cannot be enforced against arbitrary
  external transports. No real HTTP socket, slow-client backpressure,
  OS send buffer, TCP receipt or distributed retry semantics are proven.
- Existing experimental Bun.SQL quarantine closes the whole CI pool;
  physical reservation discard/reuse under cancellation still needs
  independent production verification.
- No durable production OIDC/session, Vault/BYOK/BYOA, real CPA/Gateway
  binding, real network egress enforcement, billing or public API.

The only proven publication linearization point is **synchronous
server-local handoff** while a cooperating PostgreSQL epoch lock is held.
A revocation-complete guarantee must explicitly allow or reject
late remote arrival of previously handed-off bytes. Lock COMMIT order
does not equate to receipt at a remote browser.

See [BOUNDED_PUBLICATION_HANDOFF_V1.ru.md](BOUNDED_PUBLICATION_HANDOFF_V1.ru.md),
[PUBLICATION_BARRIER_PILOT_V1.ru.md](PUBLICATION_BARRIER_PILOT_V1.ru.md),
[PRODUCTION_READINESS_GATES_V1.ru.md](PRODUCTION_READINESS_GATES_V1.ru.md).

## 2G.4d.7a — opt-in token-bound trusted publication

`createTrustedSqlPublishedBoundary` now supports server-only
`requireTokenBoundSession:true` with an authoritative staging revision
source. The verified exact bearer fingerprint is signed through all
SQL reads/revisions and FOR SHARE publication, but never returned in
a receipt. Enrolled actor IDs cannot fall back to 4-field actor-only
HMAC. This does not add a public OIDC or HTTP transport.
See [TOKEN_FINGERPRINT_REVOCATION_V1.ru.md](TOKEN_FINGERPRINT_REVOCATION_V1.ru.md).

## 2G.4d.7b — issuer subject revocation within bounded publication lease

For explicitly enrolled subjects, migration 011 extends the same
signed actor+token+epoch PostgreSQL gate with an immutable, active
issuer+subject binding. Subject revoke versions all member tenants,
blocking concurrent publishing readers on the established `FOR SHARE`
barrier until earlier COMMIT. Real multi-process evidence [PG16 #38300085282](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085282) confirms
an individually active token is denied after subject revoke COMMIT.
The synchronous local handoff still precedes DB COMMIT and is NOT a
remote HTTP receipt; atomic transport/outbox reconciliation is SPEC.
See [ISSUER_SESSION_ENROLLMENT_V1.ru.md](ISSUER_SESSION_ENROLLMENT_V1.ru.md).

## 2G.4d.7c — post-COMMIT observation is separate from local handoff

The trusted receipt-only publication inserts an allow-audit event in
its signed transaction before local synchronous handoff; only AFTER
successful PostgreSQL COMMIT can a different NOLOGIN reconciler worker
claim the event and mark `reconciled_local`. The Bun.SQL E2E proves
the receipt cannot expose event IDs/leases/rows, while PG16 crash tests
prove rollback, retry and stale-worker fencing. No code attempts to
publish HTTP bytes atomically with a SQL COMMIT. This remains SPEC,
not a production release boundary. See
[LOCAL_AUDIT_RECONCILIATION_V1.ru.md](LOCAL_AUDIT_RECONCILIATION_V1.ru.md).

## Follow-up 2G.4d.7d — audit/intent post-COMMIT simulated worker

A new PG16 trigger stages a payload-free synthetic delivery intent
when the signed 009 audit is inserted, and both become externally
visible only upon successful PostgreSQL COMMIT. A separate 012
reconciliation COMMIT precedes any 013 mock worker claim. The Bun.SQL
E2E models a fake receiver accepting once under stable UUID,
dropping the first mock ACK, and deduplicating the second attempt.
No actual HTTP send or client ACK is wired to this boundary. A local
handoff can still precede a failed PG COMMIT and is not retractable.
See [SYNTHETIC_POST_COMMIT_DELIVERY_V1.ru.md](SYNTHETIC_POST_COMMIT_DELIVERY_V1.ru.md).
