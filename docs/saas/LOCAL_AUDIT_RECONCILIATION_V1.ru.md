# 2G.4d.7c — private committed-local-audit reconciliation (staging PG16)

**IMPLEMENTED / VERIFIED** in disposable PostgreSQL16 only.
NO network transport/HTTP ACK and NO production deployment.

[Main #38302392363](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392363) (1,829 Bun PASS, 0 FAIL; ESLint/TypeScript/Vite),
[PG16 #38302392290](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392290) (real Bun.SQL signed publication, PG16 crash/concurrency, rollback,
lease reclaim/fencing), [Demo #38302392314](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392314), [Chromium #38302392437](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392437) — **4/4 SUCCESS** on code SHA
`1aeeb218a68ca7f0c8094d51551802205b60f224`.

## Precise contract

Previous migration 009 already creates an append-only, redacted
`local_publication_audit_outbox` event inside the same signed
PostgreSQL transaction as receipt-only LOCAL publication. Such an
event becomes visible to a separate connection only after successful
PostgreSQL COMMIT. A synchronous local handoff may still have occurred
before a **failed COMMIT** and cannot be rolled back externally.

New guarded migration
`staging/saas-rls/012_committed_local_audit_reconciliation_pilot.sql`
adds a second, private **local observation state**, not a delivery queue:
`local_audit_reconciliation_state` and immutable
`local_audit_reconciliation_history`. One state row is permanently
keyed by the original audit `event_id` foreign key. The original
signed tenant/actor/revision/correlation audit row remains unchanged.

The NOLOGIN NOINHERIT `saas_audit_reconciler` capability has EXECUTE
on exactly two private SECURITY DEFINER functions and schema USAGE,
**no SELECT/UPDATE/INSERT on private tables**. Neither application
`saas_ci_runner` nor signed `saas_rls_reader` can use either function
or directly inspect the state/history, worker UUID or signing keys.

1. `claim_committed_local_audit(max_events,lease_seconds,target_event)`
   claims 1–16 existing visible audit IDs; leases last 1–30 seconds.
   A dedicated worker can omit the optional target ID and scan for
   eligible events. It receives **only** event ID, increasing
   generation and random fencing UUID, never tenant/actor, bearer,
   SQL rows, secrets, or a response body.
2. Concurrent claimers use `FOR UPDATE OF event SKIP LOCKED` and
   a transactional state UPSERT; only one lease can be committed for
   an event at a time. A claimed but uncommitted lease/history rolls
   back on connection failure or cancellation. An already committed
   lease remains until expiry and may then be **reclaimed**, advancing
   its generation and replacing the random UUID.
3. `mark_local_audit_reconciled(event,generation,UUID)` succeeds only
   before active lease expiry, for exactly the current generation and
   UUID. It writes an append-only local history observation and
   atomically marks state **`reconciled_local`**, removing the lease
   token. After COMMIT the observation is terminal. Duplicate,
   stale, expired or guessed acknowledgements return FALSE; failed
   transaction ROLLBACK removes the observation and state mutation.

`reconciled_local` means **only**: "a privileged local PostgreSQL
worker observed the previously committed local audit event and
committed its own bookkeeping." It does **NOT** mean data was
transported, queued remotely, processed by a client, or acknowledged
by an HTTP consumer. No external worker, scheduler, retry daemon,
network API or event delivery transport is installed.

**Cross-connection caveat:** PostgreSQL allows a privileged session
to read its OWN uncommitted writes. "Committed-only" relies on strict
reader/publisher vs reconciler privilege/process separation, as
enforced in real CI. A superuser that impersonates multiple roles
within a single transaction can still see its own uncommitted event;
do not claim the function makes that impossible. Real production must
use a dedicated authenticated worker connection and role.

## Verified failure and adversarial matrix

| Scenario | PostgreSQL16 acceptance |
| --- | --- |
| Unsigned/foreign/revoked actor attempts to create Allow event | Existing 009/011 signed gate denies; no event to reconcile |
| Signed Allow transaction ROLLBACK | No committed source event or candidate |
| Reconciler claims then ROLLBACK | No lease or history remains |
| Two separate worker connections contend for event | Second uses SKIP LOCKED: no duplicate claim or visibility |
| PostgreSQL backend forcibly terminated before claim COMMIT | Claim/history roll back; original event survives |
| Worker disappears after claim COMMIT | Lease expires; new worker reclaims with generation+1/new UUID |
| Old claimant races with new claimant | Old generation/UUID cannot mark reconciliation |
| Mark reconciled then ROLLBACK | No committed observation; lease remains active |
| Mark reconciled then COMMIT twice | One permanent terminal local observation; duplicate fails |
| Direct app/reader table or function access | Denied; history rejects UPDATE/DELETE even for fixture |
| Migration 012 replay | Original locally reconciled terminal state preserved |
| Real non-superuser Bun.SQL receipt-only publish | Post-COMMIT audit ID is reconciled privately; no SQL rows/UUID in receipt |

The multi-process crash script
`scripts/saas-staging/verify-audit-reconciliation.sh` requires
GitHub Actions, `SAAS_EPHEMERAL_AUDIT_RECONCILE_CI=true`,
`PGDATABASE=saas_ephemeral_test`, localhost PG16 and a privileged
fixture. It kills one disposable backend using
`pg_terminate_backend` only after verifying that an uncommitted
claim is blocked from another worker, then proves safe retry and
fencing. No real AI traffic or production database is touched.

## Remaining production gaps (OPEN / SPEC)

- No atomicity between already-emitted local/HTTP bytes and PostgreSQL
  COMMIT. A failed COMMIT can leave delivered bytes with **no** audit
  source row, which reconciliation cannot discover or repair.
- No actual network delivery/ACK, client idempotency token, retry
  policy, dead-letter strategy, transport backpressure or response
  linearizability proof. This local observation state must never be
  named "delivered" or "exactly once HTTP".
- No tamper-evident external log, replicated queue, secured retention
  or disaster recovery; PostgreSQL superusers can bypass protections.
- No production-capable identity issuer, OAuth sessions, audited worker
  credentials, lease scheduler, monitoring/SLO, physical driver
  discard/failover, monotonic migrations, Vault/CPA/Gateway, egress
  firewall, billing or real Control API.
- Migration 012 must be applied AFTER 001–011 with a production
  registry that rejects out-of-order replay. CI's replay testing is
  not deploy approval.

Safety boundary unchanged: no merge, production Railway/Core/Gateway,
CPA Key Policy, /data, keys, OAuth, public endpoints, live proxy/VPN
or network enforcement. See
[PRODUCTION_READINESS_GATES_V1.ru.md](PRODUCTION_READINESS_GATES_V1.ru.md).

## 2G.4d.7d — separate, downstream synthetic intent protocol

The terminal `reconciled_local` status stays unchanged and is merely
a PREREQUISITE to a migration-013 claim of the separate synthetic
event-only intent. The two state machines have separate NOLOGIN
privileges, leases, attempt histories and terminal statuses. A
`mock_acked` event records one simulated local ACK; it never means
HTTP delivery, externally durable remote receipt or real response
commit. Details:
[SYNTHETIC_POST_COMMIT_DELIVERY_V1.ru.md](SYNTHETIC_POST_COMMIT_DELIVERY_V1.ru.md).

## 014 separate receiver-local persistence, not audit delivery

014 adds a private synthetic receiver effect/receipt row following 013.
It does not change the meaning or SQL schema of 012's
`reconciled_local`, nor provide a real transport or client ACK.
A duplicate LOCAL receiver request sees its first committed receipt,
not a second logical effect. VERIFIED on `a8eabe5` in [PG16 #38307286153](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38307286153).

## 2G.4d.7e staging-only committed intent mode

Новый event-only путь 2G.4d.7e не изменяет миграцию 012:
`reconciled_local` всё ещё означает исключительно
durable локальное наблюдение committed 009 audit.
Это prerequisite для 013 synthetic dispatch, а не
доказательство HTTP response delivery. Sender может
потерять COMMIT reply; отдельный worker позже найдёт
закоммиченный intent без повторного запроса.

**VERIFIED on code commit `fa895296a6ce4062687d0ad0af77f26114d4ef03`:** [PG16 #38309259713](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259713), [Main CI #38309259929](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259929), [Demo #38309259856](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259856), [Chromium #38309259696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259696) — all 4 SUCCESS. The final documentation commit requires its own independent Actions results; code verification does not imply production readiness.
