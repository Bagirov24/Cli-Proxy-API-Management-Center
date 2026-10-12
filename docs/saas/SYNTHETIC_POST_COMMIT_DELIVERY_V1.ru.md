# 2G.4d.7d — Synthetic committed-event delivery intent & mock ACK

**IMPLEMENTED / VERIFIED only in synthetic disposable PostgreSQL 16.**
No real HTTP recipient, network transport, external response ACK, payload
queue, or production dispatch has been implemented.

Evidence: [Main CI #38304607776](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607776) (1,829 PASS / 0 FAIL, ESLint, TypeScript, Vite), [PostgreSQL16 #38304607719](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607719), [Demo #38304607709](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607709), [Chromium #38304607769](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607769) — **4/4 SUCCESS** on code SHA `6b0bf3189c544cce21ccdfbaf58b7b2f72ba3214`.

## Problem and deliberately limited solution

2G.4d.7c established `reconciled_local`: a dedicated PG worker
durably observed a committed 009 audit event. It still had no separate
downstream-intent record or example of a consumer whose ACK was lost.

Guarded migration `013_synthetic_delivery_intent_ack_pilot.sql`
adds a SECOND, independent, private staging-only state machine.
The `synthetic_delivery_intents` trigger inserts exactly one immutable
`event_id` + random `idempotency_key` UUID in the SAME PostgreSQL
transaction as a signed `local_publication_audit_outbox` INSERT.
A failed PostgreSQL COMMIT/ROLLBACK discards BOTH. The original source
audit is never changed or marked delivered. The migration backfills
existing committed audit IDs as SIMULATION intents only: this does
not mean those historical events were sent.

An intent is eligible for a synthetic claim only after a separate
`local_audit_reconciliation_state.status='reconciled_local'` COMMIT.
Workers are limited to the NOLOGIN, NOINHERIT, non-superuser
`saas_mock_delivery_worker` role, with only EXECUTE privileges for
two private SECURITY DEFINER functions. The worker cannot directly
SELECT any audit, intent, tenant/actor or private state tables.
Ordinary SQL readers/CI runner cannot claim or ACK synthetic events.

## Exactly defined synthetic protocol

1. `claim_synthetic_delivery(max_events,lease_seconds,target_event)`
   takes 1–16 events per call with a 1–30 second lease; `target_event`
   is CI-only deterministic selection. The query uses `FOR UPDATE OF
   intent SKIP LOCKED` and returns only `delivery_event_id`,
   `delivery_generation`, `fencing_token` UUID, immutable
   `idempotency_key` UUID and `attempt_number`. The receiver has
   NO payload: no SQL rows, tenant, bearer, subject, key/credential,
   token claims, HTTP headers or AI proxy bytes.
2. One source audit event always has ONE stable idempotency UUID.
   A worker crash before claim COMMIT leaves neither lease nor
   history. If a committed claim's ACK is lost, it can be reclaimed
   only after expiry, with attempt+1 and a new random fencing UUID,
   but the SAME idempotency key. An older worker's ACK is rejected.
3. `mark_mock_delivery_ack(event,generation,lease_uuid,key_uuid)`
   terminally stores `mock_acked` only for the current, unexpired
   lease/generation and the exact immutable intent key. A duplicate,
   wrong-key, expired or stale claim returns FALSE; the append-only
   `synthetic_delivery_history` records `claimed/reclaimed/
   mock_acked` separately. SQL rollback of this mark never
   manufactures an ACK.
4. There are MAX THREE claim attempts. If the third committed
   lease expires unacknowledged, a later scan terminally records
   `retry_exhausted`; this is NOT `mock_acked`, NOT a dead-letter
   network delivery, and does not silently retry forever.

A fake ACK is supplied by a **pure in-memory test receiver**. It
has no cryptographic or network provenance. A privileged synthetic
worker could echo the key itself: **mock_acked is NOT proof of
delivery to any client**. All external receipt, recipient identity,
durable receiver idempotency, signed ACK and replay protection are
production SPEC.

## PostgreSQL16 + Bun acceptance

- Signed audited source INSERT creates intent before COMMIT;
  ROLLBACK removes both (the pre-COMMIT legacy local-handoff
  uncertainty is deliberately acknowledged, not solved).
- Unobserved committed source is not eligible for synthetic worker.
  Only after separate `reconciled_local` COMMIT can it be leased.
- Concurrent PG connections: first uncommitted worker holds row
  lock, second sees no lease due to SKIP LOCKED; forcibly terminating
  first backend rolls back claim/history and preserves source/key.
- Crash after claim COMMIT and clock-only lease expiry:
  generation+1, new UUID, identical immutable idempotency key.
  Wrong key, wrong generation, stale ACK and duplicate ACK all deny.
- Actual non-superuser trusted Bun.SQL receipt-only publication,
  committed local audit and synthetic intent. Simulated recipient
  stores one effect by idempotency key; first response ACK is lost;
  second attempt uses same key and causes NO second receiver effect;
  only the new lease records `mock_acked`. Public receipt contains
  no event ID, worker UUID, idempotency key, SQL rows or bearer.
- Claim attempts 1→2→3 then expiry leads to terminal
  `retry_exhausted` with no fake success. Direct table mutation/
  permissions denied, history append-only, migration replay preserves
  both terminal statuses.

The active CI uses disposable PG16, synthetic signed JWTs,
a privileged fixture-only `SET LOCAL ROLE` and an in-memory map.
No actual network request or user-facing message is dispatched.

## Non-negotiable production blockers

**No atomic response delivery with PostgreSQL COMMIT.** The EXISTING
synchronous local handoff may execute before a failed COMMIT. If
bytes were emitted but SQL COMMIT failed, there is NO durable 009
audit event and therefore no 013 intent to reconcile. This pilot
does not retract emitted bytes or detect a remote recipient.

Furthermore there is no actual HTTP transport/remote ACK, delivery
payload serialization or encryption, recipient authorization, durable
recipient deduplication, retry scheduler, dead-letter routing,
backpressure, cryptographically verified ACK, multi-instance failover
or externally tamper-evident audit/retention. `retry_exhausted`
needs an operational escalation policy, not an automatic remote send.
Privileged PostgreSQL owner/superuser can still alter internal state;
production needs separate certified worker credentials/connections.

Production monotonic migrations 001→013, actual provider OIDC,
Vault, CPA/Gateway, network egress firewall, billing, physical
driver discard and release approvals are outside this stage.

**No force-push/merge/deploy, Railway production, Core/Gateway/CPA
Key Policy, production OAuth/credentials, `/data`, management.html,
public SaaS endpoints, live VPN/proxy/egress or real AI traffic.**
See [LOCAL_AUDIT_RECONCILIATION_V1.ru.md](LOCAL_AUDIT_RECONCILIATION_V1.ru.md)
and [PRODUCTION_READINESS_GATES_V1.ru.md](PRODUCTION_READINESS_GATES_V1.ru.md).
