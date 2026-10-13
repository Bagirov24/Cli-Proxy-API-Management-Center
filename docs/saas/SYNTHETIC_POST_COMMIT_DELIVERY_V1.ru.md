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


**Role/transaction caveat:** Same-transaction read-your-own-writes
is possible for a PostgreSQL superuser. "After COMMIT" is established
by separate committed writer and authenticated worker connections,
not by magic SQL invisibility to an owner that deliberately impersonates
roles inside one transaction. Production must enforce this process
isolation and prevent any reader/caller from obtaining worker roles.

**ACK/exhaustion race:** The exhaustion history entry is appended only
when the current UPDATE actually commits the status transition; a
concurrent ACK that wins the state-row lock cannot create both a mock
success and a spurious `retry_exhausted` event.

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

## Negative acceptance: orphan local effect before PG ROLLBACK

A real PG16 Bun process signs a synthetic Allow and stages the 009
audit event + 013 intent, then pauses BEFORE SQL transaction completion.
The test runner observes that PostgreSQL transaction still active,
records one effect in a local in-memory simulated recipient, and lets
the SQL writer explicitly ROLLBACK. Both source audit and intent are
then absent, but the already emitted synthetic effect remains. The
test deliberately reports **PASS for exposing the gap**, not PASS for
solving it. The 013 worker cannot claim an event that does not exist,
cannot retract an earlier effect and cannot infer what the external
receiver saw.

This negative acceptance is proof that the production HTTP publication
readiness gate must stay OPEN. A separate audited post-COMMIT outbox
payload/send/recipient ACK protocol with appropriate authorization,
cancellation, idempotency and crash semantics is still SPEC.

Verified on code SHA `e452993e14d5f9db4d86a7fa74516f6961600f2f` in
[PG16 #38305618718](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38305618718)
together with [Main CI #38305618686](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38305618686)
(1,829 PASS/0 FAIL), [Demo #38305618762](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38305618762)
and [Chromium #38305618724](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38305618724)
— **4/4 SUCCESS**.

## 014: durable LOCAL synthetic receiver ledger (additional pilot)

**IMPLEMENTED / VERIFIED on code SHA a8eabe5 (staging only):**
`014_synthetic_receiver_ledger_pilot.sql` adds a guarded, append-only
PostgreSQL16 `synthetic_receiver_effects` ledger with exactly one row per
immutable 013 event/key. In this **test receiver only**, inserting the
row IS the whole simulated effect, committed atomically with its
receipt UUID. The `saas_mock_receiver` NOLOGIN capability can call
`receive_synthetic_delivery(event,key,'audit_observed_v1')` but
cannot read or modify private tables directly. An active committed 013
worker claim is required. An identical retry returns the original
receipt and `applied_now=false`; wrong key/kind fails closed.

An independent sender can use `mark_mock_receiver_ack` to check a
matching durable receiver receipt AND the unchanged 013 generation,
lease and fence. The original 013 `mark_mock_delivery_ack` remains
unchanged for compatibility with its existing synthetic tests; it is
**not** cryptographic network ACK verification. The ledger survives
receiver process restart because it lives in disposable PostgreSQL,
not an in-memory Map. PG16 acceptance additionally checks rollback,
ACK loss/retry, stale and forged ACK, terminal state, ACL and migration
replay. The referenced PostgreSQL16 CI completed SUCCESS.

**Critical boundary:** a PostgreSQL receiver-local atomic row is NOT a
remote recipient transaction; it proves neither real network delivery
nor exactly-once effects at an arbitrary client. No real payload,
network bytes, tenant rows, credentials or HTTP endpoints are added.
Pre-COMMIT synchronous local handoff remains an unsolved blocker.

**014 VERIFIED after GitHub Actions:** on code SHA
`a8eabe5ecc0ccbd42437bb73c6ee58286166c86d`, [PG16 #38307286153](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38307286153),
[Main CI #38307286415](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38307286415),
[Demo #38307286039](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38307286039),
[Chromium #38307286115](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38307286115)
all completed SUCCESS. The following documentation-only commit must be
independently verified on its own SHA before claiming final CI green.

## Stage 2G.4d.7e: intent-only trusted publication (separate path)

The previous signed local publication still has a pre-COMMIT
handoff hazard. The new opt-in `syntheticCommittedIntent.ts`
injects only an inert pre-COMMIT callback; the separate 013/014
receiver worker runs after a committed event has been observed.
Loss of a producer COMMIT response returns an UNKNOWN 503 even
when the event exists, and worker recovery proceeds on the
same durable idempotency key. **No external delivery is claimed.**
Read [the exact contract](COMMITTED_INTENT_ONLY_V1.ru.md).

**VERIFIED on code commit `fa895296a6ce4062687d0ad0af77f26114d4ef03`:** [PG16 #38309259713](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259713), [Main CI #38309259929](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259929), [Demo #38309259856](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259856), [Chromium #38309259696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259696) — all 4 SUCCESS. The final documentation commit requires its own independent Actions results; code verification does not imply production readiness.


## 2G.4d.7f — producer-side replay cannot create a second 013 intent

Unlike receiver-local deduplication (014), migration 015 binds a
stable producer operation UUIDv4 to one already committed 009 audit
and its derived 013 intent. A retry with the same signed identity
and exact request limit is a transactionally serialized lookup,
not another dispatch or another audit event. It cannot assert
real receiver ACK or remote delivery, and a different UUID remains
a distinct logical event.
See [PRODUCER_OPERATION_IDEMPOTENCY_V1.ru.md](PRODUCER_OPERATION_IDEMPOTENCY_V1.ru.md).

**CODE VERIFIED** on SHA `ca2503f2e22d30e64c32490c6f46bb7dd73b6dc1`:
[Main CI #38351833547](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833547),
[PostgreSQL16 #38351833550](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833550),
[Demo #38351833546](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833546),
[Chromium #38351833571](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833571) — **4/4 SUCCESS**.
The documentation commit must be checked independently on its own SHA.


## 016 producer issuance is not receiver delivery

The new DB-issued producer UUID and bounded read-only status operate
strictly **upstream** of the already committed 013 intent and 014
local receiver effect. An `issued` state means NO committed
production intent; `committed` means a signed event exists,
not that a remote recipient processed it. `expired` never frees a
UUID for reuse. Separate 012/013/014 worker fencing remains required.
[Issuer/recovery contract](PRODUCER_OPERATION_ISSUANCE_RECOVERY_V1.ru.md).

**CODE VERIFIED on `0d9214b8b41deb1ab97a43f71bb76bdf9d661a7d`:**
[Main CI #38354372696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372696),
[ephemeral PostgreSQL16 #38354372709](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372709),
[Demo #38354372683](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372683),
[Chromium #38354372700](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372700) — **4/4 SUCCESS**.
The final documentation SHA requires its own independent CI; this does not authorize production delivery.


## 017 quota is on producer issuer/status, NOT worker ACK

The 017 issuer/status budgets only restrict issuance and read-only
state polling for the opted-in staging port. They do not alter 012
audit observation, 013 synthetic attempts, 014 receiver receipt,
or real network delivery. Counter exhaustion changes neither
previously committed producer UUID nor its immutable 009/013 intent.
[017 abuse contract](TOMBSTONE_RETENTION_ABUSE_GATES_V1.ru.md).


**CODE VERIFIED on SHA `64d93a034face985d07aa990085d56678e441715`:**
[Main CI #38356159803](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159803),
[PostgreSQL16 #38356159812](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159812),
[Demo #38356159923](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159923),
[Chromium #38356159948](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159948)
all SUCCESS. The final documentation commit requires independent Actions on its own SHA.


## 018 insertion budgets are NOT 014 receiver quotas

Limits on creating new issued-UUID tombstones or producer
event mappings do not delete historical 013 intents, modify
012 reconciliation, or reset 014 receiver fencing/receipt.
Existing committed producer event replays do not create a new
mapping and therefore are not rejected by the new-insert budget.
No remote ACK or real recipient semantics are attested.
[018 details](SYNTHETIC_TOMBSTONE_RETENTION_V1.ru.md).


## Stage 2G.4d.7j — no recipient evidence from archival witness

The detached witness covers only SHA-256 commitments to
015 producer and 016 issued UUIDs. A committed producer
UUID may also have 013/014 mock delivery activity, but the
witness does NOT include local receiver ACK, transport
payload, remote receipt or fencing state. No stage-7j
checkpoint starts a worker or network sender.
`gcPermitted=false` and production delivery gates
remain unchanged.
[Witness details](SYNTHETIC_ARCHIVE_WITNESS_PROOF_V1.ru.md).

**CODE VERIFIED on `66019cd7602d256148562eafd304e9712a2d907b`:** [Main CI #38363925445](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925445), [ephemeral PostgreSQL16 #38363925442](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925442), [Demo #38363925450](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925450), [Chromium #38363925440](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925440) all SUCCESS. Final docs SHA needs its own Actions. No production release claim.
