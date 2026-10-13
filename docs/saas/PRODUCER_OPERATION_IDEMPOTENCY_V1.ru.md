# Stage 2G.4d.7f — durable producer operation ID / unknown COMMIT outcome

**Status:** IMPLEMENTED / CODE VERIFIED in disposable PostgreSQL 16; final documentation HEAD requires independent CI verification.

This is **not** a production transport, public API, remote ACK or real
SaaS delivery. No network payload, account metadata or user-visible
delivery attempt is stored. Only disposable PostgreSQL16 is supported.

## Problem and proof obligation

Migration 013/014 deduplicates a receiver-side retry of **one**
committed outbox event, but a producer that loses a successful PostgreSQL
COMMIT reply cannot distinguish committed from rolled back. Retrying
without a persistent producer key would mint a **different** signed 009
event and therefore another synthetic 013 intent.

Stage 2G.4d.7e ensures the new event-only path never invokes a local
receiver before COMMIT. Stage 2G.4d.7f additionally ensures that
**replaying the same operation UUIDv4** does not mint a second event.

## Isolated opt-in contract

New guarded migration:
`staging/saas-rls/015_synthetic_producer_operation_pilot.sql`.

The private, immutable `synthetic_producer_operations` mapping stores
only:
- a random UUIDv4 `operation_id` (globally unique);
- the committed `event_id` referencing the signed 009 Allow;
- the original tenant, actor, exact member role, collection,
  canonical `requested_limit` (1–100);
- a local timestamp.

The 013 trigger inserts exactly one event-only intent as the 009 audit
row is created. The registry, outbox and intent are written **inside the
same signed SQL transaction**, with no independent effect before COMMIT.
A ROLLBACK removes all three. Migration replay preserves mappings.

An exact `operation_id` is a **correlation/idempotency identifier,
never an authentication or authorization credential**. Every attempt
still verifies the RS256 bearer, current pinned issuer/actor mapping,
tenant membership and exact role, resource authorization revision,
signed transaction-scoped HMAC and PostgreSQL read barrier. Cross-tenant,
cross-actor, changed role/collection, changed limit and malformed UUID
are rejected generically without exposing whether an operation exists.

A PostgreSQL transaction-scoped advisory lock on the UUID serializes
two physical connections with the same ID. Only the first creates 009
audit + 013 intent. A racing/replayed caller rechecks the committed
binding under READ COMMITTED and succeeds **without inserting a new
event**. The stored first correlation ID and event ID never appear
in the caller receipt.

The new `createTrustedSyntheticCommittedIntentBoundary` requires an
explicit UUIDv4 on its request; this staging entrypoint turns on
`recordStagingProducerOperation`. The older local publication path
and signed 009 SQL template remain unchanged.

Successful response reports `intentCommitted=true` and
`externalReceipt=not_attested`, not a delivery receipt.
A lost PostgreSQL COMMIT response remains a generic 503 (unknown
outcome). Retrying with the **same** UUID on a healthy connection may
then confirm the existing event, without manufacturing another one.
This is not a public operation-status endpoint.

## Adversarial PostgreSQL16 + Bun acceptance

- Real signed operation and 013 intent commit together; exact replay
  with a different server correlation ID appends no new 009 event.
- Limit, collection, actor role and cross-tenant UUID collision deny
  without new event or foreign record disclosure.
- Malformed UUID and missing staging-only opt-in deny.
- Actual SQL ROLLBACK after staging leaves no operation/outbox/intent,
  and later retry with the same UUID creates the first valid event.
- Actual SQL COMMIT with a deliberately lost reply returns 503,
  but the next attempt with the same UUID detects the original committed
  event. Existing 012→013→014 worker/ACK remains independent.
- Two physical PostgreSQL sessions contend on the same UUID while
  the first transaction is uncommitted. The second waits on an
  advisory lock and commits an idempotent replay, leaving exactly
  one signed outbox row, operation mapping and intent.
- Reader/CI/receiver cannot read/modify private producer mappings,
  append-only trigger rejects mutation, migration replay retains state.

All checks use synthetic fixed fixtures, ephemeral PostgreSQL16,
test-only signed JWT, in-memory/test crypto keys and no external
network sender.

## Open production gates

**Not solved:** who mints/persists an operation ID on a real client,
HTTP idempotency headers and retention/expiration contract, durable
payload serialization, request-body canonical hashing, semantic identity
of an operation beyond collection+limit, real recipient identity and
ACK cryptography, replay DoS/rate limits, transaction-bound sender
attestation, human/operator recovery, external audit, cross-instance
failover and tenant retention policies.

A different UUID **intentionally** creates another logical event.
The same UUID with changed role/shape fails closed and may need
operator adjudication; the pilot does not silently treat it as
the previous authorization. Dispatch-time revocation policy
is still SPEC.

The older `createTrustedSqlPublishedBoundary` still has a
pre-COMMIT local handoff hazard. Even this new event-only route
inherits a non-authoritative synchronous *local security audit*
observation before SQL COMMIT. Neither is repaired by producer
idempotency. Only 009/013/015 committed rows are authoritative
synthetic event intent evidence.

No production deployment, Railway, Core/Gateway/CPA changes, OIDC,
Vault, real credentials, /data, public SaaS endpoints, client HTTP
or merge is permitted by this stage.

See [Committed Intent Only](COMMITTED_INTENT_ONLY_V1.ru.md),
[Synthetic Post-COMMIT Delivery](SYNTHETIC_POST_COMMIT_DELIVERY_V1.ru.md)
and [Production Readiness Gates](PRODUCTION_READINESS_GATES_V1.ru.md).

**CODE VERIFIED** on SHA `ca2503f2e22d30e64c32490c6f46bb7dd73b6dc1`:
[Main CI #38351833547](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833547),
[PostgreSQL16 #38351833550](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833550),
[Demo #38351833546](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833546),
[Chromium #38351833571](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833571) — **4/4 SUCCESS**.
The documentation commit must be checked independently on its own SHA.
