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


## Follow-on 016: issued versus directly supplied UUID

015 still accepts a caller-stable UUID in its original synthetic
event-only boundary (unchanged for legacy tests). The **new 016
reserved-only boundary** is a separate opted-in staging API:
`createTrustedSyntheticOperationIssuer`,
`createTrustedReservedSyntheticIntentBoundary`, and
`createTrustedSyntheticOperationStatusBoundary`. Their signed DB
contract requires a previously issued UUID with exact current identity
and shape. The issuer stores no 009/013 event, the first valid reserved
commit stores exactly one, and status reads a minimal enum only.

An expired unused issued ID cannot mint an event. An already committed
ID may be reconfirmed within the two-hour recovery window regardless
of its shorter initial issue TTL. Expired IDs remain permanent
append-only tombstones, NOT reusable slots. Real operation retention,
identity persistence and unknown-outcome HTTP API remain SPEC.
[Details](PRODUCER_OPERATION_ISSUANCE_RECOVERY_V1.ru.md).

**CODE VERIFIED on `0d9214b8b41deb1ab97a43f71bb76bdf9d661a7d`:**
[Main CI #38354372696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372696),
[ephemeral PostgreSQL16 #38354372709](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372709),
[Demo #38354372683](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372683),
[Chromium #38354372700](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372700) — **4/4 SUCCESS**.
The final documentation SHA requires its own independent CI; this does not authorize production delivery.


## 017 bounded-issued flow does not change 015 dedup

For the newer staging-only 016-issued path, 017 now gates UUID
issuance against short and lifetime per-principal quotas; status
polling commits per-principal attempt counters on denial. Legacy
015 direct synthetic UUID replay remains available to staging SQL
fixtures and still deduplicates one event but is not a fully
global rate-limiting system. No tombstone is ever deleted.
[017 contract](TOMBSTONE_RETENTION_ABUSE_GATES_V1.ru.md).


**CODE VERIFIED on SHA `64d93a034face985d07aa990085d56678e441715`:**
[Main CI #38356159803](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159803),
[PostgreSQL16 #38356159812](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159812),
[Demo #38356159923](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159923),
[Chromium #38356159948](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159948)
all SUCCESS. The final documentation commit requires independent Actions on its own SHA.


## 018 producer-event hard stop under legacy 015 SQL

Direct 015 signed event-only producer operations keep
transactional same-UUID idempotency. Their NEW committed
mapping rows now traverse the 018 producer INSERT budget
(32 actor/64 tenant per five minutes) plus 64 actor/256 tenant
lifetime ceilings. A new identity when quota is exhausted
rolls back the enclosing 009 audit and derived 013 intent;
replay of an already committed UUID makes no new insertion
and can still confirm the original event.
This is not burst throttling for replay attempts, real payload
or proof of remote delivery.
[Retention contract](SYNTHETIC_TOMBSTONE_RETENTION_V1.ru.md).


## Stage 2G.4d.7j — hash checkpoint is not idempotency authority

The offline witness uses one SHA-256 commitment per 015
producer-operation UUID and per 016 issued UUID, distinguished
by domain-separated kind. Its signed head can identify a
missing historical committed ID in a simulated restore, but
it is never consulted in the live signed 015/016 idempotency
transaction, cannot authorize a new ID, and cannot permit
a second event for a reused key. This CI is not true
crash-safe archive delivery or remote ACK.
[Witness contract](SYNTHETIC_ARCHIVE_WITNESS_PROOF_V1.ru.md).

**CODE VERIFIED on `66019cd7602d256148562eafd304e9712a2d907b`:** [Main CI #38363925445](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925445), [ephemeral PostgreSQL16 #38363925442](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925442), [Demo #38363925450](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925450), [Chromium #38363925440](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925440) all SUCCESS. Final docs SHA needs its own Actions. No production release claim.


## 2G.4d.7k — real restored PostgreSQL missing UUID is detected

The 7k offline witness verifies the immutable issued and
producer UUID commitment sets from an actual PG16 backup
restore in a separate scratch database. It refuses old
copies whose UUID set lacks later signed commitments, but
is not consulted by a real producer and does not authorize
new event minting, replaying a lost key or deleting old
operation mappings. Existing 015 atomic deduplication is
unchanged; live failover/non-reuse across restored instances
remains SPEC.
[7k strict restore proof](SYNTHETIC_WITNESS_RESTORE_PROOF_V1.ru.md).

**CODE VERIFIED at `9af3b8d5b29ebceb6a433468c650f01be913a148`:** [Main CI #38367994239](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994239), [ephemeral PostgreSQL16 #38367994247](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994247), [Demo #38367994191](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994191), [Chromium #38367994196](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994196) — **4/4 SUCCESS**. Final docs SHA must be separately verified. No archive or GC authorization.
