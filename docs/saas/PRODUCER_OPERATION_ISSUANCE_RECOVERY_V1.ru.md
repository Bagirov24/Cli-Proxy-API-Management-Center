# Stage 2G.4d.7g — signed issuance / bounded recovery (STAGING ONLY)

**IMPLEMENTED on feature branch; verification is SHA-specific.** This is an
isolated disposable-PostgreSQL16 / Bun acceptance protocol, NOT an HTTP route,
production migration, actual payload, network transport or recipient ACK.

## Contract: issue → reserved event-only commit → read-only status

Migration `016_synthetic_operation_issuance_pilot.sql` adds a private
append-only `synthetic_operation_issues` registry. A trusted Bun
`createTrustedSyntheticOperationIssuer` mints a new random UUIDv4
*server-side*; the pinned signed SQL transaction authenticates the current
tenant, actor, precise role, collection and canonical requested limit.
Only after PostgreSQL confirms COMMIT does the issuer return that UUID.

Issuance creates NO 009 signed Allow event, NO 013 intent, NO receiver effect,
NO payload and NO external request. If the issuer loses the COMMIT reply,
a private reservation may exist but the caller receives no attested UUID.
This is a leaked-id/retention concern, not a delivery event.

The new `createTrustedReservedSyntheticIntentBoundary` rejects any
*unissued* UUID or changed tenant/actor/role/collection/limit. It rechecks
current JWT/actor/RBAC, signed PG scope, epoch and token/session policy,
then calls 016 `record_signed_reserved_operation` under the same transaction.
A first valid attempt, inside its issue TTL, invokes existing 015 to atomically
write the immutable 015 mapping + signed 009 event + derived 013 intent.
A duplicate that matches the same currently authorized identity and exact
request shape uses that original committed event; it never creates another.

The independent `createTrustedSyntheticOperationStatusBoundary`
uses a separate signed **read-only** PostgreSQL transaction and current
authorization/revision checks. It exposes ONLY a minimal
`operationState` enum: `issued`, `committed`, `expired`,
plus `externalReceipt=not_attested` and a new server correlation ID.
Missing keys, tenant/actor/role/collection/limit conflicts and revoked rights
return generic denial (no operation existence oracle, event ID, worker data,
tenant ID, SQL metadata or customer payload).

This is NOT a claim that external delivery occurred. `committed`
means an event-only signed producer transaction was committed; 012 local
observation and 013/014 synthetic worker/ACK happen later and independently.

## Time and retention boundaries

PostgreSQL's own `clock_timestamp()` sets immutable deadlines:
* Issuance/use deadline: server requests 120 seconds, beginning with the
  database INSERT; expiry is hard, not extendable via retries. The exposed
  `maxIssueWindowSeconds=120` is an upper bound, not a client clock proof.
  Direct signed SQL acceptance may request 2–600 seconds to test expiration.
* Authenticated status/replay window: fixed **2 hours after issue**.
  A first commit is forbidden after the initial issue deadline. An existing
  committed event can be reconfirmed after that deadline but only within
  the two-hour recovery window.
* Beyond the recovery window, even an authorized owner sees `expired`;
  016 cannot create, replay or return a delivery attestation.
* **Critically: expiration never deletes or frees UUIDs.** The append-only
  issuance row persists as an immutable tombstone. No UUID is reused,
  even after expiration. Database retention/archival, quotas, backpressure
  and safe deletion policy remain SPEC, not implemented.

The earlier 7f `createTrustedSyntheticCommittedIntentBoundary` and
migration 015 remain untouched for backwards-compatible synthetic tests;
they DO NOT require an issued reservation. The new **7g opt-in route** does.

## Failure and adversarial acceptance

* Real disposable PostgreSQL16 and Bun: server minted UUID ignored a
  forged caller-supplied ID, issue committed without 009 outbox/013 intent,
  status `issued`, signed reserved first commit and status `committed`,
  idempotent retry without another event.
* Independent authorized North/Orbit callers and changed request limits:
  fail closed, no foreign status/payload/event disclosure.
* After actual PostgreSQL COMMIT succeeds but its reply is lost:
  producer sees generic 503 (unknown), signed recovery reads
  `committed`, retry with same issued UUID does not produce a second intent.
* After actual PostgreSQL ROLLBACK before commit:
  the already committed issue remains `issued` and a later valid retry
  creates precisely the first event.
* Direct PG16: short-lived unused issue expires, cannot commit or re-issue,
  immutable tombstone survives migration replay; committed short-TTL
  event remains confirmable until recovery window ends.
* Private table ACL, missing/foreign keys, role/request-shape conflicts,
  append-only trigger and replay across 009–016 are tested. Older 015
  cross-process advisory-lock contention and previous Bun security
  regression suites remain enabled.

## Still SPEC / PROPOSED (production gate OPEN)

No public authenticated HTTP endpoint, browser or mobile persistence,
real client idempotency header, cross-device token transfer, user operation
history, token-bucket quotas, durable payload, request-body semantic digest,
payload-at-rest encryption, OIDC/Vault, independent external audit, real
remote ACK, dispatch-time revocation, production transport retries or
safe tombstone GC/retention is provided.

An entirely **new** UUID represents a new logical operation and may
intentionally create a new event. Holding a UUID does not grant tenant
access; every operation still requires fresh authenticated authorization.
Returning `committed` does not guarantee that a recipient has processed
or acknowledged anything. A lost issuance response can strand an unused
tombstone; this pilot does not pretend to fix that with a status oracle.

The legacy synchronous local publication still has the irretractable
**pre-COMMIT handoff** hazard, and both the old and new synthetic paths
inherit non-authoritative local audit callbacks. 016 does NOT authorize
changing Core/Gateway/CPA, Railway, production databases, shared egress,
OAuth settings, /data, management.html, public routes, real traffic or merge.

**CODE VERIFIED on `0d9214b8b41deb1ab97a43f71bb76bdf9d661a7d`:**
[Main CI #38354372696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372696),
[ephemeral PostgreSQL16 #38354372709](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372709),
[Demo #38354372683](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372683),
[Chromium #38354372700](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372700) — **4/4 SUCCESS**.
The final documentation SHA requires its own independent CI; this does not authorize production delivery.
