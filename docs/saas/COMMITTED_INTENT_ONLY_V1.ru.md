# 2G.4d.7e — Synthetic committed-intent-only publication

**IMPLEMENTED (staging, not HTTP).** Verification requires GitHub Actions
on the code SHA and again on the final documentation SHA.

## Security problem

The earlier `createTrustedSqlPublishedBoundary` hands off locally using
an injected synchronous callback **before** PostgreSQL `COMMIT`.
A real SQL rollback cannot undo that callback. The existing negative
Bun/PG16 test intentionally proves this failure. Migration 013/014
cannot retroactively recover an event that never committed.

## Narrow opt-in safer path

`syntheticCommittedIntent.ts` exposes
`createTrustedSyntheticCommittedIntentBoundary(deps)`.
This entrypoint uses existing trusted RS256 bearer verification,
server-controlled actor mapping, PostgreSQL-signed transaction scope,
tenant RBAC, authorization revision checks and signed audit outbox.

It injects **no application publisher or caller-defined callback**:
its private preparation returns an intentionally inert synchronous
function. Thus no synthetic receiver effect can be emitted inside
this route's publication transaction. The trusted SQL code still
holds its authorization lock while inserting 009 signed Allow audit;
the 013 trigger creates its event-only immutable intent in the same
transaction. A successful return is possible **only after PostgreSQL
COMMIT resolves successfully**. The response is minimal:

- `source = staging-committed-intent-only`
- `intentCommitted = true`
- `externalReceipt = not_attested`
- Server-generated correlation ID only; no rows, JWT, fingerprint,
  tenant ID, idempotency key, worker fencing token or HTTP content.

The entrypoint rejects startup unless GitHub Actions disposable PG
settings are present and the server has explicitly enabled 009
`recordStagingOutbox` with a revision source. The production
application and HTTP routes do not use or import this entrypoint.

## Fenced downstream, not an in-transaction callback

Separate physical worker connections observe only committed source
events. They must first record 012 `reconciled_local`, then claim
013 synthetic intent, then apply 014's **PostgreSQL-local** idempotent
receiver effect and record its matching receipt with current generation
and fence. No user metadata payload is included. The earlier
local handoff implementation remains unchanged and unsafe as a
production transport.

## Two distinct failures

1. **Before COMMIT:** a dedicated real reserved PG16 connection
   inserts signed 009/013, then the CI adapter injects real
   `ROLLBACK` instead of its intended `COMMIT`.
   No event, intent or receiver effect survives. The boundary returns
   503, never `intentCommitted`.
2. **After COMMIT:** a dedicated PG16 connection **really executes
   and commits** the signed audit/intent, but CI loses the COMMIT reply
   before the boundary observes it. The boundary returns 503 and does
   **not** assert that COMMIT was successful or that it rolled back.
   The committed event is found independently and processed exactly
   once by the durable **synthetic local** receiver. No caller retry
   is needed to recover the existing event.

An HTTP 503 is **not proof that no event exists**. Retrying a new
caller request could create another event with a new correlation
identifier, which this pilot deliberately does not claim to prevent.
Producer-side durable operation identity and a real recovery/read
protocol remain SPEC.

## Hard boundaries / production blockers

- There is still no real HTTP network transport, remote ACK,
  payload serialization/encryption or external side effect.
- The PG receiver-local effect is atomic only with its own PG row;
  no claims about exactly-once real delivery are justified.
- No durable app-level operation/idempotency mapping protects a
  client retry after an unknown producer COMMIT outcome.
- No revocation-at-dispatch authorization policy, cancellation
  settlement, backpressure/dead-letter, multi-instance transport,
  external tamper-evident audit or production secrets.
- A callback injected via the **older** local publication API can
  still have an irreversible effect before failed COMMIT.
- Nothing here authorizes a production deployment, Core/Gateway/CPA
  changes, real traffic, Vault access, public endpoints or merge.

See `SYNTHETIC_POST_COMMIT_DELIVERY_V1.ru.md` and
`PRODUCTION_READINESS_GATES_V1.ru.md`.

## Inherited local audit side effect

The existing trusted publication engine still calls its injected
**synchronous security-audit recorder before the SQL COMMIT**.
Even this no-handoff, intent-only port can therefore record a
pre-COMMIT *local/in-memory* allow observation if PostgreSQL later
ROLLBACKs. That observation is not authoritative proof that the
signed PostgreSQL outbox or intent committed. Only the transactional
009/013 records are the durable source of truth for synthetic worker
eligibility. Relocating all external audit effects to a durable
post-COMMIT reconciler is still SPEC; do not use this pilot to claim
production audit completeness.

**VERIFIED on code commit `fa895296a6ce4062687d0ad0af77f26114d4ef03`:** [PG16 #38309259713](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259713), [Main CI #38309259929](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259929), [Demo #38309259856](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259856), [Chromium #38309259696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259696) — all 4 SUCCESS. The final documentation commit requires its own independent Actions results; code verification does not imply production readiness.


## Stage 2G.4d.7f — optional stable producer key

The new 015 guarded SQL mode augments this event-only path with a
required caller-stable, UUIDv4 `producerOperationId`. This is
NOT a bearer, role, SQL identity, session token or raw payload.
The signed transaction ensures matching tenant, actor, role,
collection and canonical limit. An identical replay (including a
recovery after lost COMMIT acknowledgement) reuses the first
committed audit+intent and creates no second event. Different
identity or shape fails closed with generic 404. Separate worker
delivery remains 012/013/014 and is NOT HTTP.
[Exact contract](PRODUCER_OPERATION_IDEMPOTENCY_V1.ru.md).

**CODE VERIFIED** on SHA `ca2503f2e22d30e64c32490c6f46bb7dd73b6dc1`:
[Main CI #38351833547](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833547),
[PostgreSQL16 #38351833550](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833550),
[Demo #38351833546](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833546),
[Chromium #38351833571](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833571) — **4/4 SUCCESS**.
The documentation commit must be checked independently on its own SHA.
