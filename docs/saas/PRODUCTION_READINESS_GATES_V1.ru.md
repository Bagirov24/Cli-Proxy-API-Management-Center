# SaaS Blueprint B — Production readiness gates (staging vs production)

**Status: SPEC/PROPOSED checklist, not production approval.**
The current feature branch is not a deployable SaaS backend and does not
authorize merging into `custom-no-apikey-fun`. Sensitive Core, Railway,
CPA Key Policy, OAuth, /data and real network traffic remain out of scope.

## 1. Verified limited security building blocks

| Boundary | Evidence | Status |
| --- | --- | --- |
| Pinned synthetic JWT → trusted actor/RBAC → signed SQL reads → RLS | 2G.4a–2G.4c, GitHub PG16 | VERIFIED ephemeral |
| Private transactional tenant epochs for status/member/grants/catalog | Migration 004, PG16 concurrency | VERIFIED ephemeral |
| Metadata projection/link revision coverage | Migration 005, [PG16 #38287715026](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38287715026) | VERIFIED ephemeral |
| Time-only grant expiry via signed next-deadline attestation | Migration 006, [PG16 #38288157880](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288157880) | VERIFIED ephemeral |
| Cooperative FOR SHARE reader/revoker COMMIT order and forced reader disconnect | Migration 007, [PG16 #38288803851](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288803851) | VERIFIED ephemeral |
| Browser/demo no-live safeguard | GitHub synthetic Chromium/Demo | VERIFIED synthetic |

These tests deliberately use synthetic identities, fixture grants, temporary
PostgreSQL16 and no real SaaS endpoints. They are regression evidence, not a
claim of production authorization or response/revocation linearizability.

## 2. Required production blockers

| Component | Missing proof / acceptance before production | Status |
| --- | --- | --- |
| Identity and sessions | Supported OIDC discovery/pinned keys, durable actor directory, replay/rotation/invalidation, revocation consistency | SPEC |
| HTTP publication | Explicit server-side delivery/handoff semantics, bounded cooperative lock lifecycle, cancellation/backpressure/crash tests and linearization specification | SPEC |
| Database reliability | Dedicated least-privileged writer, cross-instance epochs, physical Bun.SQL connection discard or alternative verified driver, deadlock/retry/failover/restore | SPEC |
| Audit | Durable access-controlled redacted log, fail-closed storage, retention/tamper evidence, incident drill | SPEC |
| SaaS Control API | Tenant-aware authenticated read/write endpoints, object-level permissions, DTO origin and no-secret projection, E2E IDOR | PROPOSED |
| Credentials | Vault, approved provider BYOK/BYOA/OAuth flows, rotation, encryption, zero cross-tenant leakage | PROPOSED |
| Data plane | CPA Gateway binding, independent Pool/Account/Egress grants, outbound network firewall/SSRF/DNS/IPv6 with live enforceable fail-closed | PROPOSED |
| Product | Tenant/project/app management, billing ledger, per-request trace, budgets, UI error states, rate limits | PROPOSED |
| Operations | Load/crash-chaos/security testing, operational SLOs, canary rollback, release approvals and Railway production change window | PROPOSED |

## 3. Proposed next safe increments

1. Prove a **bounded** response-publication callback protocol in a
   synthetic local-only transport harness (no public listener), including
   read/revoke concurrent order, cancel and failed audit/transport.
2. Replace CI Bun.SQL quarantine semantics with a driver whose physical
   connection discard has independently verified behavior; repeat
   cross-tenant leaks and cancellation tests.
3. Exercise multiple isolated backend processes against a disposable
   PostgreSQL instance, include transaction deadlocks/timeouts and grant
   expiry under clock skew.
4. Build a durable server-only actor/session directory and redacted
   audit outbox in ephemeral staging, then run end-to-end revocation proof.
5. Only with explicit review/approval, separately plan actual public
   APIs, CPA integration, vault and network enforcement. No implicit deploy.

**Unresolved conceptual point:** Database COMMIT order is not the same
as remote HTTP receipt. A revoke-complete contract must specify whether
in-flight prior authorized responses may arrive after revocation and how
a caller learns completion. No current artifact proves remote receipt
semantics, and no staging result should be reported as such.

## 2G.4d.5a: signed local publication primitive (not a release gate)

A backend-only bounded `FOR SHARE` publication handoff now passes
disposable PG16 CI (1,802 unit tests and real writer contention).
Evidence: [stage contract](BOUNDED_PUBLICATION_HANDOFF_V1.ru.md).
This closes the **local staged-handoff vs revoker COMMIT** experiment,
but not true HTTP delivery, session/audit authority or durable publish.
The HTTP publication readiness checkbox remains **SPEC**, not VERIFIED.

## 2G.4d.5b — trusted receipt integration is still staging-only

The new `createTrustedSqlPublishedBoundary` combines synthetic
JWT/actor/RBAC, signed PostgreSQL epochs, bounded local FOR SHARE,
synchronous audit and receipt-only response; real PG16 E2E passes.
Evidence: [TRUSTED_PUBLICATION_LIFECYCLE_V1.ru.md](TRUSTED_PUBLICATION_LIFECYCLE_V1.ru.md).
The **production HTTP publication** and **durable audit** blockers
remain OPEN: independent actor stores may race, audit can exist
without durable delivery, an external callback is not a proven
atomic transport, and no physical connection discard proof exists.

## 2G.4d.6a/b — transactional actor-wide revocation and audit outbox

| Ephemeral pilot | CI proof | Status |
| --- | --- | --- |
| Private actor-wide kill switch atomically bumps tenant epochs | [PostgreSQL #38292965787](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965787); real multi-process signed FOR SHARE vs logout writer | VERIFIED ephemeral |
| Signed reader cannot SELECT/UPDATE private session registry | Migration 008 and PG16 least privilege SQL | VERIFIED ephemeral |
| Signed append-only minimal publication audit/outbox, durable on COMMIT, rollback on failure | Migration 009, [PostgreSQL #38292965787](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965787) | VERIFIED ephemeral |
| Non-superuser signed local publish creates private event and receipt only | PG16 E2E, [PostgreSQL #38292965787](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965787) | VERIFIED ephemeral |
| Individual bearer token/session revocation | Actor-wide only, no token-bound MAC | SPEC |
| Durable audit + external HTTP publish atomicity | Handoff precedes PG COMMIT; not reversible if COMMIT fails | SPEC |
| Tamper-evident cross-instance audit retention/replication | No externally secured audit trail | SPEC |

The pilot remains disconnected from production OIDC/session authority,
public SaaS HTTP, Railway, Core/Gateway, CPA and network enforcement.

## Final stage 2G.4d.6 evidence (not a production approval)

**4/4 SUCCESS on code SHA `bd96d7a038378fa30524914362013ebf06fd420f`:** [Main CI #38293380784](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38293380784) (1,815 pass, 0 fail),
[PG16 #38293380854](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38293380854) (signed actor revocation, raw RLS deny, outbox, process isolation),
[Demo #38293380672](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38293380672) and [Chromium #38293380657](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38293380657). The previous verified staging experiments
remain opt-in and isolated.

**Still NO production release:** real token-bound OIDC sessions,
one authoritative multi-instance actor directory, tamper-evident
audit storage and distribution, atomic/ordered HTTP delivery,
crash-safe SQL connection lifecycle, Vault/BYOA, CPA/Gateway,
network egress, product billing and deployment approvals remain
SPEC/PROPOSED.

## 2G.4d.7a — token-specific revocation (NOT production approval)

| Security property | Evidence | Status |
| --- | --- | --- |
| Verified bearer SHA-256 binds exact HMAC transaction | [Main CI 1,822 tests](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38296991853) | VERIFIED ephemeral |
| Same actor: revoke token A, token B remains | [Real PG16 E2E](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38296991811) | VERIFIED ephemeral |
| Raw RLS denial + earliest expiry, immutable enrollment tombstone | PostgreSQL 16 SQL assertions | VERIFIED ephemeral |
| Physical PG token-revoke writer waits for signed publication COMMIT | Independent reader/writer/observer PG16 | VERIFIED ephemeral |
| Production OIDC-backed issuance/session enrollment/rotation | Synthetic signer and privileged fixture only | SPEC |
| Monotonic production migration registry and safe rollback | Existing out-of-order replay requires 010 reapplication | SPEC |
| Token-specific, tamper-evident audit and HTTP/outbox delivery ACK | Local handoff is NOT network receipt | SPEC |
| Physical driver discard, multi-instance failover and recovery | CI quarantine only | SPEC |

Remaining gates for production include authoritative actor directory,
token/session registration API, durable audit, real HTTP transport,
Vault, CPA/Gateway, network enforcement and billing. Zero live
production endpoints, credentials, Railway, /data or Core changes.
See [TOKEN_FINGERPRINT_REVOCATION_V1.ru.md](TOKEN_FINGERPRINT_REVOCATION_V1.ru.md).

## Additional 2G.4d.7a irreversible fingerprint acceptance

Guarded staging migration 010 now includes permanent
`token_fingerprint_tombstones` so a previously spent fingerprint
cannot be re-enrolled after DELETE, revived from revoked status, or
extended to a later expiry. [Real PG16 acceptance #38297886638](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38297886638)
and [Main CI #38297886508](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38297886508)
(1,822 PASS) verified these tests, with Demo and Chromium successful.
This is not an operational retention/compliance or production-token
issuance policy; those remain **SPEC**.

## 2G.4d.7b — issuer subject authority (disposable, NOT production approval)

| Security property | Proof | Status |
| --- | --- | --- |
| Immutable issuer+subject→actor and terminal subject logout | Migration 011, SQL acceptance [PG16 #38300085282](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085282) | VERIFIED ephemeral |
| Separate NOLOGIN binding-admin and token-provisioner roles | PG16 least privilege/SECURITY DEFINER checks | VERIFIED ephemeral |
| Trusted RS256 bearer→SHA-256 digest and verified exp, no `jti` reliance | [Main CI #38300085289](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085289), 1 829 PASS, 0 FAIL | VERIFIED synthetic |
| Token A revocation preserves B, subject revocation denies B | Real non-superuser Bun.SQL E2E [PG16 #38300085282](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085282) | VERIFIED ephemeral |
| Independent reader/writer issuer-subject COMMIT serializes with FOR SHARE | Multi-process PG16 [PG16 #38300085282](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085282) | VERIFIED ephemeral |
| Production issuer session enrollment/refresh/identity store | Trusted port + synthetic keys/fixture only | SPEC |
| Production monotonic migration runner and audited rollback | Reapply 011 after 010 in CI, no live runner | SPEC |
| Durable token/subject audit + remote HTTP ACK and crash reconciliation | Local handoff and minimal outbox only | SPEC |
| Vault/CPA/Gateway, actual network enforcement and billing | Outside staging-only scope | PROPOSED |

**Exact code SHA `cade8751232b8deff40143c1ed31a8ac800194a1`**: [Main CI #38300085289](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085289), [PG16 #38300085282](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085282), [Demo #38300085311](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085311), [Chromium #38300085300](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085300) —
4/4 SUCCESS. No Railway deploy, base merge, Core/Gateway/CPA changes,
production credentials, `/data`, public SaaS routes or real AI traffic.
See [ISSUER_SESSION_ENROLLMENT_V1.ru.md](ISSUER_SESSION_ENROLLMENT_V1.ru.md).

## 2G.4d.7c — committed LOCAL audit event reconciliation, not remote delivery

| Property | Evidence | Status |
| --- | --- | --- |
| Minimal signed Allow event survives PG COMMIT; ROLLBACK removes it | 009/012 SQL and [PG16 #38302392290](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392290) | VERIFIED ephemeral |
| Bounded SKIP LOCKED claim, UUID+generation lease fencing | Real PG16 concurrent workers and SQL rollback | VERIFIED ephemeral |
| Forced backend crash discards uncommitted lease/history | Two physical connections + PG supervisor, [PG16 #38302392290](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392290) | VERIFIED ephemeral |
| Expired committed lease can be reclaimed; stale/duplicate ACK denied | 012 SQL and independent process test, [PG16 #38302392290](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392290) | VERIFIED ephemeral |
| Real trusted non-superuser receipt followed by private local audit observation | Bun.SQL E2E, [PG16 #38302392290](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392290) | VERIFIED ephemeral |
| Atomic network HTTP receipt with SQL COMMIT | Local handoff happens before PG COMMIT; irrecoverable gap | SPEC |
| Externally tamper-evident audit queue, retention and consumer | Private disposable PG only; no remote consumer | SPEC |
| Worker authentication, crash/failover SLO, scheduler/alerts, secure secrets | CI-only NOLOGIN role + privileged fixture | SPEC |

**Evidence on code SHA `1aeeb218a68ca7f0c8094d51551802205b60f224`:**
[Main CI #38302392363](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392363) — 1,829 PASS / 0 FAIL, [PG16 #38302392290](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392290), [Demo #38302392314](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392314), [Chromium #38302392437](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392437) —
4/4 SUCCESS. This does not change previous production release blockers;
see [LOCAL_AUDIT_RECONCILIATION_V1.ru.md](LOCAL_AUDIT_RECONCILIATION_V1.ru.md).

## 2G.4d.7d — synthetic post-COMMIT intent / MOCK ACK only

| Boundary | Proof | Status |
| --- | --- | --- |
| Signed Allow audit + immutable synthetic intent atomic on PG COMMIT | 013 trigger/ROLLBACK, [PostgreSQL16 #38304607719](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607719) | VERIFIED ephemeral |
| No claim before separate `reconciled_local` COMMIT | PG16 ACL/gated lease SQL | VERIFIED ephemeral |
| Stable idempotency UUID, new generation/lease on retry | PG16 SQL, Bun.SQL + fake Map receiver, [PostgreSQL16 #38304607719](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607719) | VERIFIED synthetic |
| Independent physical PG crash before claim COMMIT + SKIP LOCKED | Multi-process supervisor [PostgreSQL16 #38304607719](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607719) | VERIFIED ephemeral |
| Wrong/stale/repeated mock ACK denied; ACK rollback not durable | Signed private function/SQL [PostgreSQL16 #38304607719](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607719) | VERIFIED synthetic |
| Three attempts then terminal `retry_exhausted`, never false success | PG16 SQL acceptance [PostgreSQL16 #38304607719](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607719) | VERIFIED synthetic |
| Actual remote HTTP delivery, client idempotency and cryptographic ACK | NO payload/network; fake in-memory receiver only | SPEC |
| Local handoff before failed SQL COMMIT reconciliation | Source audit+intent both roll back despite possible emitted bytes | SPEC |
| Durable receiver dedup, queue transport, retries/dead letters/SLO | CI-only fixture, no production dispatch | SPEC |
| Externally tamper-evident audit, worker auth/multi-instance recovery | Private PG16 only | SPEC |
| Production OIDC/Vault, CPA/Gateway, egress, billing, release | Unchanged | PROPOSED |

**Evidence on EXACT code SHA `6b0bf3189c544cce21ccdfbaf58b7b2f72ba3214`:** [Main #38304607776](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607776) — 1 829 PASS /
0 FAIL, [PostgreSQL16 #38304607719](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607719), [Demo #38304607709](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607709), [Chromium #38304607769](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607769) — 4/4 SUCCESS.
This is a **synthetic intent/ACK simulation, NOT actual HTTP delivery,
NOT a production-ready SaaS release**.
See [SYNTHETIC_POST_COMMIT_DELIVERY_V1.ru.md](SYNTHETIC_POST_COMMIT_DELIVERY_V1.ru.md).

## 2G.4d.7d adversarial negative proof — NOT an HTTP release gate

Real Bun + PostgreSQL16 E2E on code SHA `e452993e14d5f9db4d86a7fa74516f6961600f2f` explicitly simulates
a local effect during a signed, uncommitted 009/013 transaction. After
SQL ROLLBACK the Allow audit and intent are both missing, yet the
simulated effect persists. [PG16 #38305618718](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38305618718)
passes this **negative proof**, showing the failure is detectable in
tests but NOT recoverable by a committed-event-only reconciliation
worker. **Remote delivery, client ACK and commit/delivery atomicity
remain SPEC / NOT PRODUCTION-READY.**

## 014 durable receiver pilot is NOT a production release gate

**IMPLEMENTED / VERIFIED in ephemeral PostgreSQL16 only** on code SHA
`a8eabe5ecc0ccbd42437bb73c6ee58286166c86d`: [PG16 #38307286153](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38307286153).
Local receiver effect/receipt is committed as one row; repeated key
returns the original receipt; synthetic fenced ACK verifies that row.
Real transport, payload durability, remote receiver identity, production
retry operations and the pre-COMMIT handoff gap remain **OPEN**.

## 2G.4d.7e opt-in commit-only event pilot — production gate OPEN

Новый staging-only entrypoint не исполняет локальную передачу
перед COMMIT, но защищает только **свой event-only путь**.
Никакой real payload, remote delivery и production wiring нет.
Отдельные реальные PG16 fault injections тестируют
pre-COMMIT ROLLBACK (нет durable intent) и неизвестный producer
outcome после успешного COMMIT (событие есть, 503 возвращён).
Создание второго логического события при caller retry ещё
не исключено. Legacy synchronous handoff и production transport
по-прежнему требуют нового решения и release/security approvals.

**VERIFIED on code commit `fa895296a6ce4062687d0ad0af77f26114d4ef03`:** [PG16 #38309259713](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259713), [Main CI #38309259929](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259929), [Demo #38309259856](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259856), [Chromium #38309259696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259696) — all 4 SUCCESS. The final documentation commit requires its own independent Actions results; code verification does not imply production readiness.


## Stage 2G.4d.7f — committed producer op replay gate (CI ONLY)

**IMPLEMENTED only for synthetic event labels**: globally unique
UUIDv4 producer key with immutable signed tenant/actor/role/collection/
canonical limit binding, transaction-scoped serialization and
committed-only replay. The original pre-COMMIT local callback and
local non-authoritative audit remain unchanged.

**OPEN production blockers:** real producer ID issuance/storage, HTTP
idempotency/recovery API, operation retention/quotas, payload digest
and encryption, dispatch-time revocation, operator unknown-outcome
settlement, remote transport/ACK and independent security approval.
A new UUID can intentionally create a second logical event.
No actual network delivery or production claim is made.

**CODE VERIFIED** on SHA `ca2503f2e22d30e64c32490c6f46bb7dd73b6dc1`:
[Main CI #38351833547](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833547),
[PostgreSQL16 #38351833550](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833550),
[Demo #38351833546](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833546),
[Chromium #38351833571](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833571) — **4/4 SUCCESS**.
The documentation commit must be checked independently on its own SHA.


## 2G.4d.7g — signed issuance + bounded status is NOT production-ready

**Staging-only implementation:** server-side generated UUIDv4,
append-only issuance tombstone, time-limited first commit (120s max
from actual DB INSERT), fixed 2h authenticated recovery window,
read-only issued/committed/expired status; no event/payload/ACK leakage.
016 does not change the legacy 015 path or its earlier public risks.

**Still OPEN:** browser/mobile/account operation ID persistence,
authenticated production issuer/status endpoint, per-actor quotas,
replay abuse budgets, safe retention/GC of tombstones, durable
payload/hash, real delivery ACK, recipient authorization, dispatch-time
revocation, audit/ops and independent security approval. No Railway,
real credentials, HTTP transport, Core/Gateway or production migration.

**CODE VERIFIED on `0d9214b8b41deb1ab97a43f71bb76bdf9d661a7d`:**
[Main CI #38354372696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372696),
[ephemeral PostgreSQL16 #38354372709](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372709),
[Demo #38354372683](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372683),
[Chromium #38354372700](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372700) — **4/4 SUCCESS**.
The final documentation SHA requires its own independent CI; this does not authorize production delivery.


## 2G.4d.7h — bounded synthetic issuer does not unblock production

**Code-only staging proof:** issuer 4 per actor / 16 per tenant per
5 minutes, status read 16 per actor / 64 per tenant per minute,
hard lifetime cap 12 per actor / 48 per tenant. All tombstones remain
append-only; actor/tenant counters mutate ONLY privately, in place.
Unknown or throttled status returns generic 404 after a committed
counter debit; no operation existence oracle is exposed by this port.

**Still OPEN / SPEC:** safe tombstone archival/GC, global rate limits,
unbounded tenant/actor identity proliferation, quotas for legacy
direct-SQL paths and reserved-commit bursts, operational cap exhaustion,
production public API, real remote delivery, durable payload, ACK,
dispatch revocation, DLP/audit and independent security approval.
A fail-closed pilot lifetime ceiling does NOT prove viable production
retention or erase the original pre-COMMIT handoff risk.


**CODE VERIFIED on SHA `64d93a034face985d07aa990085d56678e441715`:**
[Main CI #38356159803](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159803),
[PostgreSQL16 #38356159812](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159812),
[Demo #38356159923](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159923),
[Chromium #38356159948](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159948)
all SUCCESS. The final documentation commit requires independent Actions on its own SHA.


## 2G.4d.7i — retention / legacy hard stops do not unlock production

**IMPLEMENTED only on disposable PG16:** new 018 immutable
INSERT ceilings and successful-write budgets for 015/016 private
records, legacy direct-016 issuance/status metering, denied
TRUNCATE and private capacity view with `gc_permitted=false`.
018 must run last after any privileged replay of 015–017.

**OPEN / SPEC:** no physical archive, external non-reuse witness,
safe GC, capacity restoration after 12/48 or 64/256 lifetime caps,
test against hostile DB owner, tamper-evidence/retention,
complete 009/legacy request-attempt quotas, true edge/global
throttling, signed production HTTP APIs, durable payload and
recipient ACK, dispatch-time revocation, real business/privacy
deletion and independent security/release approvals.
Old pre-COMMIT local handoff remains a production blocker.


## 2G.4d.7j — offline archive witness is NOT a GC gate

**Code-only VERIFIED (disposable CI):** hashed UUID commitments,
offline Ed25519 signatures, pinned latest job-local checkpoint,
monotonic chain, actual PostgreSQL pre-COMMIT invisibility/crash
ROLLBACK, simulated stale restore detection. No raw operation IDs
or customer payloads in signed files.

**Production gates remain OPEN:** separately owned durable witness,
tamper-evident out-of-DB key custody, trusted latest checkpoint
across crashes/failover, atomic database-to-archive cutover,
real PITR/restore verification, non-reuse checks on ALL future
issuance, key rotation, GC/retention/privacy signoff, physical
capacity restoration and external security approval. Old
pre-COMMIT handoff, global quotas, actual transport and ACK
remain unresolved. No archive deletion or migration 019.

**CODE VERIFIED on `66019cd7602d256148562eafd304e9712a2d907b`:** [Main CI #38363925445](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925445), [ephemeral PostgreSQL16 #38363925442](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925442), [Demo #38363925450](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925450), [Chromium #38363925440](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925440) all SUCCESS. Final docs SHA needs its own Actions. No production release claim.


## 2G.4d.7k — full dump/restore regression is not safe archive approval

**IMPLEMENTED only for ephemeral CI:** fsync/rename pinned
witness head, independently reopened signed history, fresh
process continuity, real full `pg_dump`/two isolated
`pg_restore` databases, strict UUID-set matching, stale
restore DENY, complete restore PASS and crash-to-pending
fail-closed verification. These tests do not alter 015–018
or delete identifiers.

**OPEN / SPEC:** durable independently administered
anti-rollback witness across physical hosts, atomic
database-to-witness commit protocol, evidence of all
post-COMMIT unswept IDs, physical PITR/WAL/replica recovery,
multi-node failover, adversarial operator compromise,
external key custody, quota capacity recovery and safe
archival/GC. Source database and CI witness are on one
runner/service; `gcPermitted=false` remains mandatory.
Old pre-COMMIT handoff, production HTTP, payloads and ACK
remain release blockers.

**CODE VERIFIED at `9af3b8d5b29ebceb6a433468c650f01be913a148`:** [Main CI #38367994239](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994239), [ephemeral PG16 #38367994247](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994247), [Demo #38367994191](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994191), [Chromium #38367994196](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994196) — **4/4 SUCCESS**. The final documentation HEAD must pass its own CI; no archive/GC/deployment authorization.


## 2G.4d.7l — third local high-water file still NOT durable witness

**IMPLEMENTED only in synthetic PG16 CI:** two offline
signed witness verifier processes with independently fsynced
local heads, third local high-water journal with monotonic
links and a publication lock, DENY for partially published
heads, missing/torn journal, double replica rollback, and
unsigned real PG COMMIT. CI explicitly checks the negative
counterexample: all three local files plus old projection
can rewind together and still pass internal consistency.

**Production gates remain OPEN:** separately managed durable
high-water with WORM or equivalent independent rollback
resistance, multiple hosts/trust domains, issuer-level
non-reuse fence after PostgreSQL restore, transactional
PG-to-witness outbox protocol with unknown-outcome settlement,
actual PITR/failover/partition tests, true live projection
binding, key rotation and custody, retention/privacy signoff
and explicit security authorization for any archive/GC.
No deletion, migration 019, real delivery or Railway.


## 2G.4d.7m — detected COMMIT gap is not settled production delivery

**Stage-only proof:** a real PostgreSQL connection drops before
and after COMMIT; the offline witness refuses missing UUID,
unsigned post-COMMIT identity and partially published
signed heads/high-water until the exact signed successor is
available. A matching local proof DOES NOT grant a sender
retry, production issue/status result, GC or external ACK.

**Production OPEN / SPEC:** independently operated durable
off-host witness and anti-rollback high-water, authority for
the prepared tenant/actor/role binding, fenced/atomic
PG-commit-to-witness settlement, uncertain commit resolution
during partitions and lag, immutable WORM/non-reuse across
actual PITR and host failover, external payload/delivery/ACK,
privacy retention, pre-COMMIT handoff remediation and final
independent security signoff. SQL 015–018 unchanged.


## 2G.4d.7n — separate local IPC process is not an external witness

**Disposable code only:** separate Unix-domain socket signer with
no PostgreSQL credentials, canonical Ed25519 checkpoint and
signed receipt, single-writer expected-head CAS, durable-to-runner
fsync and identical lost-ACK replay across process restart.
Pending checkpoint before head publication fails closed.
All immutable 015–018 SQL remains unchanged.

**Production gate OPEN:** separate host/operator/credential
authority and physically durable rollback-resistant trust root;
independent source authenticity (PG signed current snapshot,
issuer tenant/actor scope), true cross-system fenced COMMIT,
network partition/consensus recovery, persistent key rotation,
actual PITR/WAL failover, real delivery/recipient ACK, privacy
retention/GC approval and security review. No API, deployment,
reuse, archive or quota relief.


## 2G.4d.7o — signed least-privilege projection not production attestation

**CI-only implemented:** restricted PG16 `operation_id` SELECT,
repeatable-read projection, separate ephemeral Ed25519 source
signature, nonce+predecessor+database binding, offline
exact signed-witness projection matching, forged source
and revoked privilege DENY. A PG transaction snapshot
descriptor is only context, **not trusted WAL/LSN proof**.

**Production still OPEN:** independent attestor host/key and
trusted database/source integrity; durable nonce/root across
runner rollback, attestation enforcement inside all witness
append/issuer paths, authorized actor/tenant/role, fenced
atomic PostgreSQL COMMIT→external signed head, genuine
PITR/network partition/failover and remote delivery/ACK,
privacy/legal/GC/capacity sign-off, real API readiness
and independent security review. No SQL 019 or production.


## 2G.4d.7p — source-bound append is a CI security proof only

**IMPLEMENTED staging:** the opt-in protected Unix-socket path
requires a fresh daemon-issued challenge and Ed25519 projection
proof from pinned read-only PG16 projector before signing a
successor. Persisted proofs are revalidated at startup; identical
ACK-loss replay is supported. Raw client projection append is
refused in protected mode; legacy 7n test mode remains separate.

**STILL BLOCKED:** independent durable off-host witness and trusted
head, out-of-runner nonce/key custody and source integrity, full
issuer/actor auth, atomic/fenced COMMIT→witness publication,
UNKNOWN-COMMIT/PITR/WAL/replica promotion and network recovery,
durable outbound delivery+recipient ACK, signed retention/non-reuse
and security release approval. No independent host or production
security guarantee, no deletion/GC/cap reset.


## 2G.4d.7q — локальный high-water журнал не заменяет durable external witness

**IMPLEMENTED in disposable CI:** подписанный второй локальный
journal head, mutual public-key pins, monotonic source-attested
successors, две fsync-публикации до положительного IPC ACK, fail-closed
на partial rollback, issuer/witness crash или недоступный journal.
Старые 7n/7p standalone эксперименты остаются неизменными.

**OPEN production gates:** оба ключа и хранилища разделяют одного
runner/OS администратора и могут быть вместе откатаны; нет external
durable trusted head, independent source/actor authority, полноценного
anti-replay вне runner, atomic/fenced COMMIT↔witness, доказуемого
UNKNOWN recovery, WAL/PITR/replica promotion, partition resilience,
durable outbound delivery и authenticated recipient ACK.
Требуются отдельные privacy/retention/security gates.
No GC, UUID reuse, physical tombstone deletion or cap reset.


## 2G.4d.7r — observation после UNKNOWN не завершает recovery

**CI-only implemented:** offline без PG credentials сверяет
подписанный PG16 source, direct witness checkpoint и signed
local high-water для заранее подготовленного UUID commitment.
Physical pre-/post-COMMIT backend termination, lost ACK,
crash, stale pin, signature forgery и multiple COMMIT DENY
дополняют прежние 7l–7q проверки.

**Production release gate остаётся OPEN:** все локальные статусы
являются только observations, никогда не actor-authorized
settlement/retry/delivery/GC. Нужны независимый внешний
WORM/trusted head с удалённой key custody, rollback-resistant
nonce/anti-replay, fenced/atomic PostgreSQL COMMIT, безопасное
разрешение orphan journal / partition / PITR / WAL / failover,
production OIDC/issuer authorization, delivery ACK и privacy
retention sign-off. No migration 019, no production, no GC.


## 2G.4d.7s — CI-only reviewer pin is not independent manual settlement

**Staging implemented:** третья синтетическая подпись head
(Ed25519 reviewer), direct reviewer pin predecessor и
read-only classification of stale/rolled-back/split signed
witness and local journal. Concurrent destination writes
are exclusive. Manual review is required even on matched pin;
repair/retry/delivery/reissue/GC remain strictly denied.

**Production still BLOCKED:** reviewer pin/root на том же CI runner,
не off-host или WORM, нет human/operator trust process,
PG signed WAL/LSN settlement, atomic fencing, cross-host
consensus, safe orphan/manual recovery process, PITR/failover/
network partition, external recipient ACK or issuer-actor auth.
Joint rollback of reviewer + both local roots remains undetected
after loss of a newer independent pin. No SQL 019, deployment,
UUID reuse/archive, tombstone deletion or GC.


## Stage 2G.4d.7t — synthetic external receipt does NOT prove off-host custody

**CI implementation:** offline signed contract verifier binds
authority/key/epoch/logId/challenge, source-attested witness
head, local journal receipt, previous external signed receipt,
and user-retained minimum. Synthetic signer and all storage
still run on SAME ephemeral GitHub Actions host; statuses
are read-only manual-review hints, `offHost` and
`independentDurability` always FALSE.

**OPEN release gates:** independently administered remote
signer/HSM and monotonic WORM storage, separately retained
client high-water with unforgeable anti-replay/equivocation,
mTLS authorization, failover/partition/restore verified
audit trail, fenced atomic PostgreSQL COMMIT→remote witness,
manual-only orphan reconciliation, producer actor/tenant
authorization, delivery/recipient ACK, privacy/retention
and full security sign-off. No production/deploy/SQL019,
UUID reuse/delete, archive, receipt-delivery release,
auto-recovery or GC.
