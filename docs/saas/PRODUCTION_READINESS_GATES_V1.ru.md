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
