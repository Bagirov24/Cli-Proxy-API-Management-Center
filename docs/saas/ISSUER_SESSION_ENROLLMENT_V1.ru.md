# 2G.4d.7b — issuer/subject-controlled token enrollment and revocation

**IMPLEMENTED / VERIFIED exclusively in synthetic ephemeral PostgreSQL 16.**
Code SHA `cade8751232b8deff40143c1ed31a8ac800194a1`; [Main CI #38300085289](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085289) (1,829 Bun PASS, 0 FAIL; ESLint, TypeScript,
default-off Vite), [PostgreSQL16 #38300085282](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085282), [Demo #38300085311](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085311), [Chromium #38300085300](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085300) — **4/4 SUCCESS**.

This is **not a production OIDC issuer, managed authentication provider,
session credential, HTTP handler or deployable database migration.**

## Why this stage exists

Stage 2G.4d.7a introduced exact verified-bearer SHA-256 fingerprints and
terminal per-token revocation, but privileged CI fixtures still inserted
token records using only an actor ID. There was no independent database
proof that the token belonged to a specific pinned issuer+subject.

Migration
`staging/saas-rls/011_issuer_subject_enrollment_pilot.sql`
adds immutable issuer/subject→actor authority and two distinct,
NOLOGIN/no-BYPASSRLS PostgreSQL capabilities:

- `saas_issuer_directory_admin`: may call only private
  `pin_verified_subject(issuer,subject,actor)` and
  `revoke_verified_subject(issuer,subject)`; cannot enroll tokens,
  inspect private directory, or obtain token/signing secrets.
- `saas_issuer_provisioner`: may call only private
  `enroll_verified_token(issuer,subject,actor,fingerprint,exp)` and
  `revoke_verified_token(issuer,subject,fingerprint)`. Enrollment
  requires an existing **active** immutable binding and matching
  actor, active actor session, canonical SHA-256 and a bounded expiry
  (no later than 900 seconds). Provisioner cannot bootstrap a binding.
- `saas_ci_runner` / `saas_rls_reader`: cannot call provisioning
  functions, SET ROLE to these isolated NOLOGIN capabilities, SELECT
  the private tables or read the HMAC signer secret.

These SQL functions are SECURITY DEFINER with fixed search paths,
bounded arguments and private tables. SQL roles are not production
credentials. The E2E uses an ephemeral PostgreSQL superuser **only
to SET LOCAL ROLE** in a disposable fixture, not in the app SQL pool.

## Trusted server boundary

`issuerSessionProvisioning.ts` accepts a separately configured,
pinned RS256 `AccessTokenVerifier`, trusted server issuer/subject→actor
directory and an injected private writer port. Only AFTER verifying
the complete API bearer (correct `typ:at+jwt`, signature, issuer,
audience, expiration) does it compute SHA-256 of the **exact signed
bearer string**, recheck the actor directory after the async digest,
and pass a frozen record containing ONLY
`issuer,subject,actorId,fingerprint,expiresAtSeconds` to the writer.

JWT `jti`, custom actor/role/tenant claims and client headers never
become actor/session authority. Missing verifier-supplied expiry,
stale directory, invalid JWT, wrong audience, writer failure or
missing capabilities all deny without exposing secrets or database
details. A separate admin bootstrap must pin the issuer+subject
before any token-holder may enroll or revoke it. There is no public
API, login, cookie, refresh-token storage, or live issuer call.

## Private PostgreSQL authority and linearization

- `issuer_subject_bindings` fixes one issuer+subject to one actor.
  Rebinding, deletion, or revoked→active transitions are forbidden.
  `issuer_bound_actor_tombstones` survives token deletion and actor
  ID recreation and forbids legacy actor-only/issuerless token scope.
- `actor_token_sessions.issuer` and `.subject` are immutable
  once set; a direct issuerless token INSERT for an enrolled actor
  is rejected. Legacy 010 fixture rows remain usable only for actors
  that have NEVER pinned issuer identity.
- The 011 signed scope gate checks the same actor, HMAC, transaction
  ID, fingerprint and expiry as 010 AND requires an active immutable
  issuer+subject binding matching the token's actor. A revoked subject
  makes even an otherwise active token unavailable for raw RLS,
  signed revision, FOR SHARE publication and audit.
- Individual token revoke commits through the existing 010 token
  trigger; subject revoke has its own transaction-level epoch trigger.
  Both advance all affected tenant revisions in deterministic order,
  using the 007 signed publication `FOR SHARE` lock. Replay/no-op
  revoke does not issue a second revision update. ROLLBACK restores
  state and revisions in one database transaction.
- The 010 fingerprint and actor enrollment tombstones still prevent
  token resurrection, expiry extension and actor downgrade.

**Migration order is critical:** apply 001→011 monotonically.
CI intentionally tests replay of old 006/010 and therefore reapplies
011 LAST before new acceptance. Replaying 010 after 011 would restore
an older, weaker `scope_verified()` implementation; production MUST
forbid out-of-order migrations with an independent registry, reviewed
rollback plan and deployment gates. This staging SQL is guarded by
`saas.staging_only=true` and disposable DB/role names.

## Real acceptance evidence

- 7 additional synthetic Bun unit tests prove verified digest,
  forged `jti`/actor/role rejection, independent token fingerprints,
  immutable writer input, issuer/actor directory drift, explicit
  revocation, signed expiry and generic fail-closed writer errors.
- Real PostgreSQL 16 SQL runs the same test through three privilege
  domains, verifies immutable subject ownership, no cross-subject
  revoke, duplicate rejection, limited expiry, direct legacy
  downgrade denial, rollback and table/function ACLs.
- Actual least-privileged Bun.SQL receipt-only E2E registers two
  distinct pinned RS256 bearer tokens for the SAME issuer+subject
  using separate privileged fixture capabilities. Revoke token A:
  A denied / B allowed. Revoke subject: B denied, even while token B
  is still individually active. Denied requests add no forged Allow
  audit/outbox events or leak SQL rows, JWTs, fingerprints or subjects.
- Independent PostgreSQL processes prove SUBJECT-revoke writer
  COMMIT waits while earlier signed publication holds FOR SHARE;
  after subject COMMIT its active token is denied. Previous
  token-specific/actor-wide revocation, canceled backend, audit
  and cleanup regressions also remain green.

## Production release blockers

This is a **trusted server provisioning port plus CI-only PostgreSQL
roles and fixture**, not a real OIDC issuer-initiated lifecycle.
It needs an externally verified multi-instance directory, durable
issuer-driven session creation/renewal/logout (including already
expired bearer revocation and token rotation), a securely authenticated
non-superuser provisioning adapter, secret rotation, production
migration registry and deployment approval.

No remote HTTP delivery/ACK, tamper-evident multi-instance audit,
token-specific durable outbox reconciliation, physical Bun.SQL
connection-retirement certification, failover SLO, rate limiting,
Vault/CPA/Gateway, real network/egress enforcement or billing is
implemented. The existing local synchronous handoff may execute
before PG COMMIT and cannot be retracted if commit fails; a PostgreSQL
serialization proof is **NOT a remote client receipt guarantee**.
No Railway, production OAuth, Core/Gateway/CPA, credential/data,
`/data`, management.html, public SaaS endpoints, proxy/VPN/egress
or real AI traffic was touched.

See [TOKEN_FINGERPRINT_REVOCATION_V1.ru.md](TOKEN_FINGERPRINT_REVOCATION_V1.ru.md)
and [PRODUCTION_READINESS_GATES_V1.ru.md](PRODUCTION_READINESS_GATES_V1.ru.md).
