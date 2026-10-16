# Stage 2G.4d.7a — signed per-token revocation (staging only)

**IMPLEMENTED / VERIFIED** in disposable PostgreSQL 16; production
OIDC, SaaS HTTP and remote delivery remain **SPEC / PROPOSED**.

**Code SHA:** `772a29be5b855f31e65e28b30144adddbe776bb1`.
Evidence: [Main CI #38296991853](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38296991853)
(1,822 Bun PASS / 0 FAIL, ESLint, TS and Vite),
[PG16 #38296991811](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38296991811),
[Demo #38296991833](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38296991833)
and [Chromium #38296991887](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38296991887):
**4/4 SUCCESS** on that code SHA.

## Design and threat boundary

A trusted server verifies the **full pinned RS256 at+jwt bearer** and
issuer+subject actor mapping, then computes SHA-256 over the exact
signed bearer string. This digest is NOT obtained from untrusted JWT
`jti`, route parameters, headers or actor claims. It is never returned
to an HTTP caller, audit receipt or SQL row projection.

Explicit opt-in `requireTokenBoundSession:true` needs a signed
authorization revision source and a private registered token record.
The signed PostgreSQL HMAC now binds
`actor/tenant/txid/expiry/fingerprint` using CHR(31), and the sixth
`SET LOCAL` field carries only the hash. The session-bearing scope
is frozen and propagated through initial/final revision checks and
the bounded `FOR SHARE` publication barrier. Never-enrolled
synthetic actors retain backward-compatible 4-field HMAC ONLY.

Guarded disposable migration
`staging/saas-rls/010_token_fingerprint_scope_pilot.sql` creates a
private `actor_token_sessions` registry for fingerprint, actor, expiry
and active/revoked status. Row triggers version ALL current member
tenant epochs in the same transaction as registration/revocation.
A permanent private `token_bound_actor_tombstones` row makes legacy
downgrade impossible even after deleting every token and
deleting/re-creating the actor. Unprivileged app readers cannot
read/write private token rows, tombstones, or signer keys.

Every authenticated RLS gate validates the exact signed actor,
registered token fingerprint and clock expiry. The signed revision
state conservatively includes the earliest **token OR grant**
expiry, preventing time-only expiry from authorizing stale output.

**Migration ordering:** 001→010 MUST be monotonic. The CI deliberately
replays 006 after initial 010 installation and then reapplies 010 as
the final version before acceptance. Out-of-order replay of an old
migration can overwrite the token-aware revision function; a
production migration registry must forbid this. No live migration
is authorized.

## Verified adversarial cases

- Two synthetic, valid RS256 bearer tokens for the SAME actor yield
  different hashes; token A revoke denies A and advances tenant
  revision, while token B still gets signed receipt-only publication.
- A previously valid 4-field actor-only HMAC cannot downgrade an
  enrolled actor. Substituting B's hash into A's HMAC fails.
- PostgreSQL direct signed RLS SELECT, authorized revision and
  publication barrier deny revoked token A; unsigned/invalid JWT
  cannot acquire a SQL connection.
- Token expiry by time (without SQL mutation) denies after deadline,
  with the raw tenant revision unchanged.
- Token deletion AND actor ID re-creation cannot undo the private
  enrollment tombstone. Synthetic test transactions roll back.
- Independent physical PG reader/writer/observer: a token-specific
  revoke COMMIT must wait on the reader's signed `FOR SHARE`
  publication lock. After COMMIT, the signed token is denied.
- Minimal signed outbox remains append-only/durable on successful PG
  COMMIT, with no SQL rows or bearer in public receipts.

## Unimplemented production requirements

Issuer-controlled session registration/renewal and OIDC/JWK rotation;
one authoritative actor/subject mapping shared by all instances;
migration downgrade/rollback management; tamper-evident,
token-specific durable audit reconciliation and network delivery ACK;
clock skew bounds, crash-safe driver connection destruction, HTTP
backpressure/retry and multi-instance failover; Vault, CPA/Gateway,
egress firewall and billing. A synchronous local handoff before a
failed SQL COMMIT cannot be undone, and database ordering is NOT
proof of remote receipt. No production credentials, Railway, /data,
Core/Gateway/CPA, real proxy/egress or merge were touched.

## 2G.4d.7a hardening — used fingerprint is never reusable

**IMPLEMENTED / VERIFIED** in disposable PG16, code SHA
`38dc64e466a119000b0067e4f5e74217c96dabfb`:
[PostgreSQL16 #38297886638](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38297886638),
[Main CI #38297886508](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38297886508)
(1,822 PASS, 0 FAIL), [Demo #38297886653](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38297886653),
[Chromium #38297886773](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38297886773)
— four of four SUCCESS.

The private `token_fingerprint_tombstones` table permanently records
each previously enrolled SHA-256 fingerprint and its original actor,
including after the active token row is deleted. A privileged fixture
writer cannot `DELETE` + `INSERT` an old fingerprint, migrate it to
another actor, update `revoked` back to `active`, or extend
`expires_at` for an enrolled token. Shortening expiry is allowed.
Direct reader/CI app table access remains denied. Synthetic PostgreSQL
adversarial acceptance asserts these failure paths and rollback;
actual Bun.SQL two-token E2E continues to pass.

These tombstones are deliberately *not* a production token directory,
issuer, key vault or tamper-evident audit log. Their lifetime,
retention/compliance requirements and disaster recovery remain
production SPEC. Never store raw bearer strings in this registry.

## 2G.4d.7b — authoritative issuer-subject layer above token fingerprint

Migration 010 fingerprint ownership remains irreversible. New migration
011 additionally demands a pre-pinned issuer+subject binding for
issuer-enrolled token rows and terminal SUBJECT revocation. It denies
still-active token rows after subject logout and permanently prevents
legacy issuerless token enrollment for pinned actors. The app-side
provisioning module validates exact signed RS256 bearer and verified
expiry, never trusts JWT `jti`, and only passes a hash to a private
writer capability. No real issuer provisioning credentials or public
API exist. Details:
[ISSUER_SESSION_ENROLLMENT_V1.ru.md](ISSUER_SESSION_ENROLLMENT_V1.ru.md).
