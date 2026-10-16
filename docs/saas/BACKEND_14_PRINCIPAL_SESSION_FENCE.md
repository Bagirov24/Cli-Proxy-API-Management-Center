# Backend 14 — private PG16 principal session fence (Phase A)

**2026-10-16. This is SQL + disposable PostgreSQL16 CI, NOT live OIDC or a public SaaS API.** The current permanent SaaS staging already has migration 0000–0005; migration 0006 is **not** applied by merging this PR.

## Isolated, non-production boundary

Railway project `a9703851-6eb1-406c-bb15-7d3a89359fb7`, staging environment `b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b`, dedicated PostgreSQL16 `37f8f166-75a6-4617-b243-8e681181c16d`, private `postgres.railway.internal:5432/saas_staging`. Current `saas_schema_migrator` is `NOLOGIN PASSWORD NULL`; SaaS Control API is disabled/unmounted. No public TCP/HTTP endpoint, live tenant credentials or customer data.

User waived backup/PITR **only for disposable staging tests**, accepting data loss. This waiver does not apply to production, CPA Core/Gateway, `custom-no-apikey-fun`, `/data`, real OAuth accounts, provider keys or customer records.

## Migration 0006: deny-all until a real session exists

File: `staging/saas-bootstrap/0006_principal_session_fence.sql`, reviewed SHA256 to be pinned on final commit. Requires exact PostgreSQL16 staging database, explicit `saas.staging_only=true`, a true non-superuser `saas_schema_migrator` session, and exactly five prior SHA-attested migration receipts (0005 must match `b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556`). It refuses any existing session schema or replay and atomically appends receipt 0006. **UNKNOWN COMMIT => STOP; inspect independently, do not retry.**

Creates private schema `saas_identity` with:
- `principal_sessions`: a UUID session, authenticated PostgreSQL login, tenant, **authorization grant revision**, opaque identity-binding UUID, short expiry, monotonic session revision and irreversible revoked timestamp. **No JWT, cookie, token, password, OAuth code, raw subject or provider secret.**
- At most **one unrevoked session per PostgreSQL login**; expired sessions still require an explicit operator revoke before reissue. This never authorizes a shared HTTP-to-DB login impersonating arbitrary users.
- `session_events`: transaction-atomic issue/revoke audit with operator and reason, mutation/truncate blocking triggers. **Not WORM**; database superuser can bypass triggers.
- Operator-only `SECURITY INVOKER` functions for issuing and revoking, requiring both `session_user` and `current_user` = `postgres`. Issuance enforces an active grant, exact access revision, restricted LOGIN membership and a maximum **15-minute TTL**. The opaque identity-binding UUID is an operator-supplied reference, *not independent proof of OIDC verification*. No app/runtime role gets schema USAGE, direct table access or operator function EXECUTE.

Replaces `saas_acl.can_read_tenant(uuid)` with a narrow `VOLATILE SECURITY DEFINER` that still trusts authenticated PostgreSQL `session_user`, never attacker-controlled `saas.tenant_id`, JWT claims or `SET ROLE`. In addition to the existing ACL grant and `FOR SHARE` lock it requires one unexpired, unrevoked private session for **the exact tenant and grant revision**, with a second `FOR SHARE` fence. Grant revoke/regrant invalidates the previous revision's sessions. Existing tenants/projects stay **FORCE RLS and SELECT-only** with no new app write privileges.

A successful DB session revoke only gates future database statements once a conflicting authorized transaction completes. It **does not** guarantee cancellation of already sent network responses, independently verify OIDC, or make a per-user HTTP connection pool safe.

## CI acceptance

`scripts/saas-staging/verify-backend14-session-pg16.sh` is allowed only on GitHub Actions against disposable loopback `saas_staging_ci` after Backend13 fixture tests. It confirms the six receipts/catalog contracts and rejects replay/pilot DB. A real restricted PostgreSQL LOGIN with synthetic tenant fixture proves: deny before session; tenant scope and rejection of spoofed GUC/SET ROLE; time expiry; explicit tombstone before replacement; blocked concurrent revoke while reader holds `FOR SHARE`; CAS stale revision denial; inaccessible private session/audit; grant-revoke/regrant cannot resurrect an old session; and no tenant writes. No live Railway staging SQL is applied as part of this CI.

## Next production-critical gates

1. Separately verified real OIDC/PKCE issuer adapter: exact trusted issuer/audience/redirect, JWKS rotation, signature and nonce, CSRF and clock handling.
2. Server-only identity binding, approved DB login provisioning/revocation (or independently proven signed scope) and physical connection discard; **no shared LOGIN** for arbitrary HTTP tenants.
3. Transactional and off-host tamper-evident audit, response/COMMIT uncertainty reconciliation, multi-process revocation and transport testing.
4. PITR + **verified restore** before any non-disposable customer data; independent security/ops sign-off before public SaaS or Core/Gateway integration.

No public SaaS listener, real user login, production migration or existing Core deployment is authorized by this phase.
