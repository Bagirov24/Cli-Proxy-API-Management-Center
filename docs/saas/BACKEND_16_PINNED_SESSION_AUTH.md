# Backend 16.2 — pinned JWT and bearer-bound private session port

**Status:** unmounted and default-off. Test JWTs have real synthetic RSA-2048 signatures, but the session authority is a TEST DOUBLE. This is not evidence of an actual IdP, PostgreSQL identity, Railway deployment, authorized user session or production readiness.

## Reused trust boundaries

The repo already has:
- **operatorPinnedOidcAccessVerifier.ts**: exact operator-pinned HTTPS issuer, intended OAuth resource audience and curated RS256 public JWKS; no network discovery/dynamic keys
- **trustedAccessToken.ts**: validates signature, JWT typ=at+jwt, issuer/audience, nbf/iat/exp, and bounded lifespan
- **verifiedSubjectBinding.ts**: domain-separated SHA-256 of a cryptographically verified issuer+subject only, never client claims
- **backend16PrivateTenantProjectRead.ts**: unmounted /internal/saas/v1 handler with independently supplied authenticate() and readAuthorized() ports

Backend16.2 adds **backend16PinnedSessionAuthenticator.ts**, implementing only the first of these two ports. It fails startup on missing/invalid public OIDC trust material, and for each request:
1. Verifies the raw bearer JWT through the pinned RS256 verifier before any session lookup; malformed, expired, wrong typ/audience/issuer/signature/key tokens fail closed
2. Calculates separate SHA-256 fingerprints of the verified issuer+subject and the **exact signed raw bearer JWT**. It does not forward raw bearer, tenant ID, actor ID, requested role or PG login to the session source
3. Requires an operator-supplied resolveCurrent() authority to attest a current enrollment and session by exact issuer + **both** fingerprints + bounded verified expiry; its response must echo these without mismatch
4. Rejects reserved-looking logins, bad UUIDs, expired/excessive session lifetimes, cancellation, provider errors and stale fingerprints without retry or revealing secrets
5. Returns a frozen minimal principal with effective expiry = **min(verified JWT expiry, DB session expiry)**, ensuring a valid-but-expired login or signed JWT cannot prolong a session

Two signed JWTs for one OIDC subject are **not interchangeable**, because the digest of each complete bearer is distinct. This increment adds no SQL, migration, listener, dynamic JWKS fetch, OAuth callback, session issuance, user provisioning, credentials or Railway changes.

## Boundaries still unproven

A TypeScript session snapshot is **not cryptographic proof** that PostgreSQL accepted the principal. The injected current-session authority is deliberately NOT implemented here. It must be backed by the private durable enrollment/session source and must never trust JWT tenant_id/role or a stale cache. The string role-name guard alone cannot establish PG rolsuper, rolbypassrls, role memberships or physical session_user.

The separate readAuthorized() port must independently use a **physical per-principal LOGIN connection** (not operator postgres, the sealed schema migrator, a shared NOLOGIN role, SET ROLE impersonation, or client-selected tenant GUC). Inside one bounded READ COMMITTED transaction it must revalidate current SQL0007 tenant ACL/CAS revision, active session and binding under FOR SHARE with FORCE RLS on saas_data tenants/projects. PostgreSQL READ ONLY transactions reject FOR SHARE; enforce a server-owned SELECT allowlist and physical role permissions instead, as documented in BACKEND_16_PHYSICAL_PG_ADMISSION.md. Abort, driver uncertainty, failed rollback/release, or UNKNOWN COMMIT means fail closed, quarantine and never replay. A mandatory external redacted audit must be proven before a real HTTP request can be published.

The permanent Railway staging PG16 already has Backend15 SQL0007 according to prior positive evidence. There is no operator-enrolled Backend16 OIDC login, no live session authority, no deployed saas-control-api and no production SaaS traffic. **This PR does not apply or replay SQL0007** or touch production Core/Gateway and /data.

## CI scope and remaining release gates

The dedicated **SaaS Backend16 Private Read Contract** workflow now exercises both the 16.1 HTTP and 16.2 pinned-session tests plus full repository TypeScript. Tests generate real RSA-2048 signed synthetic at+jwt tokens to cover issuer/audience/typ/key/signature tampering, expiry, distinct JWT fingerprints, authority receipt mismatches, abort, errors, and DTO redaction. **The session lookup is a fake; these are NOT live PG16 nor external OIDC E2E tests.**

Before enabling the feature even on private staging:
- Independently approve a real IdP issuer/audience/JWKS trust lifecycle, subject enrollment and revocation
- Implement per-principal PG physical connection selection, role-flag verification and subject/session/grant SQL0007 readback, with two different logins/tenants and revoke/cancellation races on real PostgreSQL16
- Validate authoritative multi-instance session freshness, durable redacted audit, physical connection discard, recovery/PITR, ingress/egress isolation and canary rollback
- Use the production readiness gate checklist in PRODUCTION_READINESS_GATES_V1.ru.md; do not mount this handler or assert production readiness based on mock tests or TypeScript types
