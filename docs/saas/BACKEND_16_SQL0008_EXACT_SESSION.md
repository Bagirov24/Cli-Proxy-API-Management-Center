# Backend16.4 — SQL0008 exact subject/session/binding gate

**Scope:** isolated Railway PostgreSQL16 staging (saas_staging) and disposable GitHub PostgreSQL16 CI (saas_staging_ci) ONLY. NOT live CPA Core/Gateway, any production database, pilot saas_rls, OAuth provider, API listener or real tenant enrollment.

**Status:** guarded proposed migration + disposable PG16 acceptance. SQL0008 is NOT automatically applied to Railway when merged. NO service-start migration or replay.

## Purpose and security contract

SQL0007 verifies current tenant grant, authenticated physical PostgreSQL LOGIN, live session and operator-enrolled subject binding. Its private SECURITY DEFINER boolean function can_read_tenant(uuid) cannot check the **exact** OAuth-authenticated sessionId, bindingId and server-computed issuer/subject digest. Backend16.1–16.3 intentionally do not publish tenant or project data.

SQL0008 adds exactly one function:

    saas_acl.exact_subject_session_authorized(
      p_tenant uuid, p_session uuid, p_binding uuid, p_subject_sha256 text
    ) RETURNS boolean

It is VOLATILE SECURITY DEFINER, owned by the isolated non-superuser schema migrator, fixed search_path (pg_catalog, pg_temp), and grants EXECUTE only to NOLOGIN runtime reader/writer templates. It never returns private rows, tenant metadata, OIDC claims, tokens or secret material. No new LOGIN, identity, session, project, RLS policy, DML grant, HTTP listener, provider secret or runtime schema USAGE is created.

The server MUST validate the signed access JWT with its reviewed pinned issuer, audience, time, JWKS and session authority before computing the domain-separated SHA256(issuer + NUL + verified subject). The DB does NOT cryptographically verify OIDC claims or exact raw bearer fingerprint. A verified subject digest is not by itself a valid session.

## Locking and exact identity

The function checks the real authenticated PostgreSQL session_user, which is unchanged by SET ROLE, rejects privileged, BYPASSRLS, CREATEROLE, CREATEDB and REPLICATION roles, and requires the correct reader/writer membership plus isolated staging DB.

A single transaction holds row locks in order:
1. Active tenant ACL for the exact session_user; capture current access_revision with FOR SHARE.
2. The specified sessionId AND bindingId for the same LOGIN, tenant, grant revision, unrevoked, unexpired; FOR SHARE.
3. The specified bindingId AND verified subject digest for the same LOGIN, tenant, revision, active and unrevoked; FOR SHARE.
4. Recheck expiry before returning TRUE. All mismatches and old sessions return FALSE, without tenant existence disclosure.

These FOR SHARE locks block revoke COMMIT until the admitted SQL transaction ends. They do not retract previously delivered HTTP responses. PostgreSQL refuses FOR SHARE in a READ ONLY transaction; callers must use bounded READ COMMITTED with an allowlisted sequence of read-only queries and least-privilege DB permissions. The exact gate and later FORCE RLS SELECT MUST execute under the same authenticated physical connection and transaction with known COMMIT acknowledgement. Unknown COMMIT => quarantine, destroy the physical backend, never retry.

## Migration controls

Only a separately audited one-shot installer can provision the temporarily unsealed saas_schema_migrator login, apply SQL0008, verify the eighth receipt and catalog, then restore NOLOGIN/password-null. SQL0007 SHA-256 stays pinned at:

    1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0

The SQL0008 runner separately attests its own exact-byte SHA256 and reviewed source commit; it refuses unexpected migrations or existing SQL0008 objects. Unknown COMMIT must be reconciled by separate read-only observation, never by replaying the installer. This pull request DOES NOT enable the sealed Railway migrator or deploy SQL0008 to persistent staging.

The CI-only harness refuses Railway IDs, wrong DB, wrong host, non-GitHub context, and production mode. It applies SQL0008 after SQL0001-0007 on disposable PG16, verifies eight receipts, rejects replay/wrong database, and authenticates two different physical LOGINs. It tests wrong tenant, session, binding or digest, revocation, lock timeout, independently observed backend PIDs, re-enrollment under the same LOGIN and revocation followed by grant revision reissue. Database rows and credentials are synthetic and ephemeral.

## Remaining blockers

SQL0008 is not a replacement for real OIDC provider enrollment, bearer-bound current session authority, a physical credential vault/connection pool, guaranteed backend PID discard, independent durable redacted audit, cancellation, two-tenant private HTTP E2E, backup/PITR and canary controls.

The Backend16 HTTP handler remains unmounted, the Railway saas-control-api remains undeployed and production Core/Gateway plus /data remain untouched. The complete production readiness gate still applies.
