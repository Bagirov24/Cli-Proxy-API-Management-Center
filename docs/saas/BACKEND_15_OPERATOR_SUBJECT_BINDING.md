# Backend 15 — operator subject-binding fence (isolated PG16 staging)

**17 October 2026.** Status: **reviewed code + disposable PostgreSQL16 CI**, NOT a public OIDC login, production identity authority, automatic DB provisioning, or approval to deploy publicly. The live SaaS staging had SQL `0000–0006` successfully installed before this stage. The Backend14 one-shot Function was removed after deployment-log verification; `saas-control-api` remains disabled.

## Purpose and trust boundary

Backend14 stored an opaque operator-supplied `identity_binding_id` on a short-lived private session. That value was **not itself proof** that any external issuer signed a valid token or that the subject was a tenant member. Backend15 adds a separate, persistent **operator enrollment gate** to prevent arbitrarily asserted binding UUIDs from unlocking `tenants/projects`.

This stage **does not** implement a real OIDC callback or create/log in any user. The operator must separately verify issuer, audience, RS256 signature, subject, timestamp, IdP key rotation and tenant approval before recording a subject fingerprint; PostgreSQL cannot prove those facts from a hexadecimal hash. Access requires ALL of: genuine restricted DB `session_user`, tenant ACL + exact CAS revision, an active private session bound to the *same* principal/tenant/grant, and one active enrolled binding. Neither `SET ROLE`, `saas.tenant_id`, a JWT `tenant_id` claim nor an arbitrary UUID authorizes access.

## Code and migration

- `src/features/saasBlueprint/controlApi/server/verifiedSubjectBinding.ts` accepts an injected `AccessTokenVerifier`; production callers must construct it using the reviewed operator-pinned issuer, resource audience and public JWKS trust. The verifier interface must cryptographically validate the raw access token before returning claims. A domain-separated UTF-8 SHA256 of `saas:issuer-subject:v1\0<issuer>\0<subject>` is returned; no raw subject, token, claims, secrets or selected tenant appear in the result. This preparation is **not** a privileged DB write or a certificate of successful identity verification by the database. Static unit tests use synthetic claims only.
- `staging/saas-bootstrap/0007_operator_subject_binding_fence.sql`, operator-reviewed one-shot non-superuser `saas_schema_migrator`, requires exact PostgreSQL16 `saas_staging` / disposable `saas_staging_ci`, explicit staging-only GUC and exact previous `0006` SHA-256 receipt. It appends receipt `0007` in the same transaction, refuses schema replay and does not insert identities.
- Private `saas_identity.subject_bindings`: opaque UUID, real DB principal, tenant, grant revision, lowercase digest, active/revoked tombstone and CAS revision. Globally unique fingerprint prevents recycling even after revoke; one active binding per PostgreSQL LOGIN prevents multi-tenant shared-connection reuse.
- `saas_identity.register_subject_binding` and `revoke_subject_binding`: **SECURITY INVOKER, operator-only**. Registration requires an exact currently active tenant grant revision and a restricted LOGIN. Revocation increments the immutable binding revision, sets a tombstone and is never a DELETE. Transactional events are protected by mutation-blocking triggers and no app grants; the operator/superuser can nevertheless still tamper, so **not external WORM**.
- `issue_principal_session` now requires a matching active binding ID with the identical login/tenant/revision. Existing Backend14 sessions without enrollment become **deny-all** when `0007` takes effect, including those with pre-existing arbitrary UUIDs.
- `saas_acl.can_read_tenant` now holds **three** `FOR SHARE` row locks: ACL grant, private session and subject binding. A binding-revoke operator UPDATE cannot acknowledge COMMIT before a concurrent reader releases the lock. No app write privileges, new user logins, network paths, public domains or Core/Gateway modifications are introduced. Already-delivered HTTP responses are **not** retroactively cancelled.

## Disposable PostgreSQL16 acceptance

`scripts/saas-staging/verify-backend15-subject-binding-pg16.sh` is gated on GitHub Actions and loopback PostgreSQL16 only, **after** the existing Backend14 synthetic CI. It checks:

1. Correct source hash, seven receipts, private catalog, granted/non-granted table privileges, audit triggers and reject wrong database/replay.
2. A synthetic pre-existing Backend14 session immediately loses visibility after the new migration. Enrollment alone does not retroactively validate the old UUID. A new session with the exact operator-enrolled binding sees only its own tenant.
3. Forged tenant GUC, `SET ROLE`, unauthorized role access to binding/audit, tenant writes, missing/stale grants, unknown binding ID and duplicate fingerprint are refused.
4. Concurrent reader holds the binding row; operator revoke with a short lock timeout is refused, and no false revoke acknowledgement occurs. Once reader COMMITs, revoke succeeds and next reads are denied.
5. Old revision replay, binding resurrection/DELETE, audit mutation, fingerprint reuse and revoked-binding session issuance are denied.

CI success means **only disposable synthetic PG16 proof**, never actual IdP security sign-off.

## Deployment and product restrictions

No live Railway `0007` is applied merely by merging this PR. A future separate reviewed private one-shot runner is necessary; use the same exact project/environment/DB preflight, immutable SQL SHA, temporary migrator seal `NOLOGIN PASSWORD NULL`, `restartPolicy=NEVER`, no domain/proxy, receipt read-back and no retry on UNKNOWN COMMIT. Do not run any SQL001–027 synthetic pilot against this permanent schema.

The user waived backups/PITR **only for disposable isolated staging tests**; production/Core/Gateway, `custom-no-apikey-fun`, `/data`, real OAuth/BYOK secrets and real users remain off-limits. Verify backup/PITR+restore, independently durable auditing and connection/issuer security before irreplaceable data.

### Still needed for first working SaaS

A supported real IdP approval and pinned issuer/audience/JWKS, an enrollment operator with independently verified evidence (not bare SHA), safe per-login provisioning/rotation and physical DB-pool isolation, session issuance tied to one verified login context, OIDC nonce/PKCE callback, external tamper-evident audit, true remote HTTP publication and an authenticated private read-only API. No public SaaS service is authorized by this stage.
