# Backend vertical slice 02 — project creation and CAS rename, one-shot PG writes

**2026-10-14 · DRAFT / REVIEW ONLY / NOT PRODUCTION APPROVED**

Source: checked [Draft PR #23, read-only projects](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/23), exact parent SHA `2b6fb23facb1d550437c134e403c631ef9636af0`. Nothing changes in source #3–#23, the merge-readiness aggregate #21, release safety #22, `custom-no-apikey-fun`, Railway or GitHub Release.

## Endpoint contract — executable, but not mounted

`src/features/saasBlueprint/controlApi/server/tenantProjectsWriteHttpHandler.ts` is a backend Fetch Request/Response factory. It does **not** instantiate a network listener or connect to production.

| Method | Route | Exact JSON | Success |
| --- | --- | --- | --- |
| `POST` | `/control-api/v1/tenants/:tenantId/projects` | `{"name":"Project name"}` | 201, `{ok:true,status:201,apiVersion:1,source:"signed-postgresql",projectId:"<server-UUIDv4>"}` |
| `PATCH` | `/control-api/v1/tenants/:tenantId/projects/:projectId` | `{"name":"New name","expectedVersion":1}` | 200, `{ok:true,status:200,apiVersion:1,source:"signed-postgresql"}` |

All other verbs, paths, query strings, client-provided `projectId` on POST, actor, role, attempts, fingerprint, correlation, idempotency keys and cookies are denied. Body is bounded to 512 bytes with UTF-8 validation, exact keys, safe name and integer CAS version. The tenant path and PATCH project path are identifiers, not authority. Only a server-configured HTTPS origin is accepted; unencrypted loopback is possible **only** under explicit GitHub disposable PG16 guard `SAAS_PROJECT_WRITE_HTTP_CI=true`. No CORS, cookies, caching or raw SQL/DB/issuer diagnostics.

## Strict server-owned write boundary

- Reuses the existing tested `createM1ProjectCommandBoundary`: verified pinned access JWT issuer/subject → server private subject-to-actor directory → unambiguous current tenant admin/owner membership (both checked again before write).
- Only **after** trusted RBAC does the handler hash the full twice-verified access JWT as lowercase SHA-256 and require a **server-owned per-bearer token fingerprint → session UUID + monotonic epoch** lookup. It never accepts session ID, token jti, fingerprint or role from HTTP. Missing/invalid session denies before journal and DB. The native writer invokes SQL025 `saas_m1_api.lock_project_session_epoch(UUID,BIGINT,TEXT,TEXT)` under the already signed PG transaction and the mandatory project trigger refuses missing/revoked/old session epochs. In this CI the registry is an explicit in-memory fixture and PG session row is created by a separate privileged setup; it is **not** a production-distributed session authority.
- Only **after** a trusted active session does the handler mint a fresh CSPRNG UUIDv4 attempt. It obtains a matching `{attemptId,sequence}` receipt from a dedicated pre-COMMIT `TenantProjectPrecommitJournal` before reserving PostgreSQL. A failed/missing/different receipt returns 503 with **zero** SQL writer calls. Caller NEVER supplies the attempt ID, signer, PG identity or project ID on create.
- The `TenantProjectSignedWriter` interface must enforce fixed SQL, signed tenant+actor transaction claims, current PostgreSQL membership, project lifecycle and `expectedVersion` CAS, PLUS **atomic project+mandatory audit+attempt UUID binding**. This slice reuses the existing native M1a/M1c/M1d/M1g disposable PostgreSQL16 writer to verify those conditions against real SQL. TypeScript signatures alone do not make an arbitrary supplied implementation secure.
- PostgreSQL deny/zero changed rows → 404, confirmed ACK → 201/200. Signer, journal, driver or COMMIT uncertainty → 503. **No retry**, no transparent reissue, and 503 does **not** prove a rollback. The outer handler intentionally cannot perform recovery, polling, operator repair, release, GC or destructive SQL.

## Adversarial and real database acceptance

`tests/saasTenantProjectsWriteHttpHandler.test.ts` tests issuer/actor-derived authorization, client authority/header impersonation, foreign tenant, revoked role, malicious JSON/IDs, exact CAS and body bounds, signer receipt corruption, writer 404 vs unknown 503, one attempt per authorized request and no unsafe origins.

A dedicated **twelfth** disposable PostgreSQL16 invocation runs after all unchanged M1a–M1q acceptance in the same GitHub runner. Its actual `127.0.0.1` Bun HTTP listener invokes the new handler with existing pinned synthetic RS256 access verifier, signed native non-superuser Bun.SQL transaction driver and **second NO-PG-credentials Node witness process with fsynced signed pre-COMMIT journal**. The fixture must observe:
- HTTP POST 201, unique server UUID, **1 project / 1 mandatory PG audit / 1 attempt binding / 1 session proof**, and signed SQL read version 1.
- HTTP PATCH 200 on version 1, version 2 persisted, **1/2/2 + 2 PG session proofs**; stale version 1 PATCH 404 with 0 new audit/bindings/proofs.
- Current PG membership revoked while server actor cache stays admin → 404, 0 project/audit/attempt.
- Real PostgreSQL COMMIT succeeds but synthetic ACK is lost → one 503, exactly **1/1/1 + 1 locked session proof** remains persisted; transaction adapter poisoned, no retry.
- Real backend terminated BEFORE COMMIT → 503, **0/0/0 + 0 session proofs** persisted; fsynced prior attempt remains as historical evidence.
- Witness process unavailable → 503 **before any PG reservation**. Off-path unsigned/malformed tokens and reader/auditor roles never even issue a witness attempt.
- Independently verify the six one-use signed intent entries offline. This is a local runner proof, NOT independent off-host WORM/HSM or production UNKNOWN-COMMIT settlement.

Existing SQL021 mandatory trigger, SQL024 bound-attempt constraints, SQL025 session-lock/proof trigger, DB-side M1d authorization fence and all M1a–M1q regression proofs remain in force. `saas_ephemeral_test` and migrations `staging/saas-rls/001–018,020–025` remain disposable staging only. **NO SQL019 or production migrations.**

## Explicit production gaps and merge discipline

This is a real request handler and real transactional PG16 test, **not** an independently audited production SaaS write API. Missing: external IdP trust governance, browser callback/cookie/CSRF controls, durable cross-replica auth/session binding and revocation, production physical connection discard/cancellation and timeouts, independent off-host witness/WORM, remote PRE-COMMIT/COMMIT ambiguity settlement, governance-operated signer, privacy-respecting immutable audit storage, rate limiting/quotas, operator recovery, tenant onboarding, source-branch deployment safety, API-to-Gateway mounting.

`POST` retry from a human/client following a 503 is not authorized to be treated as idempotent; operator reconciliation using independent persisted evidence is required before any later resubmission. Because server IDs are not returned on unknown COMMIT, naive re-submission can duplicate work. **Do not issue an automated second request.**

[Aggregate merge-readiness #21](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/21) and [auto-release guard #22](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/22) remain unmerged. Direct push to `custom-no-apikey-fun` could trigger GitHub Release mutation and possible Railway production Core deploy. Codeowner, independent security review and operator release freeze are still OPEN. Railway sandbox independent negative TCP 8443 no-listener proof and old synthetic TLS PKI deadline **2026-10-15 13:33 UTC** remain operator-owned.

**No Ready, merge, production/SQL019/Railway writes, live credentials, automatic unknown-COMMIT retry/reissue, archival or GC.** `authorizationGranted=false`, `gcPermitted=false`.
