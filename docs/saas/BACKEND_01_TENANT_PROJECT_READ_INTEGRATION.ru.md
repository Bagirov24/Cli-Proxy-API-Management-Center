# SaaS backend vertical slice 01 — authenticated tenant/project READ

**Status: implementation for integration review; NOT production/deployment approved.**
Base: isolated aggregate integration [Draft PR #21](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/21), exact parent HEAD `7d04161be9583817c83f4032ad8986ad8ae4662b`. Separate [release-guard Draft PR #22](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/22) is not merged or changed here.

## Deliverable — executable server-side route

`src/features/saasBlueprint/controlApi/server/tenantProjectsReadHttpHandler.ts` implements a **Fetch Request/Response handler**, not a mock DTO:

```http
GET /control-api/v1/tenants/{tenantId}/projects?limit=1..50
Authorization: Bearer <verified-access-token>
```

Successful response projects only an explicitly allowlisted `[{id,name,status}]` from the **real** signed PostgreSQL RLS source `saas_rls.projects`, with no raw SQL rows, tenant ownership, credential material or internal roles. Default limit 20, max 50. No write verbs, SQL expressions, arbitrary order, offset, pagination cursor, cookies, user-supplied actor/role/session identity or forwardable internal correlation identifier. Strict origin is **server-configured** (never selected from Host/Forwarded headers); HTTPS required except explicit `GITHUB_ACTIONS=true` disposable loopback CI switch `SAAS_PROJECT_READ_HTTP_CI=true`, disallowed on Railway/production.

Authentication path: existing pinned access JWT verifier → server-held issuer/subject→actor directory → current actor memberships → `tenant-viewer`/owner/admin/auditor capability → **mandatory** server-issued auth revision → SHA-256 of actual verified bearer → signed transaction-scoped `saas_rls_reader` PG authorization gate under current tenant/member/session status and RLS → second fresh transaction check → reverify token/actor/membership and revision → fixed allowlist projection → synchronous security audit **before any successful HTTP bytes are returned**. No actor-only signed scope fallback. Any missing authority, invalid RLS/signature/row, abort, revoked bearer, ambiguous membership or audit failure returns generic 401/403/404/503 with `no-store` and no tenant/SQL/secret diagnostic.

**Important truthfulness:** the handler itself is transport-independent and does not mount in the existing Vite UI, Gateway or Core. Its injected private interfaces are real, not hard-coded synthetic actors. However production identity provisioning, externally governed IdP, durable audit transport, physical Bun.SQL pool quarantine/discard and atomic revocation-to-HTTP-publication across replicas still require independent implementations and review. Existing source SQL tables are **disposable staging schema**, not approved production migrations.

## Tests (must pass on final PR HEAD)

- `tests/saasTenantProjectsReadHttpHandler.test.ts`: allowlisted project DTO; SQL field suppression; bearer denial; tenant IDOR; spoofed actor/role headers and browser cookies; Origin/Sec-Fetch-Site; malformed/doubled limit; path traversal; wrong DB-authorized membership; in-flight revocation after SQL; cross-tenant/malformed/duplicate DB rows; signer/audit failure; origin protocol guard; safe 503 with zero leaked data.
- Existing ephemeral PostgreSQL16 workflow `scripts/saas-staging/verify-trusted-pg-e2e.mjs` gains an opt-in **actual 127.0.0.1 HTTP server** backed by non-superuser Bun.SQL and real signed PostgreSQL transaction/RLS+token fingerprint table from migration 010. Real two token sessions for one actor: verify A/B 200, revoked A 404 but independent B 200; DB/tenant IDOR 404, unauthenticated 401, forged headers/cookies 403, wrong verb 405 and no CORS. Other existing PG16 fixtures run unmodified with one extra `SAAS_PROJECT_READ_HTTP_CI=true` attached **only to that explicit disposable E2E step**.
- Existing Main CI, PG16, Demo Build and Chromium QA must run and succeed on **one final SHA**; parent #21 success does not substitute for this new PR.

## Remaining gates / order

**No direct merge** to `custom-no-apikey-fun`: current GitHub Release workflow publishes automatically, while Railway production `cliproxyapi-core` sources that branch; possibility of automatic production redeploy is not independently resolved. #22 proposes (but has not installed) a verification-only workflow. Independent security/code-owner/operator approval for #21/#22/new backend and operator-authorized release/deploy freeze are still needed. Keep all PRs Draft, no Ready or merge while blocked.

This slice deliberately does **not** offer public OAuth login, cookie/CSRF/session issuance, POST/PATCH/DELETE, durable actor directory, production API mount, production PostgreSQL migrations, CPA key issuance, routing or outbound provider calls. Those are subsequent small vertical slices. No SQL019, production DB, Railway writes, live certs/keys, UNKNOWN COMMIT retry or GC. `authorizationGranted=false`, `gcPermitted=false`.

Separate sandbox test PKI deadline **2026-10-15 13:33 UTC** remains open until operator produces independent TCP 8443 no-listener proof and determines certificate lifecycle retirement/rotation.
