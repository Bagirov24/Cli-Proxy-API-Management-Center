# Backend16.1 - private, unmounted tenant/project read boundary

**Status:** proposed first Backend16 repo PR; unmounted/default-off, not deployed and not a production-ready SaaS API. This increment is intentionally limited to a strict Request/Response boundary; it does not replace the repository's existing OIDC, session, binding, or PostgreSQL implementation.

## Context

Backend15 Phase B `0007_operator_subject_binding_fence.sql` was positively applied to isolated Railway staging in the preceding engineering session. The one-shot installer was removed and PostgreSQL with its persistent volume was retained. The production `cliproxyapi-core`, `api-gateway` and `/data` were not modified. Do not repeat SQL0007.

The current candidate is designed for `src/features/saasBlueprint/controlApi/server/` and is **not imported by an application listener**. There is no `Bun.serve`, `fetch` listener, database client, SQL DDL, migration runner, secret value, or Railway resource in this candidate.

## Supported private routes, future-only

| Route | Method | Minimal allow response |
| --- | --- | --- |
| `/internal/saas/v1/tenants/{tenantUuid}` | GET | `{ "tenant": { "id": "..." } }` |
| `/internal/saas/v1/tenants/{tenantUuid}/projects` | GET | `{ "tenantId": "...", "projectIds": ["..."] }` |

The factory requires an exact operator-pinned HTTPS `expectedOrigin`; foreign origins and client proxy/Host overrides are refused before authentication. All other methods give 405; disabled returns 404 with no trust-port calls; unknown or unauthorized tenant returns the same 404. No query parameters, cookie credentials, client-defined roles, PG LOGIN headers or tenant identity headers are supported. Project output is limited to at most 50 distinct canonical UUIDs with no raw SQL row or metadata projection. All responses explicitly prevent caching, omit CORS allowance and set restrictive content headers.

The URL's `tenantUuid` is only a **requested resource key**. It is never trusted as identity or as proof of access. A client JWT or hash alone cannot authorize data.

## Ports required before enabling

1. `enabled()` must come from a server-controlled flag; `expectedOrigin` must be pinned at composition time, not derived from HTTP Host or X-Forwarded-* headers and default to false. Importing the module does not mount a route.
2. `authenticate(token, signal)` must be implemented using the **already reviewed** server-side pinned OIDC verifier, not JWT decode-only and not unverified client attributes. It must check issuer, exact intended audience, trusted JWKS signature/rotation, `alg`, `kid`, `exp`, `iat`, `nbf`, session enrollment, revocation, PKCE/nonce where applicable, and trusted issuer-to-subject enrollment. It returns an authenticated principal with a verified, short-lived PG session and binding ID; `subjectFingerprintSha256` is an internal lookup key, not authorization by itself.
3. `readAuthorized(principal, tenantUuid, signal)` must run exclusively against a PostgreSQL16 **dedicated physical connection** authenticated as the provisioned distinct per-subject PG LOGIN (never the `postgres` operator and never the shared NOLOGIN runtime role). No direct `SET ROLE` or client-controlled tenant GUC may change authority. Ensure logout/revoke invalidates/discards physical connections; no unsafe reuse of pooled sessions.
4. The trusted DB transaction must revalidate current tenant grant and exact CAS revision, current PG session, and active `saas_identity.subject_bindings` with the row-locking and FORCE RLS semantics already developed in Backend12-15, then read only authorized tenant/project IDs. The read result must not be published until the transaction has successfully committed; cancellation and SQL errors should fail closed without retry. Instrument transaction timeout and physical connection discard in an independent integration test.
5. The real DB port must validate that `tenantUuid` supplied from the route belongs to the authenticated principal according to the **database's current** binding/grant/RLS state. It returns `{kind:'denied'}` without revealing why for unknown/unauthorized resources. It should not return stale cached authorizations.

**Important:** The HTTP module cannot independently prove ports 2–5. In particular, TypeScript annotations and the shape of a `VerifiedPrincipal` object do **not** provide cryptographic authentication or RLS enforcement. Avoid making it reachable until those ports have direct multi-process PostgreSQL16/OIDC acceptance, including cross-tenant IDOR and real revocation concurrency tests.

## Local verification (not GitHub CI)

Run with Node 22.16+:

```sh
node --experimental-strip-types --test tests/saasBackend16PrivateTenantProjectRead.test.ts
tsc -p tsconfig.backend16.json
```

Local Node tests and strict TypeScript checks must pass. CI evidence is recorded only after GitHub Actions finishes on the exact PR HEAD. These cover disabled gate, minimal responses, missing/malformed bearer, expired session, dangerous PostgreSQL logins, wrong issuer shape, forged tenant/role headers, bad query/path/method, tenant-not-found indistinguishability, cross-tenant/malformed/out-of-limit results, redaction of private fields and exceptions, abort handling, and expiry during a read. Tests use trusted-port doubles and do **not** connect to Railway or PostgreSQL.

## Acceptance required before GitHub merge or staging deployment

- [x] Inspected `main` and existing `tenantProjectsReadHttpHandler.ts`, `saasStagingHttpComposition.ts`, `trustedAccessToken.ts`, `verifiedSubjectBinding.ts`, and Backend15 SQL0007. This additional unmounted route is explicitly separate from `/control-api/v1` and does not replace the existing signed SQL handlers.
- [ ] Validate current Backend15 SQL0007 was installed and migrator is sealed. No new schema changes or migration replay.
- [ ] Implement/authenticate the trusted OIDC and physical PG login/session adapters in *separate* reviewed change(s). Add direct real PostgreSQL16 tests for concurrent revoke/cancel/connection disposal and two independent tenants.
- [ ] Keep the new handler **unmounted/default-off**, as in this candidate, until a security sign-off permits strictly private staging routing. Never publish a domain or public TCP proxy implicitly.
- [ ] Run the repository's actual tests, TypeScript checks and all required exact-HEAD PR workflows (Main CI; SaaS Staging RLS PG16; Blueprint Demo Build; Browser QA; Management release guard; Backend15 one-shot contract and real PG16 catalog checks if triggered by changed paths).
- [ ] Review PR, verify no production/Core/Gateway/volume changes and only then merge. Do not report a GitHub PR number, CI result or Railway deployment without an actual tool confirmation.
- [ ] Production requires additional real IdP/OIDC, audit/outbox and off-host consistency, backup/PITR+restore, egress/CPA isolation and canary gates in `docs/saas/PRODUCTION_READINESS_GATES_V1.ru.md`.

## Intended repository paths

```
src/features/saasBlueprint/controlApi/server/backend16PrivateTenantProjectRead.ts
tests/saasBackend16PrivateTenantProjectRead.test.ts
docs/saas/BACKEND_16_PRIVATE_READ_BOUNDARY.md
```

The included `tsconfig.backend16.json` is a **standalone local type-check harness**, not necessarily a repository change; integrate into the repository's existing TypeScript setup after checking source compatibility.

## Existing Control API integration distinction

The repository already has an unmounted `/control-api/v1/tenants/:id/projects` read handler with signed SQL/RLS and an isolated-staging composition. This Backend16 module uses a different, strictly private `/internal/saas/v1` resource contract and intentionally supplies **no** runtime adapter. It must not be mounted alongside the existing handler until reviewers choose and prove a single authoritative trust path. It neither constructs nor substitutes for the reviewed OIDC verifier, physical PostgreSQL pool, session authority or durable audit; these remain required gates.
