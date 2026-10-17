# Backend16.6 — unmounted exact SQL0008 tenant/project read port

**Status:** source-only fail-closed readAuthorized adapter; **not mounted**, no HTTP listener, no real PostgreSQL driver/vault, no IdP, no Railway deployment, no customer data. This stage does NOT make SaaS production-ready.

## Why this port exists

SQL0008 (reviewed source at GitHub commit 314f0962f2d955241fb5ee7a29175bddb648c130) now defines the exact session predicate for physical PostgreSQL LOGIN + tenant + sessionId + bindingId + operator-verified subject digest. SQL0007 FORCE RLS predicates additionally hold tenant ACL, active session and binding FOR SHARE locks. The Backend16.1 unmounted private HTTP handler requires a readAuthorized port that enforces these proofs **in a single transaction on a single physical connection**; the Backend16.3 probe does not produce tenant data.

This module implements that TypeScript PORT contract, not its physical production dependency. A server-owned Backend16PhysicalPgPool must select **verified per-principal credentials**, never a client-selected PG login/password, shared NOLOGIN pool or SET ROLE. The port checks PostgreSQL session_user=current_user=expected LOGIN, PG database exact isolated staging, backend PID, LOGIN and non-elevated role flags, and exactly one runtime reader/writer membership.

## Bounded query protocol

Inside one bounded READ COMMITTED transaction:

1. BEGIN and server-owned SET LOCAL statement_timeout=5s and lock_timeout=1.5s. PostgreSQL READ ONLY transactions cannot execute the FOR SHARE locks from SQL0007/0008; fixed SQL allowlists and DB least-privilege provide write denial instead.
2. Verify physical login role catalog and attached database. Any mismatch => abort output, pool quarantine/discard.
3. Run exact SQL0008 predicate with **four bound server-derived parameters**, no interpolated tenant/session/subject or writable tenant GUC.
4. Only after TRUE, query the FORCE RLS tenant witness and a sorted LIMIT 51 project_id-only projection on the SAME connection while the predicate locks are still held. Any foreign tenant, extra field, duplicate ID, malformed UUID or more than 50 projects => refuse.
5. Check JWT/server-session TTL before COMMIT and after the known COMMIT acknowledgment. Release connection safely **before** returning an immutable {kind:authorized, tenantId, projectIds} projection. If the predicate is FALSE, return indistinguishable {kind:denied} after known COMMIT, with NO tenant/project SELECT.
6. SQL exception, deadline, cancelled request, uncertain network/COMMIT response or broken physical release => poison the pool synchronously, request physical backend discard and throw a generic unavailable error. Never replay the transaction.

No tenant names, DB credentials, subject hashes, access tokens, session IDs, raw error messages or SQLSTATE are included in user-facing DTOs.

## Tests and what they do NOT prove

Synthetic fake-pool tests validate query order, SQL allowlist, issuer+subject/sessionId/bindingId tuple parameters, two role membership choices, malformed role/tenant/projects, up to 50 bounded project IDs, RLS mismatch, abort, session expiry, unknown COMMIT, no retry, pool quarantine/discard interface and disabled HTTP mounting discipline.

**Tests are NOT live driver/PID proof**. SQL0008's real **disposable PostgreSQL16** E2E was verified in PR #52, but it did not validate this Bun adapter's connection lifecycle or a real OIDC issuer. No physical driver is provided by this PR.

## Release blockers

- Permanent staging SQL0008 installation is a distinct one-shot operator workflow prepared in PR #53. It remains **not confirmed installed**. The staged Railway installer Function is a disabled NO-DB placeholder; never replace it with the real installer until an operator confirms Restart Policy NEVER and fresh preflight.
- Real pinned-JWKS/OIDC access token enrollment, multi-instance bearer-bound session lookup and per-principal physical PG credential vault/pool need E2E with distinct backend PIDs, session expiry, FOR SHARE revoke races, actual aborted driver queries and **physical** connection discard evidence.
- Durable redacted off-host audit (authorization plus delivered response), private ingress and explicit publication/revocation linearization must be designed/tested before mounting. Returning a post-COMMIT DTO here is not a proof of remote HTTP delivery ordering; revocation cannot retract already-delivered data.
- Full system/CPA Gateway/e­gress integration, disaster recovery, load tests and production canary approval remain required. No running Core/Gateway, /data, pilot SQL, real credentials, live users or production environment is changed.

**Do not mount a listener, route actual users or deploy public SaaS based on typechecks or fake connection unit tests.**
