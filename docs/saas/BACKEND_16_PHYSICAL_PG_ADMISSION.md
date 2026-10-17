# Backend 16.3 — physical PostgreSQL LOGIN admission (NOT a SaaS data reader)

**Status: source-only, unmounted, default-off, no Railway deployment.** This increment adds an operator-supplied physical-login PG admission *probe*. It must NOT be wired to the HTTP readAuthorized() port: returning physical-rls-observed is not authorization to serialize projects or tenants.

## Critical SQL0007 findings

The persistent isolated staging PG16 was confirmed with Backend15 SQL0007 installed and its migrator returned to NOLOGIN/PASSWORD NULL in the preceding operator run. Its saas_acl.can_read_tenant() performs FOR SHARE locking across saas_acl.principal_tenants, saas_identity.principal_sessions and saas_identity.subject_bindings. These locks protect already admitted in-flight reads from concurrent revoke COMMIT. PostgreSQL **refuses SELECT FOR SHARE inside a READ ONLY transaction**, so a protocol READ ONLY transaction cannot implement this algorithm without modifying the SQL contract.

The new Backend16.3 probe explicitly runs BEGIN ISOLATION LEVEL READ COMMITTED and a bounded sequence of server-owned SELECT / SET LOCAL commands. Read-only behavior is instead enforced by database-granted privileges and a physical driver-side SQL allowlist — **not** by PostgreSQL transaction READ ONLY. Before any real deployment, operators must prove that the per-principal LOGIN has only appropriate SELECT/EXECUTE rights, no INSERT/UPDATE/DELETE, no role escalation and no BYPASSRLS, and that driver quarantine terminates the actual backend.

## What the unmounted probe checks

- A server-provided VerifiedPrincipal with canonical session/binding UUIDs, short expiry, SHA-256 subject fingerprint, and a safe per-principal login string; no JWT, HTTP headers, client role or database password enters query parameters
- The injected pool selects a physical backend using **operator-owned credentials for exactly that principal's distinct LOGIN**, never a shared operator/NOLOGIN connection or SET ROLE
- Inside a single bounded transaction, a fixed SQL query verifies session_user=current_user=the intended login; exact staging DB name, staging-only marker, positive backend PID, LOGIN enabled, no SUPERUSER/BYPASSRLS/CREATEROLE/CREATEDB/REPLICATION and membership in saas_runtime_reader
- The existing SQL0007 can_read_tenant($1::uuid) database predicate (FOR SHARE locked), followed by a FORCE RLS tenant-row read, both with the same bound tenant UUID; empty/unauthorized tenant is returned as a generic denied result
- Successful COMMIT acknowledgement and final expiry check precede any returned result; all malformed rows, cancellation, SQL errors, lost COMMIT ACK, unknown physical identity or broken release synchronously quarantine the pool and require physical backend discard

**No tenant/project data can be published** by this module: its only positive result is kind=physical-rls-observed. It is purposefully NOT compatible with ReaderDecision / kind=authorized.

## Why SQL0007 alone cannot complete Backend16

SQL0007 grants runtime SELECT only on saas_data.tenants/projects and EXECUTE on a *boolean* saas_acl.can_read_tenant(uuid). The private rows of saas_identity.principal_sessions and saas_identity.subject_bindings are explicitly revoked from runtime SELECT, and no safe non-privileged DB function currently lets the caller independently attest exact **sessionId + bindingId + verified issuer/subject fingerprint** under the same FOR SHARE lock. Treating any active DB-login session as equivalent to the OIDC-authenticated caller's specific session risks accepting a stale access token after a login is explicitly revoked and later re-enrolled.

**The next step must be an independently reviewed, pinned SQL0008 (or equivalent) narrow SECURITY DEFINER verifier**, with exact authenticated session_user, supplied current session UUID, binding UUID, verified subject digest, tenant grant revision and FOR SHARE checks. It must have a new one-shot migration gate, ephemeral PostgreSQL16 real concurrency/abort/revocation tests and separate operator approval. This PR does NOT create or execute a new migration. No retry/replay of SQL0007 is authorized.

## CI and deployment boundary

The dedicated Backend16 private contract workflow tests a fake physical pool with positive/negative SQL identity snapshots, per-login selection, denied cross-tenant RLS, ACL/row mismatches, expiry, abort, lost COMMIT acknowledgement, synchronous quarantine, and forced discard, then full TypeScript. The existing ephemeral PostgreSQL16 RLS pipeline also runs; **that suite is not proof that the new injected physical driver exists in Railway or that physical backend PID discard is implemented and tested**.

Real physical PG16 PID proof, independent per-login vault credential selection, real OIDC enrollment+token-bound session lookup, an exact SQL0008 session/binding verifier, two-tenant revocation races, external durable audit and private network policy are still release blockers. Do not mount a private/public listener or populate client data until separately proven. The running production Core/Gateway and /data remain out of scope.
