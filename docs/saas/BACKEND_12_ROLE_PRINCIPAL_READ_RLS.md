# Backend 12 — PostgreSQL16 role-principal tenant read-only RLS

**16 October 2026. Isolated, disposable SaaS staging only.** The user temporarily waived backup/PITR for disposable staging test data and accepts possible data loss. This does **not** permit use of real customer credentials/data, production migrations, Gateway/Core changes, public API or network exposure. The existing `saas-control-api` stays unmounted and `SAAS_HTTP_EXPLICIT_ENABLE=false`.

## Design decision: do not authorize on an attacker-controlled GUC

A PostgreSQL runtime role can generally `SET saas.tenant_id='other'`. This can never establish trust. Rather than enabling an unsafe signed-looking or plain GUC-based policy, this stage uses **the authenticated PostgreSQL `session_user`** with an operator-controlled private allowlist, and continues to deny writes.

- `0003_operator_runtime_roles.sql`, executed **only as `postgres`** on allowlisted `saas_staging`, creates `saas_runtime_reader` and `saas_runtime_writer`, both **NOLOGIN, NOINHERIT, NOSUPERUSER, NOBYPASSRLS, NOCREATEROLE, NOCREATEDB, NOREPLICATION**. Both have **no credentials, memberships or grants** at creation. An atomic receipt with source SHA-256 and commit is recorded in `saas_bootstrap.schema_migrations`. No schema or tenant rows are changed.
- `0004_principal_bound_read_rls.sql`, executed separately as temporarily activated (operator-controlled) `saas_schema_migrator`, creates `saas_acl.principal_tenants`. Only operator/schema owner can manage that table; no application LOGIN is created. `saas_acl.can_read_tenant(uuid)` is a narrow `SECURITY DEFINER` function with pinned `search_path`, zero dynamic SQL and PUBLIC EXECUTE explicitly revoked. It uses **`session_user`**, immutable across `SET ROLE`, and rejects superusers/bypass RLS. It does not interpret any tenant claim, actor header, caller-selected GUC or HTTP JWT.
- Both baseline tables `saas_data.tenants` and `saas_data.projects` remain **FORCE ROW LEVEL SECURITY**. Exactly one scoped **SELECT** policy is added to each. `saas_runtime_reader` / `saas_runtime_writer` receive SELECT, function EXECUTE and schema USAGE only. **No INSERT/UPDATE/DELETE/TRUNCATE grants or policies** exist. The writer role is only a reserved NOLOGIN template and CANNOT currently write.
- An identity can only read a tenant if a separate privileged operator deliberately establishes a login/tenant row in `saas_acl.principal_tenants`, and the authenticated DB login has explicit role membership. **No actual app login is provisioned in the staging migration.** In absence of membership and mapping, the effective state remains deny-all, including for the schema owner (FORCE RLS).
- Granting credentials and tenant membership, providing a real IdP or exposing `saas-control-api` require another security-reviewed stage. A pool shared by arbitrary HTTP tenants **must not** impersonate them by `SET ROLE` or `SET saas.tenant_id`. For dynamic identities, develop a separately proven DB-verified signed tenant+session transaction boundary.

## Migration sequencing and reconciliation

Existing live staging ledger `0001`/`0002` was applied and checked in Backend11, with migrator sealed `NOLOGIN`. New 0003/0004 **cannot be replayed**. Both verify PostgreSQL16, exact database (`saas_staging`, `saas_staging_ci` only), explicit `saas.staging_only=true`, expected prior SHA-256 receipts, correct operator vs migrator identity, absence of preexisting roles/ACL/policies, and no runtime superuser/bypass privilege.

Approved one-time operator workflow: verify exact Railway project `a9703851-6eb1-406c-bb15-7d3a89359fb7` / environment `b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b` and private PostgreSQL16 service `37f8f166-75a6-4617-b243-8e681181c16d`. Review SQL SHA-256 and exact Git commit. Execute `0003` as `postgres` from a private one-shot runner; only after an acknowledged COMMIT provision a randomly generated temporary 64-hex migrator password and LOGIN via an operator-only action, execute `0004` as `saas_schema_migrator`, verify four receipts/roles/FORCE RLS/zero live principals and seal migrator `NOLOGIN` again. Then remove the ephemeral privileged runner and preserve non-secret evidence. **On unknown COMMIT, STOP — do not repeat SQL or autoconnect.** No public TCP proxy/domain, no Core/Gateway credentials or inherited volumes.

### CI acceptance

`scripts/saas-staging/verify-backend12-principal-rls-pg16.sh` is guarded for **GitHub Actions disposable loopback PG16 only**, never Railway. It applies 0003/0004 after the earlier 0000–0002 acceptance, from their appropriate real PG roles. It checks exact receipts, no runtime LOGIN, table privileges, SECURITY DEFINER safety, no unexpected policies and denied replays/wrong database. It then uses three **CI-only synthetic LOGINs** with independent passwords and rows:
- A sees only tenant A/project A; B only B/project B; an unmapped login sees neither.
- Spoofed session GUC and `SET ROLE` cannot change `session_user` tenant scope.
- Cross-role escalation, project/tenant writes, mapping modifications and ledger reads are denied.
- Migrator, still subject to FORCE RLS, sees zero projects despite being the table owner.

Five GitHub Actions must be SUCCESS on the exact final PR SHA before merge or live staging changes. A green CI only proves disposable PG16, not production readiness. No live customer data or API listener; PITR+restore is still required before non-disposable data.

## Remaining security work

Per-tenant trusted login provisioning or DB-verified signed transaction/session scope, ownership/revocation, per-tenant audit and off-host WORM, CAS writes with unknown-COMMIT reconciliation, robust physical connection discard and real OIDC/JWKS onboarding. Do not attach the existing `saas_rls` synthetic pilot and SQL001–027/SQL019 to these persistent tables.
