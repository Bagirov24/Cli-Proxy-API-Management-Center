# Backend 13 — tenant login grant/revoke CAS, transactional audit and RLS revocation fence

Status: **reviewed migration + DISPOSABLE GitHub PG16 CI; NOT applied to live Railway staging by this PR.** 16 October 2026. Permanent SaaS staging schema, not the separate historical SQL001–027/SQL019 synthetic pilot.

## Boundary and prior state

Isolated staging only: Railway project `a9703851-6eb1-406c-bb15-7d3a89359fb7`, environment `b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b`, PostgreSQL16 `37f8f166-75a6-4617-b243-8e681181c16d` on isolated persistent `/var/lib/postgresql/data`. Backend11 0000–0002 and Backend12 0003–0004 were applied/read back; the temporary migration Functions were **deleted**, and `saas_schema_migrator` was sealed `NOLOGIN PASSWORD NULL`.

The user explicitly accepted losing *disposable staging tests* and waived the staging backup/PITR prerequisite. This does **not** authorize production changes, real customer identities/provider keys, public SaaS API or bypassing auditing; verified backups and restoration are required before irreplaceable data. Never touch CPA Core/Gateway, its `custom-no-apikey-fun` branch, /data volume or credentials.

## 0005: Operator-controlled lifecycle

File: `staging/saas-bootstrap/0005_principal_lifecycle_revocation_fence.sql`.

Requires PostgreSQL16, only `saas_staging` or `saas_staging_ci`, explicit `saas.staging_only=true`, and a **real non-superuser `saas_schema_migrator` session**, with exact existing four attested ledger receipts. Refuses unexpected roles, memberships, actual tenant/project/mapping rows and replay. One atomic SQL transaction appends its own SHA256 + reviewed source commit receipt. UNKNOWN COMMIT = STOP, compare receipt and DB catalog; **never rerun speculatively**.

- `saas_acl.principal_tenants` now has `access_revision` and `updated_at`; state becomes `reader | writer | revoked`. Revoke is a **persisted tombstone**, not DELETE. Every regrant must CAS against the last revision, preventing ABA/stale reactivation. A partial unique index guarantees **at most one active tenant per database login**; this is stricter than multi-membership to avoid unsafe reuse of a login across arbitrary HTTP tenants.
- `saas_acl.change_principal_access(principal_name, tenant_uuid, expected_revision, next_level, reason)` is **SECURITY INVOKER**, only callable as the isolated PostgreSQL **postgres** operator session (no PUBLIC/runtime EXECUTE). Expected revision `0` means the first grant only; positive versions require exact CAS and a different next state. Restricts grants to verified LOGIN accounts with no superuser/BYPASSRLS/CREATEROLE/CREATEDB/REPLICATION and explicit membership of the appropriate NOLOGIN role template; refuses extra inherited role memberships.
- No application login, password, IdP account, mapping or grant is provisioned in the migration. `saas_runtime_reader` / `saas_runtime_writer` stay **NOLOGIN** and only have read policies. The word `writer` still does NOT authorize DML.
- `saas_acl.principal_access_audit` captures each approved INSERT/UPDATE through a trigger, in the *same database transaction*, recording principal, tenant, old/new state, revision, operator login, reason, transaction ID and clock time. Audit rows reject ordinary UPDATE, DELETE and TRUNCATE via triggers; direct map DELETE and TRUNCATE are likewise rejected. This is an **operator-facing transactional audit, not WORM**: a superuser could still disable triggers or rewrite the database. Future off-host tamper-evident audit is still required.
- The existing RLS predicate `saas_acl.can_read_tenant(uuid)` becomes **VOLATILE SECURITY DEFINER**. It trusts the authenticated PostgreSQL `session_user` and takes `FOR SHARE` on the matching active allowlist row. A concurrent revoke/CAS UPDATE must obtain a conflicting lock and **cannot acknowledge completion while an active reader holds its transaction lock**. Future READ COMMITTED statements see revoked tombstones; older RR/serializable snapshots must not silently regain access after a committed update (PostgreSQL can raise serialization failure). Caller-controlled GUC `saas.tenant_id` and `SET ROLE` cannot substitute a different session_user.

### Revocation semantics and deliberate limits

The fence serializes **RLS-authorized statements/transactions versus operator-driven grant updates**, but it does not kill already-running remote requests, guarantee client-side cancellation, or establish a usable OIDC/session-authentication system. A reader transaction can delay a revoke acknowledgment. Long-running transactions may raise errors or be blocked. All database clients must use bounded transaction and statement timeouts, quarantine uncertain connections, reauthenticate per genuine DB login, and never treat a GUC or SET ROLE as a cross-tenant identity proof. No release-grade SLA or multi-region revocation assertion is made.

Normal operators with access to `postgres` must not insert raw tenant maps; the helper makes reason+CAS/audit an explicit contract. A DB superuser is still omnipotent; protect that login physically and eventually move to an audited lower-privilege operator role with independent off-host audit and WORM retention.

## Disposable PG16 acceptance

`scripts/saas-staging/verify-backend13-lifecycle-pg16.sh` runs **only** in GitHub Actions on local PG16 at `127.0.0.1:5432`, after Backend12 CI removed its own synthetic tenant/login fixtures. It executes 0005 as the restricted migrator, verifies the new 5th receipt/DDL, blocks replay and the wrong pilot database, then creates three disposable synthetic login principals and tenants. Tests include:

- Login A only reads tenant/project A, login B only B, unmapped C sees none; spoofed `saas.tenant_id` and SET ROLE do not cross scopes.
- Duplicate/parallel initial grant, assigning two active tenants to one login, missing role, invalid revocation, stale CAS and old-version regrant all fail.
- Both runtime templates and caller LOGIN are denied direct tenant/project write, private mapping/audit access and the operator change function.
- Approved grant → revoke → regrant leaves increasing tombstone revisions, each represented exactly once in the atomic audit.
- A real PostgreSQL transaction reading tenant A holds the ACL `FOR SHARE` lock. A concurrent revoke with a short lock_timeout must be refused; after the reader commits, revoke succeeds and later reads return no rows. This tests a real concurrency fence rather than only catalog flags.
- Raw DELETE of a mapping and UPDATE/DELETE/TRUNCATE of the audit table are rejected in ordinary SQL. PostgreSQL superuser override remains outside this proof and is not hidden.

CI still requires five GitHub Actions all SUCCESS at the exact final PR commit before any merge. This PR is **code plus ephemeral CI only**, not an automatic live Railway migration. A separate PR/operator-reviewed one-shot Function with immutably pinned SQL SHA256, strict environment guard, single-use credential, `restartPolicy=NEVER`, zero public endpoints, catalog+audit readback and post-success deletion is required to install 0005 on Railway staging.

## Future Backend14 prerequisites

Real IdP and signed session/account binding, connection isolation, tenant login creation/revocation with credential storage and zero role escalation, CAS writes and independently durable audit, compensations for unknown COMMIT, disaster recovery/PITR, multi-region authorization and production acceptance. `saas-control-api` remains disabled until those requirements are independently proven.
