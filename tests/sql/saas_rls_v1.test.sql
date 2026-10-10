\set ON_ERROR_STOP on
-- Runs ONLY in a throwaway PostgreSQL 16 service within GitHub Actions.
-- Never supplies real Core data, Railway variables or production credentials.
SET saas.staging_only = 'true';
\ir ../../staging/saas-rls/001_readonly_pilot.sql
-- Migration replay must be idempotent before fixture data is inserted.
\ir ../../staging/saas-rls/001_readonly_pilot.sql

CREATE SCHEMA IF NOT EXISTS saas_rls_test;
CREATE OR REPLACE FUNCTION saas_rls_test.assert_true(ok BOOLEAN, message TEXT)
RETURNS void LANGUAGE plpgsql AS $fn$
BEGIN
  IF ok IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'RLS acceptance FAILED: %', message; END IF;
END
$fn$;
GRANT USAGE ON SCHEMA saas_rls_test TO saas_rls_reader;
GRANT EXECUTE ON FUNCTION saas_rls_test.assert_true(BOOLEAN, TEXT) TO saas_rls_reader;

-- Prove the no-login reader is non-bypass and cannot inspect private grants.
SELECT saas_rls_test.assert_true(
  (SELECT rolcanlogin = FALSE AND rolbypassrls = FALSE
   FROM pg_roles WHERE rolname = 'saas_rls_reader'), 'reader must be NOLOGIN / NOBYPASSRLS'
);
SELECT saas_rls_test.assert_true(
  NOT has_table_privilege('saas_rls_reader', 'saas_rls.memberships', 'SELECT')
  AND NOT has_table_privilege('saas_rls_reader', 'saas_rls.resource_grants', 'SELECT')
  AND NOT has_table_privilege('saas_rls_reader', 'saas_rls.resource_catalog', 'INSERT')
  AND NOT has_table_privilege('saas_rls_reader', 'saas_rls.resource_catalog', 'UPDATE')
  AND NOT has_table_privilege('saas_rls_reader', 'saas_rls.resource_catalog', 'DELETE'),
  'reader must not read auth tables or mutate metadata'
);
SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*) = 7
   FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
   WHERE n.nspname = 'saas_rls'
     AND c.relname IN ('tenants', 'projects', 'applications', 'key_bindings',
                       'resource_catalog', 'resource_links', 'routing_bindings')
     AND c.relrowsecurity AND c.relforcerowsecurity),
  'all seven exposed tables need FORCE ROW LEVEL SECURITY'
);

BEGIN;
INSERT INTO saas_rls.tenants(id, name, status) VALUES
  ('demo-north', 'North Studio', 'active'),
  ('demo-orbit', 'Orbit Lab', 'active'),
  ('demo-suspended', 'Paused Test Tenant', 'suspended');

INSERT INTO saas_rls.memberships(actor_id, tenant_id, role, status) VALUES
  ('actor-north', 'demo-north', 'tenant-admin', 'active'),
  ('actor-orbit', 'demo-orbit', 'tenant-viewer', 'active'),
  ('actor-auditor', 'demo-north', 'tenant-auditor', 'active'),
  ('actor-revoked', 'demo-north', 'tenant-owner', 'revoked'),
  ('actor-paused', 'demo-suspended', 'tenant-owner', 'active');

INSERT INTO saas_rls.projects(id, tenant_id, name, status) VALUES
  ('project-north', 'demo-north', 'Customer support', 'active'),
  ('project-orbit', 'demo-orbit', 'Internal research', 'active'),
  ('project-suspended', 'demo-suspended', 'Off limits', 'active');
INSERT INTO saas_rls.applications(id, tenant_id, project_id, name, status) VALUES
  ('app-north', 'demo-north', 'project-north', 'Helpdesk Bot', 'active'),
  ('app-orbit', 'demo-orbit', 'project-orbit', 'Research Assistant', 'active');

INSERT INTO saas_rls.key_bindings
  (id, tenant_id, application_id, key_kind, status) VALUES
  ('key-north', 'demo-north', 'app-north', 'cpa', 'active'),
  ('native-north', 'demo-north', 'app-north', 'core-native', 'active'),
  ('key-orbit', 'demo-orbit', 'app-orbit', 'cpa', 'active');

INSERT INTO saas_rls.resource_catalog
  (id, kind, owner_kind, owner_tenant_id, status) VALUES
  ('pool-north', 'pool', 'tenant', 'demo-north', 'active'),
  ('account-north', 'account', 'tenant', 'demo-north', 'active'),
  ('egress-north', 'egress', 'tenant', 'demo-north', 'active'),
  ('pool-orbit', 'pool', 'tenant', 'demo-orbit', 'active'),
  ('account-orbit', 'account', 'tenant', 'demo-orbit', 'active'),
  ('egress-orbit', 'egress', 'tenant', 'demo-orbit', 'active'),
  ('pool-platform', 'pool', 'platform', NULL, 'active'),
  ('account-platform', 'account', 'platform', NULL, 'active'),
  ('egress-platform', 'egress', 'platform', NULL, 'active'),
  ('account-platform-hidden', 'account', 'platform', NULL, 'active'),
  ('egress-platform-expired', 'egress', 'platform', NULL, 'active');

INSERT INTO saas_rls.resource_grants
  (id, resource_id, resource_kind, grantee_tenant_id, owner_kind,
   owner_tenant_id, status, expires_at) VALUES
  ('grant-pool', 'pool-platform', 'pool', 'demo-north', 'platform', NULL, 'active', NULL),
  ('grant-account', 'account-platform', 'account', 'demo-north', 'platform', NULL, 'active', NULL),
  ('grant-egress', 'egress-platform', 'egress', 'demo-north', 'platform', NULL, 'active', NULL),
  ('wrong-owner-grant', 'account-orbit', 'account', 'demo-north', 'platform', NULL, 'active', NULL),
  ('wrong-type-grant', 'account-orbit', 'pool', 'demo-north', 'tenant', 'demo-orbit', 'active', NULL),
  ('hidden-grant', 'account-platform-hidden', 'account', 'demo-north', 'platform', NULL, 'disabled', NULL),
  ('expired-grant', 'egress-platform-expired', 'egress', 'demo-north', 'platform', NULL,
    'active', '2000-01-01T00:00:00Z');

INSERT INTO saas_rls.resource_links
  (id, link_kind, from_id, to_id, status) VALUES
  ('north-pool-member', 'pool-account', 'pool-north', 'account-north', 'active'),
  ('platform-pool-member', 'pool-account', 'pool-platform', 'account-platform', 'active'),
  ('platform-account-route', 'account-egress', 'account-platform', 'egress-platform', 'active'),
  ('cross-tenant-hidden', 'pool-account', 'pool-platform', 'account-orbit', 'active'),
  ('no-secret-egress', 'account-egress', 'account-platform', 'egress-platform-expired', 'active'),
  ('orbit-pool-member', 'pool-account', 'pool-orbit', 'account-orbit', 'active');

INSERT INTO saas_rls.routing_bindings
  (id, tenant_id, application_id, key_binding_id, pool_id,
   provider_id, requested_model_id, status, egress_policy) VALUES
  ('north-route', 'demo-north', 'app-north', 'key-north', 'pool-north',
    'demo-provider', 'demo-chat', 'active', 'required'),
  ('north-shared-route', 'demo-north', 'app-north', 'key-north', 'pool-platform',
    'demo-provider', 'demo-chat', 'active', 'required'),
  ('north-foreign-pool-route', 'demo-north', 'app-north', 'key-north', 'pool-orbit',
    'demo-provider', 'demo-chat', 'active', 'required'),
  ('north-native-key-route', 'demo-north', 'app-north', 'native-north', 'pool-north',
    'demo-provider', 'demo-chat', 'active', 'required'),
  ('orbit-route', 'demo-orbit', 'app-orbit', 'key-orbit', 'pool-orbit',
    'demo-provider', 'demo-chat', 'active', 'required');

-- 1. Fail closed with no tenant/actor in connection-local context.
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0 FROM saas_rls.tenants),
  'empty context reveals no tenants');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0 FROM saas_rls.resource_catalog),
  'empty context reveals no resources');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0 FROM saas_rls.routing_bindings),
  'empty context reveals no bindings');
RESET ROLE;

-- 2. Explicit trusted North scope: own + THREE separately granted resources.
SELECT set_config('saas.actor_id', 'actor-north', true);
SELECT set_config('saas.tenant_id', 'demo-north', true);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 1 FROM saas_rls.tenants),
  'North may see only its tenant');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 1 FROM saas_rls.projects),
  'North sees own projects only');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 1 FROM saas_rls.applications),
  'North sees own application only');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 1 FROM saas_rls.key_bindings),
  'North sees only CPA key binding, never native Core key');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 6 FROM saas_rls.resource_catalog),
  'North sees 3 owned and exactly 3 individually granted resources');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 3 FROM saas_rls.resource_links),
  'North sees only links where BOTH ends were authorized');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 2 FROM saas_rls.routing_bindings),
  'Routing hides native key bindings and unknown/foreign pool references');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0
  FROM saas_rls.resource_catalog WHERE id LIKE '%orbit%'),
  'a forged account grant must not leak foreign tenant resources');
RESET ROLE;

-- 3. Tenant switch WITHOUT switching actor: no rows, including shared metadata.
SELECT set_config('saas.tenant_id', 'demo-orbit', true);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0 FROM saas_rls.tenants),
  'URL tenant switch does not create an Orbit membership');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0 FROM saas_rls.resource_catalog),
  'tenant switch does not expose Orbit resources');
RESET ROLE;

-- 4. Orbit has its own records, not North or platform grants.
SELECT set_config('saas.actor_id', 'actor-orbit', true);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 3 FROM saas_rls.resource_catalog),
  'Orbit sees only its 3 resources');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 1 FROM saas_rls.resource_links),
  'Orbit sees only the own pool membership');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 1 FROM saas_rls.routing_bindings),
  'Orbit cannot see North routes');
RESET ROLE;

-- 5. Auditor has projects/apps but never sensitive metadata.
SELECT set_config('saas.actor_id', 'actor-auditor', true);
SELECT set_config('saas.tenant_id', 'demo-north', true);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 1 FROM saas_rls.projects),
  'auditor should see tenant project');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 1 FROM saas_rls.applications),
  'auditor should see tenant application');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0 FROM saas_rls.key_bindings),
  'auditor cannot enumerate CPA key bindings');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0 FROM saas_rls.resource_catalog),
  'auditor cannot enumerate accounts/pools/egress');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0 FROM saas_rls.routing_bindings),
  'auditor cannot enumerate routing');
RESET ROLE;

-- 6. Revoked actor + suspended tenant do not disclose anything.
SELECT set_config('saas.actor_id', 'actor-revoked', true);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0 FROM saas_rls.projects),
  'revoked actor cannot read projects');
RESET ROLE;
SELECT set_config('saas.actor_id', 'actor-paused', true);
SELECT set_config('saas.tenant_id', 'demo-suspended', true);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0 FROM saas_rls.tenants),
  'suspended tenant is invisible');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0 FROM saas_rls.projects),
  'suspended tenant project is invisible');
RESET ROLE;

-- 7. Revocation of a SINGLE grant invalidates both the resource and its link.
SELECT set_config('saas.actor_id', 'actor-north', true);
SELECT set_config('saas.tenant_id', 'demo-north', true);
UPDATE saas_rls.resource_grants SET status = 'disabled' WHERE id = 'grant-account';
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 5 FROM saas_rls.resource_catalog),
  'revoking account grant hides account but does not revoke pool or egress');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 1 FROM saas_rls.resource_links),
  'revoked shared account removes pool-member and account-egress links');
RESET ROLE;

-- 8. Revoking pool alone must not revoke independent account and egress grants.
UPDATE saas_rls.resource_grants SET status = 'active' WHERE id = 'grant-account';
UPDATE saas_rls.resource_grants SET status = 'disabled' WHERE id = 'grant-pool';
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 5 FROM saas_rls.resource_catalog),
  'pool grant disabled; account and egress grants remain independent');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 2 FROM saas_rls.resource_links),
  'without pool grant only platform account-egress and North link remain');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 1 FROM saas_rls.routing_bindings),
  'routing reference to revoked pool must not be disclosed');
RESET ROLE;

-- 9. Expiry is evaluated by database time, never by a client-provided clock.
UPDATE saas_rls.resource_grants SET status = 'active' WHERE id = 'grant-pool';
UPDATE saas_rls.resource_grants
  SET expires_at = '2000-01-01T00:00:00Z' WHERE id = 'grant-egress';
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 5 FROM saas_rls.resource_catalog),
  'expired egress grant is denied independently');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 2 FROM saas_rls.resource_links),
  'expired egress removes only account-egress edge');
RESET ROLE;

-- 10. In-place membership revocation denies rows without rebuilding sessions.
UPDATE saas_rls.memberships SET status = 'revoked'
WHERE actor_id = 'actor-north' AND tenant_id = 'demo-north';
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0 FROM saas_rls.resource_catalog),
  'in-flight membership revocation must invalidate RLS visibility');
SELECT saas_rls_test.assert_true((SELECT COUNT(*) = 0 FROM saas_rls.projects),
  'revocation hides even ordinary projects');
RESET ROLE;
ROLLBACK;

\echo 'PASS: staging-only PostgreSQL RLS tenant/role/grant/read-only acceptance'
