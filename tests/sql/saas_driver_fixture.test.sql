\set ON_ERROR_STOP on
-- Only for the disposable GitHub Actions PostgreSQL database.
-- The runner is never a superuser and has neither ownership nor LOGIN access
-- to the private membership, grant and signer tables.
BEGIN;
DO $role$
BEGIN
  IF current_database() <> 'saas_ephemeral_test' THEN
    RAISE EXCEPTION 'Refusing to create staging driver fixtures on another database';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_ci_runner') THEN
    RAISE EXCEPTION 'Expected a fresh ephemeral role';
  END IF;
  CREATE ROLE saas_ci_runner LOGIN NOINHERIT NOBYPASSRLS;
END
$role$;
-- psql quotes this value as a SQL literal. CI generates random hex and
-- passes it only to this disposable database/bootstrap process.
ALTER ROLE saas_ci_runner PASSWORD :'ephemeral_password';
GRANT saas_rls_reader TO saas_ci_runner;
ALTER ROLE saas_ci_runner SET statement_timeout = '3000ms';

SELECT saas_rls_test.assert_true(
  NOT (SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb
       FROM pg_roles WHERE rolname = 'saas_ci_runner')
  AND pg_has_role('saas_ci_runner', 'saas_rls_reader', 'MEMBER')
  AND NOT has_table_privilege('saas_ci_runner', 'saas_rls.memberships', 'SELECT')
  AND NOT has_table_privilege('saas_ci_runner', 'saas_rls.resource_grants', 'SELECT')
  AND NOT has_table_privilege('saas_ci_runner', 'saas_rls_private.scope_signers', 'SELECT'),
  'runner must be least-privileged and have no signing secrets'
);
COMMIT;

BEGIN;
INSERT INTO saas_rls.tenants(id, name, status) VALUES
  ('demo-north', 'North Studio', 'active'),
  ('demo-orbit', 'Orbit Lab', 'active'),
  ('demo-paused', 'Paused Tenant', 'suspended');

INSERT INTO saas_rls.memberships(actor_id, tenant_id, role, status) VALUES
  ('actor-north', 'demo-north', 'tenant-admin', 'active'),
  ('actor-orbit', 'demo-orbit', 'tenant-viewer', 'active'),
  ('actor-auditor', 'demo-north', 'tenant-auditor', 'active'),
  ('actor-paused', 'demo-paused', 'tenant-owner', 'active');

INSERT INTO saas_rls.projects(id, tenant_id, name, status) VALUES
  ('north-project', 'demo-north', 'North Project', 'active'),
  ('orbit-project', 'demo-orbit', 'Orbit Project', 'active'),
  ('paused-project', 'demo-paused', 'Paused Project', 'active');

INSERT INTO saas_rls.applications(id, tenant_id, project_id, name, status) VALUES
  ('north-app', 'demo-north', 'north-project', 'North App', 'active'),
  ('orbit-app', 'demo-orbit', 'orbit-project', 'Orbit App', 'active');

INSERT INTO saas_rls.key_bindings(id, tenant_id, application_id, key_kind, status) VALUES
  ('north-binding', 'demo-north', 'north-app', 'cpa', 'active'),
  ('north-native', 'demo-north', 'north-app', 'core-native', 'active'),
  ('orbit-binding', 'demo-orbit', 'orbit-app', 'cpa', 'active');

INSERT INTO saas_rls.resource_catalog
  (id, kind, owner_kind, owner_tenant_id, status) VALUES
  ('north-pool', 'pool', 'tenant', 'demo-north', 'active'),
  ('north-account', 'account', 'tenant', 'demo-north', 'active'),
  ('north-egress', 'egress', 'tenant', 'demo-north', 'active'),
  ('orbit-pool', 'pool', 'tenant', 'demo-orbit', 'active'),
  ('orbit-account', 'account', 'tenant', 'demo-orbit', 'active'),
  ('orbit-egress', 'egress', 'tenant', 'demo-orbit', 'active'),
  ('shared-pool', 'pool', 'platform', NULL, 'active'),
  ('shared-account', 'account', 'platform', NULL, 'active'),
  ('shared-egress', 'egress', 'platform', NULL, 'active');

INSERT INTO saas_rls.resource_grants
  (id, resource_id, resource_kind, grantee_tenant_id,
   owner_kind, owner_tenant_id, status) VALUES
  ('grant-pool', 'shared-pool', 'pool', 'demo-north', 'platform', NULL, 'active'),
  ('grant-account', 'shared-account', 'account', 'demo-north', 'platform', NULL, 'active'),
  ('grant-egress', 'shared-egress', 'egress', 'demo-north', 'platform', NULL, 'active');

INSERT INTO saas_rls.resource_links(id, link_kind, from_id, to_id, status) VALUES
  ('north-member', 'pool-account', 'north-pool', 'north-account', 'active'),
  ('orbit-member', 'pool-account', 'orbit-pool', 'orbit-account', 'active'),
  ('shared-member', 'pool-account', 'shared-pool', 'shared-account', 'active'),
  ('shared-network', 'account-egress', 'shared-account', 'shared-egress', 'active');

INSERT INTO saas_rls.routing_bindings
  (id, tenant_id, application_id, key_binding_id, pool_id,
   provider_id, requested_model_id, status, egress_policy) VALUES
  ('north-route', 'demo-north', 'north-app', 'north-binding', 'north-pool',
   'fixture-provider', 'fixture-model', 'active', 'required'),
  ('north-shared', 'demo-north', 'north-app', 'north-binding', 'shared-pool',
   'fixture-provider', 'fixture-model', 'active', 'required'),
  ('orbit-route', 'demo-orbit', 'orbit-app', 'orbit-binding', 'orbit-pool',
   'fixture-provider', 'fixture-model', 'active', 'required');
COMMIT;

\echo 'PASS: disposable non-superuser driver role and synthetic tenant fixtures'
