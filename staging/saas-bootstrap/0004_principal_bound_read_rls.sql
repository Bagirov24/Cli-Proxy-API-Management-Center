-- Backend12 / 0004: STRICT PostgreSQL principal-bound READ-ONLY tenant RLS.
-- No signed HTTP/session identities, writable grants or public listener.
-- NO trusts of arbitrary current_setting('tenant_id'), request header or SET ROLE.
-- Requires the genuine saas_schema_migrator LOGIN temporarily provisioned
-- by an operator; reinstate NOLOGIN after the reviewed one-shot job.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL statement_timeout = '20s';
SET LOCAL lock_timeout = '3s';
SET LOCAL search_path = pg_catalog, pg_temp;
SELECT pg_catalog.set_config('saas.b12.prior_roles_sha', :'expected_0003_sha256', true);
SELECT pg_catalog.set_config('saas.b12.policy_sha', :'migration_sha256', true);
SELECT pg_catalog.set_config('saas.b12.policy_commit', :'source_commit', true);

DO $guard$
DECLARE
  count_roles integer;
  n integer;
  attrs record;
BEGIN
  IF current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999 OR
     current_database() NOT IN ('saas_staging','saas_staging_ci') OR
     current_setting('saas.staging_only', true) IS DISTINCT FROM 'true' OR
     pg_is_in_recovery() OR current_setting('transaction_read_only') <> 'off' OR
     session_user <> 'saas_schema_migrator' THEN
    RAISE EXCEPTION 'Backend12 RLS policy migrator context refused';
  END IF;
  SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb
    INTO attrs FROM pg_catalog.pg_roles WHERE rolname=session_user;
  IF NOT FOUND OR attrs.rolsuper OR attrs.rolbypassrls OR
     attrs.rolcreaterole OR attrs.rolcreatedb THEN
    RAISE EXCEPTION 'Backend12 refused privileged migrator';
  END IF;
  SELECT count(*) INTO n FROM saas_bootstrap.schema_migrations;
  IF n <> 3 OR
     NOT EXISTS (SELECT 1 FROM saas_bootstrap.schema_migrations
                 WHERE migration_id='0001_ledger_only' AND
                       source_sha256='7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279') OR
     NOT EXISTS (SELECT 1 FROM saas_bootstrap.schema_migrations
                 WHERE migration_id='0002_tenant_projects_baseline' AND
                       source_sha256='80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f') OR
     NOT EXISTS (SELECT 1 FROM saas_bootstrap.schema_migrations
                 WHERE migration_id='0003_operator_runtime_roles' AND
                       source_sha256=current_setting('saas.b12.prior_roles_sha',true)) OR
     current_setting('saas.b12.prior_roles_sha',true) !~ '^[a-f0-9]{64}$' OR
     current_setting('saas.b12.policy_sha',true) !~ '^[a-f0-9]{64}$' OR
     current_setting('saas.b12.policy_commit',true) !~ '^[a-f0-9]{40}$' THEN
    RAISE EXCEPTION 'Backend12 mismatched or uncertain migration receipts';
  END IF;
  SELECT count(*) INTO count_roles FROM pg_catalog.pg_roles
    WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer')
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
      AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb
      AND NOT rolreplication;
  IF count_roles <> 2 OR
     EXISTS (
       SELECT 1 FROM pg_catalog.pg_auth_members
       WHERE roleid IN (SELECT oid FROM pg_catalog.pg_roles
                        WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer'))
     ) OR
     to_regnamespace('saas_acl') IS NOT NULL OR
     EXISTS (SELECT 1 FROM pg_catalog.pg_policy
             WHERE polrelid IN ('saas_data.tenants'::regclass,
                                'saas_data.projects'::regclass)) OR
     EXISTS (SELECT 1 FROM pg_catalog.pg_class
             WHERE oid IN ('saas_data.tenants'::regclass,
                           'saas_data.projects'::regclass)
               AND (NOT relrowsecurity OR NOT relforcerowsecurity)) THEN
    RAISE EXCEPTION 'Backend12 runtime role/policy baseline ambiguous';
  END IF;
END
$guard$;

-- Operator-managed map: no PUBLIC or runtime SELECT/INSERT/UPDATE/DELETE.
-- In staging the only writer is operator/admin (or sealed schema owner).
CREATE SCHEMA saas_acl AUTHORIZATION saas_schema_migrator;
REVOKE ALL ON SCHEMA saas_acl FROM PUBLIC;

CREATE TABLE saas_acl.principal_tenants (
  principal_name name NOT NULL
    CHECK (principal_name NOT IN ('postgres','saas_schema_migrator',
                                  'saas_runtime_reader','saas_runtime_writer')),
  tenant_id uuid NOT NULL REFERENCES saas_data.tenants(tenant_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  access_level text NOT NULL CHECK (access_level IN ('reader','writer')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (principal_name, tenant_id)
);
REVOKE ALL ON saas_acl.principal_tenants FROM PUBLIC;

-- SECURITY DEFINER only to read the PRIVATE allowlist. This is NOT a
-- tenant-assertion GUC: session_user is the authenticated DB login and
-- persists across SET ROLE and changes to application-defined GUC values.
-- No dynamic SQL, no table writes, no provider secrets, no auth bootstrap.
CREATE FUNCTION saas_acl.can_read_tenant(subject_tenant uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $access$
  SELECT
    current_setting('saas.staging_only', true) IS NOT DISTINCT FROM 'true'
    AND session_user NOT IN ('postgres', 'saas_schema_migrator')
    AND EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles r
      WHERE r.rolname = session_user
        AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls
    )
    AND EXISTS (
      SELECT 1 FROM saas_acl.principal_tenants x
      WHERE x.principal_name = session_user::name
        AND x.tenant_id = subject_tenant
        AND x.access_level IN ('reader', 'writer')
    );
$access$;
REVOKE ALL ON FUNCTION saas_acl.can_read_tenant(uuid) FROM PUBLIC;
GRANT USAGE ON SCHEMA saas_acl TO saas_runtime_reader, saas_runtime_writer;
GRANT EXECUTE ON FUNCTION saas_acl.can_read_tenant(uuid)
  TO saas_runtime_reader, saas_runtime_writer;

GRANT USAGE ON SCHEMA saas_data TO saas_runtime_reader, saas_runtime_writer;
GRANT SELECT ON saas_data.tenants, saas_data.projects
  TO saas_runtime_reader, saas_runtime_writer;

-- One precise SELECT policy per relation. INSERT, UPDATE and DELETE have
-- NO policies, and runtime roles have NO DML grants: fail closed twice.
CREATE POLICY tenant_principal_read ON saas_data.tenants
  FOR SELECT TO saas_runtime_reader, saas_runtime_writer
  USING (saas_acl.can_read_tenant(tenant_id));
CREATE POLICY project_principal_read ON saas_data.projects
  FOR SELECT TO saas_runtime_reader, saas_runtime_writer
  USING (saas_acl.can_read_tenant(tenant_id));

INSERT INTO saas_bootstrap.schema_migrations
  (migration_id, source_sha256, source_commit)
VALUES ('0004_principal_bound_read_rls', :'migration_sha256', :'source_commit');

COMMIT;
