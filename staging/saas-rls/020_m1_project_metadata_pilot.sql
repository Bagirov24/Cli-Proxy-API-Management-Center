-- M1a project-metadata CRUD capability. EPHEMERAL PostgreSQL16 CI ONLY.
-- Not part of production migration chain. No network, secrets or Core data.
-- Explicit hard stop: current_database + postgres installer + staging flag.
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
     OR current_user <> 'postgres'
     OR current_setting('saas.staging_only', true) IS DISTINCT FROM 'true'
     OR to_regprocedure('saas_rls.authorized_revision(text,text,text,text)') IS NULL
     OR to_regprocedure('saas_rls_private.scope_verified()') IS NULL THEN
    RAISE EXCEPTION 'M1a project pilot must run ONLY in disposable PG16 CI';
  END IF;
END
$guard$;

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_m1_project_owner') THEN
    CREATE ROLE saas_m1_project_owner NOLOGIN NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_m1_project_executor') THEN
    CREATE ROLE saas_m1_project_executor NOLOGIN NOINHERIT NOBYPASSRLS;
  END IF;
END
$roles$;
ALTER ROLE saas_m1_project_owner NOLOGIN NOINHERIT NOBYPASSRLS;
ALTER ROLE saas_m1_project_executor NOLOGIN NOINHERIT NOBYPASSRLS;

CREATE SCHEMA IF NOT EXISTS saas_m1_private AUTHORIZATION saas_m1_project_owner;
ALTER SCHEMA saas_m1_private OWNER TO saas_m1_project_owner;
REVOKE ALL ON SCHEMA saas_m1_private FROM PUBLIC, saas_m1_project_executor, saas_rls_reader;

CREATE SCHEMA IF NOT EXISTS saas_m1_api AUTHORIZATION saas_m1_project_owner;
ALTER SCHEMA saas_m1_api OWNER TO saas_m1_project_owner;
REVOKE ALL ON SCHEMA saas_m1_api FROM PUBLIC, saas_rls_reader;
GRANT USAGE ON SCHEMA saas_m1_api TO saas_m1_project_executor;

-- The trusted function owner may invoke the existing signed tx-scoped
-- authorization revision; the executor is NEVER granted the signing key.
GRANT USAGE ON SCHEMA saas_rls TO saas_m1_project_owner;
GRANT EXECUTE ON FUNCTION saas_rls.authorized_revision(TEXT,TEXT,TEXT,TEXT)
  TO saas_m1_project_owner;

CREATE TABLE IF NOT EXISTS saas_m1_private.projects (
  tenant_id TEXT NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_-]{1,64}$'),
  project_id TEXT NOT NULL CHECK (project_id ~ '^[A-Za-z0-9_-]{1,64}$'),
  name TEXT NOT NULL CHECK (
    char_length(name) BETWEEN 1 AND 120
    AND name = btrim(name)
    AND name !~ '[[:cntrl:]]'
  ),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'disabled')),
  version BIGINT NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, project_id)
);
ALTER TABLE saas_m1_private.projects OWNER TO saas_m1_project_owner;
REVOKE ALL ON saas_m1_private.projects FROM PUBLIC, saas_m1_project_executor, saas_rls_reader;
ALTER TABLE saas_m1_private.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_m1_private.projects FORCE ROW LEVEL SECURITY;

-- A signed PostgreSQL transaction scope is required, but *not sufficient*.
-- The DB independently resolves CURRENT membership and tenant status from
-- migration 004's authorized_revision. No role, actor or tenant from JWT
-- claims/headers grants access. A tenant-admin/owner may mutate, while a
-- viewer/auditor may only read the sanitized metadata.
CREATE OR REPLACE FUNCTION saas_m1_private.can_read(target_tenant TEXT)
RETURNS BOOLEAN LANGUAGE sql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT COALESCE(
    saas_rls.authorized_revision(
      target_tenant, current_setting('saas.scope_actor',true),
      'tenant-owner', 'projects') IS NOT NULL
    OR saas_rls.authorized_revision(
      target_tenant, current_setting('saas.scope_actor',true),
      'tenant-admin', 'projects') IS NOT NULL
    OR saas_rls.authorized_revision(
      target_tenant, current_setting('saas.scope_actor',true),
      'tenant-viewer', 'projects') IS NOT NULL
    OR saas_rls.authorized_revision(
      target_tenant, current_setting('saas.scope_actor',true),
      'tenant-auditor', 'projects') IS NOT NULL, FALSE);
$fn$;
CREATE OR REPLACE FUNCTION saas_m1_private.can_write(target_tenant TEXT)
RETURNS BOOLEAN LANGUAGE sql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT COALESCE(
    saas_rls.authorized_revision(
      target_tenant, current_setting('saas.scope_actor',true),
      'tenant-owner', 'projects') IS NOT NULL
    OR saas_rls.authorized_revision(
      target_tenant, current_setting('saas.scope_actor',true),
      'tenant-admin', 'projects') IS NOT NULL, FALSE);
$fn$;
ALTER FUNCTION saas_m1_private.can_read(TEXT) OWNER TO saas_m1_project_owner;
ALTER FUNCTION saas_m1_private.can_write(TEXT) OWNER TO saas_m1_project_owner;
REVOKE ALL ON FUNCTION saas_m1_private.can_read(TEXT) FROM PUBLIC, saas_m1_project_executor, saas_rls_reader;
REVOKE ALL ON FUNCTION saas_m1_private.can_write(TEXT) FROM PUBLIC, saas_m1_project_executor, saas_rls_reader;

DROP POLICY IF EXISTS m1_signed_read ON saas_m1_private.projects;
CREATE POLICY m1_signed_read ON saas_m1_private.projects
  FOR SELECT TO saas_m1_project_owner
  USING (saas_m1_private.can_read(tenant_id));

DROP POLICY IF EXISTS m1_signed_insert ON saas_m1_private.projects;
CREATE POLICY m1_signed_insert ON saas_m1_private.projects
  FOR INSERT TO saas_m1_project_owner
  WITH CHECK (saas_m1_private.can_write(tenant_id));

DROP POLICY IF EXISTS m1_signed_update ON saas_m1_private.projects;
CREATE POLICY m1_signed_update ON saas_m1_private.projects
  FOR UPDATE TO saas_m1_project_owner
  USING (saas_m1_private.can_write(tenant_id))
  WITH CHECK (saas_m1_private.can_write(tenant_id));

-- No table DML is granted to the executor. It can ONLY call four
-- narrow SECURITY DEFINER operations that fail closed and never raise
-- user-derived error text. Physical DELETE is intentionally impossible.
CREATE OR REPLACE FUNCTION saas_m1_api.create_project(
  target_tenant TEXT, target_project TEXT, target_name TEXT
) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE affected INTEGER;
BEGIN
  IF target_tenant IS NULL OR target_tenant !~ '^[A-Za-z0-9_-]{1,64}$'
     OR target_project IS NULL OR target_project !~ '^[A-Za-z0-9_-]{1,64}$'
     OR target_name IS NULL OR char_length(target_name) NOT BETWEEN 1 AND 120
     OR target_name <> btrim(target_name) OR target_name ~ '[[:cntrl:]]'
     OR NOT saas_m1_private.can_write(target_tenant) THEN
    RETURN FALSE;
  END IF;
  INSERT INTO saas_m1_private.projects (tenant_id,project_id,name)
    VALUES (target_tenant,target_project,target_name)
    ON CONFLICT (tenant_id,project_id) DO NOTHING;
  GET DIAGNOSTICS affected = ROW_COUNT;
  RETURN affected = 1;
EXCEPTION WHEN OTHERS THEN RETURN FALSE;
END
$fn$;

CREATE OR REPLACE FUNCTION saas_m1_api.get_project(
  target_tenant TEXT, target_project TEXT
) RETURNS TABLE(project_id TEXT,name TEXT,status TEXT,version BIGINT)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF target_tenant IS NULL OR target_tenant !~ '^[A-Za-z0-9_-]{1,64}$'
     OR target_project IS NULL OR target_project !~ '^[A-Za-z0-9_-]{1,64}$'
     OR NOT saas_m1_private.can_read(target_tenant) THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT p.project_id,p.name,p.status,p.version
    FROM saas_m1_private.projects AS p
    WHERE p.tenant_id=target_tenant AND p.project_id=target_project;
END
$fn$;

CREATE OR REPLACE FUNCTION saas_m1_api.rename_project(
  target_tenant TEXT, target_project TEXT, target_name TEXT, expected_version BIGINT
) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE affected INTEGER;
BEGIN
  IF target_tenant IS NULL OR target_tenant !~ '^[A-Za-z0-9_-]{1,64}$'
     OR target_project IS NULL OR target_project !~ '^[A-Za-z0-9_-]{1,64}$'
     OR target_name IS NULL OR char_length(target_name) NOT BETWEEN 1 AND 120
     OR target_name <> btrim(target_name) OR target_name ~ '[[:cntrl:]]'
     OR expected_version IS NULL OR expected_version < 1
     OR NOT saas_m1_private.can_write(target_tenant) THEN
    RETURN FALSE;
  END IF;
  UPDATE saas_m1_private.projects AS p
    SET name=target_name, version=p.version+1
  WHERE p.tenant_id=target_tenant AND p.project_id=target_project
    AND p.version=expected_version AND p.status='active';
  GET DIAGNOSTICS affected = ROW_COUNT;
  RETURN affected = 1;
EXCEPTION WHEN OTHERS THEN RETURN FALSE;
END
$fn$;

CREATE OR REPLACE FUNCTION saas_m1_api.disable_project(
  target_tenant TEXT, target_project TEXT, expected_version BIGINT
) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE affected INTEGER;
BEGIN
  IF target_tenant IS NULL OR target_tenant !~ '^[A-Za-z0-9_-]{1,64}$'
     OR target_project IS NULL OR target_project !~ '^[A-Za-z0-9_-]{1,64}$'
     OR expected_version IS NULL OR expected_version < 1
     OR NOT saas_m1_private.can_write(target_tenant) THEN
    RETURN FALSE;
  END IF;
  UPDATE saas_m1_private.projects AS p
    SET status='disabled', version=p.version+1
  WHERE p.tenant_id=target_tenant AND p.project_id=target_project
    AND p.version=expected_version AND p.status='active';
  GET DIAGNOSTICS affected = ROW_COUNT;
  RETURN affected = 1;
EXCEPTION WHEN OTHERS THEN RETURN FALSE;
END
$fn$;

ALTER FUNCTION saas_m1_api.create_project(TEXT,TEXT,TEXT) OWNER TO saas_m1_project_owner;
ALTER FUNCTION saas_m1_api.get_project(TEXT,TEXT) OWNER TO saas_m1_project_owner;
ALTER FUNCTION saas_m1_api.rename_project(TEXT,TEXT,TEXT,BIGINT) OWNER TO saas_m1_project_owner;
ALTER FUNCTION saas_m1_api.disable_project(TEXT,TEXT,BIGINT) OWNER TO saas_m1_project_owner;
REVOKE ALL ON FUNCTION saas_m1_api.create_project(TEXT,TEXT,TEXT) FROM PUBLIC, saas_rls_reader;
REVOKE ALL ON FUNCTION saas_m1_api.get_project(TEXT,TEXT) FROM PUBLIC, saas_rls_reader;
REVOKE ALL ON FUNCTION saas_m1_api.rename_project(TEXT,TEXT,TEXT,BIGINT) FROM PUBLIC, saas_rls_reader;
REVOKE ALL ON FUNCTION saas_m1_api.disable_project(TEXT,TEXT,BIGINT) FROM PUBLIC, saas_rls_reader;
GRANT EXECUTE ON FUNCTION saas_m1_api.create_project(TEXT,TEXT,TEXT)
  TO saas_m1_project_executor;
GRANT EXECUTE ON FUNCTION saas_m1_api.get_project(TEXT,TEXT)
  TO saas_m1_project_executor;
GRANT EXECUTE ON FUNCTION saas_m1_api.rename_project(TEXT,TEXT,TEXT,BIGINT)
  TO saas_m1_project_executor;
GRANT EXECUTE ON FUNCTION saas_m1_api.disable_project(TEXT,TEXT,BIGINT)
  TO saas_m1_project_executor;

DO $assert$
BEGIN
  IF has_table_privilege('saas_m1_project_executor','saas_m1_private.projects','SELECT')
     OR has_table_privilege('saas_m1_project_executor','saas_m1_private.projects','INSERT')
     OR has_table_privilege('saas_m1_project_executor','saas_m1_private.projects','UPDATE')
     OR has_table_privilege('saas_m1_project_executor','saas_m1_private.projects','DELETE')
     OR has_schema_privilege('saas_m1_project_executor','saas_m1_private','USAGE')
     OR has_function_privilege('saas_rls_reader','saas_m1_api.create_project(text,text,text)','EXECUTE')
     OR has_function_privilege('saas_m1_project_executor','saas_rls_private.scope_verified()','EXECUTE')
     OR NOT (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
             WHERE oid='saas_m1_private.projects'::REGCLASS) THEN
    RAISE EXCEPTION 'M1a executor/table signer ACLs are unsafe';
  END IF;
END
$assert$;
COMMIT;
\echo 'PASS M1a: disposable signed-scope project CRUD with no table DML/delete capability installed'
