-- Backend12 / 0003: ONE-SHOT operator-only NOLOGIN runtime roles.
-- Isolated PostgreSQL16 saas_staging / disposable saas_staging_ci ONLY.
-- No passwords, LOGIN credentials, public API, tenant mapping, or data.
-- Persistent staging migrator remains NOLOGIN until a separately audited job.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL statement_timeout = '15s';
SET LOCAL lock_timeout = '3s';
SET LOCAL search_path = pg_catalog, pg_temp;
-- psql variables are substituted OUTSIDE dollar-quoted DO bodies.
SELECT pg_catalog.set_config('saas.b12.operator_sha', :'migration_sha256', true);
SELECT pg_catalog.set_config('saas.b12.operator_commit', :'source_commit', true);

DO $guard$
DECLARE
  role_super boolean;
  rows_count integer;
BEGIN
  IF current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999 OR
     current_database() NOT IN ('saas_staging','saas_staging_ci') OR
     current_setting('saas.staging_only', true) IS DISTINCT FROM 'true' OR
     pg_is_in_recovery() OR current_setting('transaction_read_only') <> 'off' OR
     session_user <> 'postgres' THEN
    RAISE EXCEPTION 'Backend12 runtime-role operator context refused';
  END IF;
  SELECT rolsuper INTO role_super FROM pg_catalog.pg_roles WHERE rolname = session_user;
  IF role_super IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Backend12 requires isolated PostgreSQL operator';
  END IF;
  IF to_regclass('saas_bootstrap.schema_migrations') IS NULL OR
     to_regclass('saas_data.tenants') IS NULL OR
     to_regclass('saas_data.projects') IS NULL OR
     to_regnamespace('saas_acl') IS NOT NULL OR
     EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname IN (
       'saas_runtime_reader','saas_runtime_writer')) THEN
    RAISE EXCEPTION 'Backend12 prior schema or roles ambiguous: stop, never replay';
  END IF;
  SELECT count(*) INTO rows_count FROM saas_bootstrap.schema_migrations;
  IF rows_count <> 2 OR NOT EXISTS (
       SELECT 1 FROM saas_bootstrap.schema_migrations
       WHERE migration_id = '0001_ledger_only'
         AND source_sha256 = '7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279'
     ) OR NOT EXISTS (
       SELECT 1 FROM saas_bootstrap.schema_migrations
       WHERE migration_id = '0002_tenant_projects_baseline'
         AND source_sha256 = '80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f'
     ) OR
     current_setting('saas.b12.operator_sha', true) !~ '^[a-f0-9]{64}$' OR
     current_setting('saas.b12.operator_commit', true) !~ '^[a-f0-9]{40}$' THEN
    RAISE EXCEPTION 'Backend12 untrusted migration chain';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_policy
    WHERE polrelid IN ('saas_data.tenants'::regclass,
                       'saas_data.projects'::regclass)
  ) THEN
    RAISE EXCEPTION 'Backend12 policies already exist, stop';
  END IF;
END
$guard$;

-- NOLOGIN, NOINHERIT, NOBYPASSRLS, no memberships, passwords or grants.
-- These are privilege templates only, NOT tenant/auth identities.
CREATE ROLE saas_runtime_reader
  NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
  NOREPLICATION;
CREATE ROLE saas_runtime_writer
  NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
  NOREPLICATION;

-- Operator-signed-by-hash receipt (NOT cryptographic WORM).
INSERT INTO saas_bootstrap.schema_migrations
  (migration_id, source_sha256, source_commit)
VALUES ('0003_operator_runtime_roles', :'migration_sha256', :'source_commit');

COMMIT;
