-- Backend09: one-shot operator-owned PostgreSQL16 STAGING migrator role.
-- NEVER run in startup, app deploy, CPA Core/Gateway, or production.
-- Run ONLY from an independently reviewed operator session, with:
--   PGOPTIONS='-c saas.staging_only=true' psql -X -v ON_ERROR_STOP=1
--   -d saas_staging -v migration_password=<external high-entropy hex>
-- This is NOT 0001_ledger_only.sql and DOES NOT install any pilot SQL001-027.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL statement_timeout = '15s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog, pg_temp;

DO $guard$
BEGIN
  IF current_setting('server_version_num')::integer < 160000 OR
     current_setting('server_version_num')::integer >= 170000 OR
     current_database() NOT IN ('saas_staging', 'saas_staging_ci') OR
     current_setting('saas.staging_only', true) IS DISTINCT FROM 'true' OR
     pg_is_in_recovery() OR
     current_setting('transaction_read_only') <> 'off' OR
     session_user <> 'postgres' THEN
    RAISE EXCEPTION 'Backend09 operator role bootstrap refused';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles
             WHERE rolname = 'saas_schema_migrator') THEN
    RAISE EXCEPTION 'Backend09 migrator already exists: reconcile, no retry';
  END IF;
  IF to_regnamespace('saas_bootstrap') IS NOT NULL OR
     to_regnamespace('saas_rls') IS NOT NULL OR
     to_regnamespace('saas_rls_private') IS NOT NULL OR
     to_regnamespace('saas_m1_private') IS NOT NULL OR
     to_regnamespace('saas_m1_api') IS NOT NULL THEN
    RAISE EXCEPTION 'Backend09 requires a fresh standalone SaaS database';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_namespace
    WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'public',
                         'pg_toast') AND nspname NOT LIKE 'pg_temp_%'
      AND nspname NOT LIKE 'pg_toast_temp_%'
  ) THEN
    RAISE EXCEPTION 'Backend09 refused pre-existing application schemas';
  END IF;
END
$guard$;

-- Require a randomly generated >=48 hex-character password. Nothing here
-- prints the value; supply it through a protected operator secret channel.
-- Error on invalid/missing psql variable; NO fallback password.
SELECT 1 / (CASE WHEN length(:'migration_password') BETWEEN 48 AND 128
                     AND :'migration_password' ~ '^[0-9a-f]+$'
                 THEN 1 ELSE 0 END) AS credential_policy_check;

CREATE ROLE saas_schema_migrator
  WITH LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
       NOREPLICATION PASSWORD :'migration_password';

DO $grants$
BEGIN
  -- Lock down this dedicated database; other Railway projects/databases
  -- are NEVER referenced. The postgres operator retains superuser access.
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC',
                 current_database());
  EXECUTE format('GRANT CONNECT, CREATE ON DATABASE %I TO saas_schema_migrator',
                 current_database());
END
$grants$;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- No table, schema, role-membership, CREATEROLE, BYPASSRLS, GRANT OPTION,
-- or session/issuer/project capability is conferred here.
COMMIT;
