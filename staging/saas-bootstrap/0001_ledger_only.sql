-- Backend 08: ONE-SHOT isolated staging migration receipt bootstrap.
-- No tenant tables, provider credentials, Core, Gateway or SQL001-027.
-- Operator-only. This file MUST NOT be run by a service on startup.
-- Requires psql -v bootstrap_sha256=<sha256 of this file>
--               -v source_commit=<exact reviewed 40-hex git commit>.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL statement_timeout = '15s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog, pg_temp;

DO $guard$
DECLARE
  is_superuser boolean;
BEGIN
  IF current_setting('server_version_num')::integer < 160000 OR
     current_setting('server_version_num')::integer >= 170000 THEN
    RAISE EXCEPTION 'Backend08 requires PostgreSQL16';
  END IF;
  IF current_database() NOT IN ('saas_staging', 'saas_staging_ci') OR
     current_setting('saas.staging_only', true) IS DISTINCT FROM 'true' OR
     pg_is_in_recovery() OR
     current_setting('transaction_read_only') <> 'off' THEN
    RAISE EXCEPTION 'Backend08 refused non-staging database';
  END IF;
  IF to_regnamespace('saas_rls') IS NOT NULL OR
     to_regnamespace('saas_rls_private') IS NOT NULL OR
     to_regnamespace('saas_m1_private') IS NOT NULL OR
     to_regnamespace('saas_m1_api') IS NOT NULL OR
     to_regnamespace('saas_bootstrap') IS NOT NULL THEN
    RAISE EXCEPTION 'Backend08 refused an already initialized or pilot database';
  END IF;
  IF current_database() = 'saas_staging' THEN
    SELECT rolsuper INTO is_superuser
      FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF is_superuser IS DISTINCT FROM false THEN
      RAISE EXCEPTION 'Persistent staging requires a non-superuser migrator';
    END IF;
  END IF;
END
$guard$;

-- Owner is the operator-provisioned MIGRATION ROLE, never the SaaS runtime.
-- No IF NOT EXISTS: an unknown previous COMMIT is a manual reconciliation.
CREATE SCHEMA saas_bootstrap;
REVOKE ALL ON SCHEMA saas_bootstrap FROM PUBLIC;

CREATE TABLE saas_bootstrap.schema_migrations (
  migration_id text PRIMARY KEY
    CHECK (migration_id ~ '^[0-9]{4}_[a-z0-9_]+$'),
  source_sha256 text NOT NULL
    CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
  source_commit text NOT NULL
    CHECK (source_commit ~ '^[a-f0-9]{40}$'),
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  applied_by name NOT NULL DEFAULT session_user
);

-- Append-only guard is an operational tripwire, NOT tamper-proof/WORM:
-- the schema owner can still change DDL and must be externally audited.
CREATE FUNCTION saas_bootstrap.reject_ledger_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $reject$
BEGIN
  RAISE EXCEPTION 'Schema migration receipts are append-only';
END
$reject$;
REVOKE ALL ON FUNCTION saas_bootstrap.reject_ledger_mutation() FROM PUBLIC;
CREATE TRIGGER deny_ledger_change
BEFORE UPDATE OR DELETE ON saas_bootstrap.schema_migrations
FOR EACH ROW EXECUTE FUNCTION saas_bootstrap.reject_ledger_mutation();

REVOKE ALL ON TABLE saas_bootstrap.schema_migrations FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA saas_bootstrap
  REVOKE ALL ON TABLES FROM PUBLIC;

INSERT INTO saas_bootstrap.schema_migrations
  (migration_id, source_sha256, source_commit)
VALUES ('0001_ledger_only', :'bootstrap_sha256', :'source_commit');

COMMENT ON SCHEMA saas_bootstrap IS
  'Operator-owned staging-only migration ledger, not an application schema';
COMMIT;
