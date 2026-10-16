\set ON_ERROR_STOP on
-- Backend 08: disposable PostgreSQL16 only, after a FIRST and ONLY
-- bootstrap in a separate saas_staging_ci database. Never Railway.
DO $verify$
DECLARE
  expected_id text;
  mig_count integer;
BEGIN
  IF current_database() <> 'saas_staging_ci' OR
     current_setting('server_version_num')::integer < 160000 OR
     current_setting('server_version_num')::integer >= 170000 THEN
    RAISE EXCEPTION 'Incorrect bootstrap test database';
  END IF;
  IF to_regnamespace('saas_bootstrap') IS NULL OR
     to_regclass('saas_bootstrap.schema_migrations') IS NULL THEN
    RAISE EXCEPTION 'Migration ledger missing';
  END IF;
  SELECT COUNT(*), MAX(migration_id)
    INTO mig_count, expected_id
    FROM saas_bootstrap.schema_migrations;
  IF mig_count <> 1 OR expected_id <> '0001_ledger_only' THEN
    RAISE EXCEPTION 'Expected exactly one non-replayed migration receipt';
  END IF;
  IF to_regnamespace('saas_rls') IS NOT NULL OR
     to_regnamespace('saas_m1_private') IS NOT NULL OR
     to_regnamespace('saas_m1_api') IS NOT NULL THEN
    RAISE EXCEPTION 'Pilot schema leaked into persistent bootstrap';
  END IF;
  IF pg_catalog.has_schema_privilege('saas_ci_runner', 'saas_bootstrap', 'USAGE') OR
     pg_catalog.has_table_privilege('saas_ci_runner',
       'saas_bootstrap.schema_migrations', 'SELECT') OR
     pg_catalog.has_table_privilege('saas_ci_runner',
       'saas_bootstrap.schema_migrations', 'INSERT') THEN
    RAISE EXCEPTION 'Runtime fixture gained migration metadata rights';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_trigger
    WHERE tgrelid = 'saas_bootstrap.schema_migrations'::regclass
      AND tgname = 'deny_ledger_change' AND NOT tgisinternal
  ) THEN
    RAISE EXCEPTION 'Append-only tripwire missing';
  END IF;
END
$verify$;
SELECT 'PASS Backend08: bootstrap receipt, no pilot schema, no runtime grants' AS result;
