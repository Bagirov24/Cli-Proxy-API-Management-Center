\set ON_ERROR_STOP on
-- Backend09: disposable PostgreSQL16 role isolation contract.
-- This test MUST run only in a distinct saas_staging_ci database after
-- operator role 0000 and non-superuser receipt 0001, never on Railway.
DO $verify$
DECLARE
  role_attributes record;
  current_owner name;
  ledger_owner name;
  db_owner name;
  total integer;
  last_actor name;
BEGIN
  IF current_database() <> 'saas_staging_ci' OR
     current_setting('server_version_num')::integer < 160000 OR
     current_setting('server_version_num')::integer >= 170000 OR
     session_user <> 'postgres' THEN
    RAISE EXCEPTION 'Backend09 role assertions must run in disposable PG16';
  END IF;

  SELECT rolcanlogin, rolsuper, rolinherit, rolcreaterole,
         rolcreatedb, rolreplication, rolbypassrls
    INTO role_attributes
    FROM pg_catalog.pg_roles WHERE rolname = 'saas_schema_migrator';
  IF NOT FOUND OR NOT role_attributes.rolcanlogin OR
     role_attributes.rolsuper OR role_attributes.rolinherit OR
     role_attributes.rolcreaterole OR role_attributes.rolcreatedb OR
     role_attributes.rolreplication OR role_attributes.rolbypassrls THEN
    RAISE EXCEPTION 'Backend09 identity role has excessive privileges';
  END IF;

  IF (SELECT COUNT(*) FROM pg_catalog.pg_auth_members
      WHERE member = 'saas_schema_migrator'::regrole) <> 0 OR
     NOT pg_catalog.has_database_privilege(
       'saas_schema_migrator', current_database(), 'CONNECT') OR
     NOT pg_catalog.has_database_privilege(
       'saas_schema_migrator', current_database(), 'CREATE') OR
     pg_catalog.has_database_privilege(
       'saas_schema_migrator', 'saas_ephemeral_test', 'CREATE') OR
     pg_catalog.has_database_privilege(
       'saas_ci_runner', current_database(), 'CONNECT') THEN
    RAISE EXCEPTION 'Backend09 migrator database rights crossed the boundary';
  END IF;

  SELECT pg_catalog.pg_get_userbyid(nspowner)
    INTO current_owner
    FROM pg_catalog.pg_namespace WHERE nspname = 'saas_bootstrap';
  SELECT pg_catalog.pg_get_userbyid(relowner)
    INTO ledger_owner
    FROM pg_catalog.pg_class
    WHERE oid = 'saas_bootstrap.schema_migrations'::regclass;
  SELECT pg_catalog.pg_get_userbyid(datdba)
    INTO db_owner
    FROM pg_catalog.pg_database
    WHERE datname = current_database();
  SELECT COUNT(*), MAX(applied_by)
    INTO total, last_actor
    FROM saas_bootstrap.schema_migrations;
  IF current_owner <> 'saas_schema_migrator' OR
     ledger_owner <> 'saas_schema_migrator' OR db_owner <> 'postgres' OR
     total <> 1 OR last_actor <> 'saas_schema_migrator' THEN
    RAISE EXCEPTION 'Backend09 ledger was not built by restricted schema owner';
  END IF;

  IF pg_catalog.has_schema_privilege(
       'saas_ci_runner', 'saas_bootstrap', 'USAGE') OR
     pg_catalog.has_schema_privilege(
       'saas_ci_runner', 'public', 'USAGE') OR
     pg_catalog.has_table_privilege('saas_ci_runner',
       'saas_bootstrap.schema_migrations', 'SELECT') THEN
    RAISE EXCEPTION 'Backend09 runtime role can read migration metadata';
  END IF;

  IF to_regnamespace('saas_rls') IS NOT NULL OR
     to_regnamespace('saas_m1_private') IS NOT NULL OR
     to_regnamespace('saas_m1_api') IS NOT NULL THEN
    RAISE EXCEPTION 'Backend09 unexpectedly contains pilot schemas';
  END IF;
END
$verify$;
SELECT 'PASS Backend09: restricted migrator, no inheritance/grants, PG16 ledger owner' AS result;
