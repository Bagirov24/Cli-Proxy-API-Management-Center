\set ON_ERROR_STOP on
-- M1b: grant an isolated NOLOGIN project executor to the disposable CI runner.
-- Must execute only AFTER M1a SQL acceptance, never on production PostgreSQL.
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
     OR current_user <> 'postgres'
     OR current_setting('saas.staging_only', true) IS DISTINCT FROM 'true'
     OR NOT EXISTS (
       SELECT 1 FROM pg_roles
       WHERE rolname='saas_ci_runner'
         AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
     OR NOT EXISTS (
       SELECT 1 FROM pg_roles
       WHERE rolname='saas_m1_project_executor'
         AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
  THEN
    RAISE EXCEPTION 'M1b driver grant refused outside disposable PG16 CI';
  END IF;
END
$guard$;
GRANT saas_m1_project_executor TO saas_ci_runner;
SELECT saas_rls_test.assert_true(
  pg_has_role('saas_ci_runner','saas_m1_project_executor','MEMBER')
  AND NOT has_schema_privilege('saas_ci_runner','saas_m1_private','USAGE')
  AND NOT has_table_privilege('saas_ci_runner','saas_m1_private.projects','SELECT')
  AND NOT has_table_privilege('saas_ci_runner','saas_m1_private.projects','INSERT')
  AND NOT has_table_privilege('saas_ci_runner','saas_m1_private.projects','UPDATE')
  AND NOT has_table_privilege('saas_ci_runner','saas_m1_private.projects','DELETE')
  AND NOT has_table_privilege('saas_ci_runner','saas_rls_private.scope_signers','SELECT'),
  'M1b runner may SET ROLE only; signer key and table DML remain private'
);
COMMIT;
\echo 'PASS M1b: temporary non-superuser project-executor role grant, no direct table/signer access'