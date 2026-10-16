\set ON_ERROR_STOP on
-- Backend10: disposable PostgreSQL16 only, separate saas_staging_ci DB.
-- Test of STRICT RLS deny-all BEFORE any later auth/scope migration.
DO $verify$
DECLARE
  t record;
  tblname text;
  mig_count int;
  policy_count int;
  fk_count int;
  schema_owner name;
BEGIN
  IF current_database() <> 'saas_staging_ci' OR session_user <> 'postgres' OR
     current_setting('server_version_num')::integer < 160000 OR
     current_setting('server_version_num')::integer >= 170000 THEN
    RAISE EXCEPTION 'Backend10 acceptance must only run in disposable PG16';
  END IF;
  SELECT pg_catalog.pg_get_userbyid(nspowner) INTO schema_owner
    FROM pg_catalog.pg_namespace WHERE nspname = 'saas_data';
  IF schema_owner <> 'saas_schema_migrator' THEN
    RAISE EXCEPTION 'Backend10 schema owner is not restricted migrator';
  END IF;
  SELECT COUNT(*) INTO mig_count FROM saas_bootstrap.schema_migrations;
  IF mig_count <> 2 OR NOT EXISTS (
    SELECT 1 FROM saas_bootstrap.schema_migrations
    WHERE migration_id = '0002_tenant_projects_baseline' AND
      source_sha256 ~ '^[a-f0-9]{64}$' AND
      source_commit ~ '^[a-f0-9]{40}$' AND
      applied_by = 'saas_schema_migrator'
  ) THEN
    RAISE EXCEPTION 'Backend10 ledger missing second attested receipt';
  END IF;
  FOR tblname IN SELECT UNNEST(ARRAY['tenants','projects']) LOOP
    SELECT c.relrowsecurity, c.relforcerowsecurity,
           pg_catalog.pg_get_userbyid(c.relowner) AS owner,
           c.relkind
      INTO t
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'saas_data' AND c.relname = tblname;
    IF NOT FOUND OR NOT t.relrowsecurity OR NOT t.relforcerowsecurity OR
       t.owner <> 'saas_schema_migrator' OR t.relkind <> 'r' THEN
      RAISE EXCEPTION 'Backend10 missing forced RLS on %', tblname;
    END IF;
    SELECT COUNT(*) INTO policy_count FROM pg_catalog.pg_policy
      WHERE polrelid = pg_catalog.to_regclass('saas_data.' || tblname);
    IF policy_count <> 0 THEN
      RAISE EXCEPTION 'Backend10 accidentally enabled policies on %', tblname;
    END IF;
    IF pg_catalog.has_table_privilege(
         'saas_ci_runner', 'saas_data.' || tblname, 'SELECT') OR
       pg_catalog.has_table_privilege(
         'saas_ci_runner', 'saas_data.' || tblname, 'INSERT') THEN
      RAISE EXCEPTION 'Backend10 leaked runtime privileges on %', tblname;
    END IF;
  END LOOP;

  SELECT COUNT(*) INTO fk_count FROM pg_catalog.pg_constraint
    WHERE conrelid = 'saas_data.projects'::regclass
      AND contype = 'f'
      AND confrelid = 'saas_data.tenants'::regclass
      AND confdeltype = 'r';
  IF fk_count <> 1 THEN
    RAISE EXCEPTION 'Backend10 project-to-tenant FK not restrictive';
  END IF;
  IF pg_catalog.has_schema_privilege('saas_ci_runner', 'saas_data', 'USAGE') OR
     EXISTS (
       SELECT 1 FROM pg_catalog.pg_namespace n,
         LATERAL pg_catalog.aclexplode(
           COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))
         ) a
       WHERE n.nspname = 'saas_data' AND a.grantee = 0 AND
             a.privilege_type IN ('USAGE', 'CREATE')
     ) OR
     to_regnamespace('saas_rls') IS NOT NULL OR
     to_regnamespace('saas_m1_api') IS NOT NULL OR
     to_regnamespace('saas_m1_private') IS NOT NULL THEN
    RAISE EXCEPTION 'Backend10 schema is not private or pilot SQL leaked';
  END IF;
  IF EXISTS (SELECT 1 FROM saas_data.tenants) OR
     EXISTS (SELECT 1 FROM saas_data.projects) THEN
    RAISE EXCEPTION 'Backend10 schema was not initially empty';
  END IF;
END
$verify$;
SELECT 'PASS Backend10: forced RLS deny-all, tenant FK, no grants, two receipts' AS result;
