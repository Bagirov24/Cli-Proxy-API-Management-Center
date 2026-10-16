\set ON_ERROR_STOP on
-- Backend13 PG16 disposable CI contract; called after 0005 and before any
-- synthetic tenant/login is ever created.
DO $contract$
DECLARE
  n int;
  fn record;
  t text;
  role_name text;
BEGIN
  IF current_database()<>'saas_staging_ci' OR session_user<>'postgres'
     OR current_setting('server_version_num')::int NOT BETWEEN 160000 AND 169999
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'Backend13 SQL contract refused outside disposable CI';
  END IF;
  SELECT count(*) INTO n FROM saas_bootstrap.schema_migrations;
  IF n<>5 OR NOT EXISTS (
    SELECT 1 FROM saas_bootstrap.schema_migrations
    WHERE migration_id='0005_principal_lifecycle_revocation_fence'
      AND source_sha256 ~ '^[a-f0-9]{64}$'
      AND source_commit ~ '^[a-f0-9]{40}$'
      AND applied_by='saas_schema_migrator'
  ) THEN
    RAISE EXCEPTION 'Backend13 new migration receipt missing';
  END IF;
  IF (SELECT count(*) FROM saas_data.tenants)<>0
     OR (SELECT count(*) FROM saas_data.projects)<>0
     OR (SELECT count(*) FROM saas_acl.principal_tenants)<>0
     OR (SELECT count(*) FROM saas_acl.principal_access_audit)<>0 THEN
    RAISE EXCEPTION 'Backend13 has unexpected live/fixture data';
  END IF;
  SELECT prosecdef,provolatile,proconfig INTO fn
    FROM pg_catalog.pg_proc
    WHERE oid='saas_acl.can_read_tenant(uuid)'::regprocedure;
  IF NOT FOUND OR NOT fn.prosecdef OR fn.provolatile<>'v'
     OR NOT (fn.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']) THEN
    RAISE EXCEPTION 'Backend13 revocation fence is not VOLATILE SECURITY DEFINER';
  END IF;
  SELECT prosecdef,provolatile,proconfig INTO fn
    FROM pg_catalog.pg_proc
    WHERE oid='saas_acl.change_principal_access(name,uuid,bigint,text,text)'::regprocedure;
  IF NOT FOUND OR fn.prosecdef OR fn.provolatile<>'v'
     OR NOT (fn.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']) THEN
    RAISE EXCEPTION 'Backend13 operator transition must be SECURITY INVOKER';
  END IF;
  FOR role_name IN SELECT unnest(ARRAY['saas_runtime_reader','saas_runtime_writer']) LOOP
    IF pg_catalog.has_function_privilege(
       role_name,'saas_acl.change_principal_access(name,uuid,bigint,text,text)',
       'EXECUTE')
       OR NOT pg_catalog.has_function_privilege(role_name,
         'saas_acl.can_read_tenant(uuid)','EXECUTE')
       OR pg_catalog.has_table_privilege(role_name,
         'saas_acl.principal_tenants','SELECT')
       OR pg_catalog.has_table_privilege(role_name,
         'saas_acl.principal_access_audit','SELECT')
       OR pg_catalog.has_table_privilege(role_name,
         'saas_acl.principal_access_audit','INSERT')
       OR pg_catalog.has_table_privilege(role_name,
         'saas_data.projects','UPDATE')
       OR pg_catalog.has_table_privilege(role_name,
         'saas_data.tenants','DELETE') THEN
      RAISE EXCEPTION 'Backend13 runtime template gained excess privileges';
    END IF;
  END LOOP;
  IF (SELECT count(*) FROM pg_catalog.pg_trigger
      WHERE tgrelid='saas_acl.principal_tenants'::regclass
        AND NOT tgisinternal AND tgenabled IN ('O','A'))<>2
     OR (SELECT count(*) FROM pg_catalog.pg_trigger
      WHERE tgrelid='saas_acl.principal_access_audit'::regclass
        AND NOT tgisinternal AND tgenabled IN ('O','A'))<>2 THEN
    RAISE EXCEPTION 'Backend13 audit or tombstone protection triggers missing';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_indexes
    WHERE schemaname='saas_acl'
      AND tablename='principal_tenants'
      AND indexname='principal_one_active_tenant_idx'
      AND indexdef LIKE '%UNIQUE%'
  ) THEN
    RAISE EXCEPTION 'Backend13 single-tenant login fence missing';
  END IF;
  FOR t IN SELECT unnest(ARRAY['tenants','projects']) LOOP
    IF (SELECT count(*) FROM pg_catalog.pg_policy
        WHERE polrelid=('saas_data.'||t)::regclass
          AND polcmd='r')<>1
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_policy
                  WHERE polrelid=('saas_data.'||t)::regclass AND polcmd<>'r')
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class
         WHERE oid=('saas_data.'||t)::regclass AND relrowsecurity AND relforcerowsecurity) THEN
      RAISE EXCEPTION 'Backend13 tenant/project table lost SELECT-only FORCE RLS';
    END IF;
  END LOOP;
END
$contract$;
SELECT 'PASS Backend13: CAS tombstones, ACL fencing and operator-only audit catalog' AS result;
