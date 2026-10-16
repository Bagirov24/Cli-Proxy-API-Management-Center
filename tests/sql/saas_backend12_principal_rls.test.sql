\set ON_ERROR_STOP on
-- Backend12 on disposable PG16 only, after migrations 0003 and 0004.
DO $verify$
DECLARE
  login_attrs record;
  n int;
  tbl text;
  role_name text;
  owner_name name;
  f record;
BEGIN
  IF current_database() <> 'saas_staging_ci' OR session_user <> 'postgres' OR
     current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999 THEN
    RAISE EXCEPTION 'Backend12 CI role/RLS contract cannot run outside disposable PG16';
  END IF;
  SELECT count(*) INTO n FROM saas_bootstrap.schema_migrations;
  IF n <> 4 OR NOT EXISTS (
    SELECT 1 FROM saas_bootstrap.schema_migrations
    WHERE migration_id='0003_operator_runtime_roles'
      AND source_sha256 ~ '^[a-f0-9]{64}$'
      AND applied_by='postgres'
  ) OR NOT EXISTS (
    SELECT 1 FROM saas_bootstrap.schema_migrations
    WHERE migration_id='0004_principal_bound_read_rls'
      AND source_sha256 ~ '^[a-f0-9]{64}$'
      AND applied_by='saas_schema_migrator'
  ) THEN
    RAISE EXCEPTION 'Backend12 migration receipts missing or untrusted';
  END IF;
  SELECT pg_catalog.pg_get_userbyid(nspowner) INTO owner_name
    FROM pg_catalog.pg_namespace WHERE nspname='saas_acl';
  IF owner_name <> 'saas_schema_migrator' THEN
    RAISE EXCEPTION 'Backend12 ACL schema owned by wrong principal';
  END IF;
  SELECT p.prosecdef, p.provolatile,
         p.proconfig INTO f
    FROM pg_catalog.pg_proc p
    WHERE p.oid='saas_acl.can_read_tenant(uuid)'::regprocedure;
  IF NOT FOUND OR NOT f.prosecdef OR f.provolatile <> 's' OR
     NOT (f.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']) THEN
    RAISE EXCEPTION 'Backend12 function unsafe ownership/execution/search_path';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc p,
      LATERAL pg_catalog.aclexplode(p.proacl) a
    WHERE p.oid='saas_acl.can_read_tenant(uuid)'::regprocedure
      AND a.grantee=0 AND a.privilege_type='EXECUTE'
  ) THEN
    RAISE EXCEPTION 'Backend12 SECURITY DEFINER function leaked PUBLIC EXECUTE';
  END IF;
  IF (SELECT count(*) FROM saas_acl.principal_tenants) <> 0 OR
     (SELECT count(*) FROM saas_data.tenants) <> 0 OR
     (SELECT count(*) FROM saas_data.projects) <> 0 THEN
    RAISE EXCEPTION 'Backend12 baseline unexpectedly provisioned identities/data';
  END IF;
  FOR role_name IN SELECT unnest(ARRAY['saas_runtime_reader','saas_runtime_writer']) LOOP
    SELECT rolcanlogin, rolsuper, rolinherit, rolbypassrls, rolcreaterole,
           rolcreatedb, rolreplication
      INTO login_attrs FROM pg_catalog.pg_roles WHERE rolname=role_name;
    IF NOT FOUND OR login_attrs.rolcanlogin OR login_attrs.rolsuper OR
       login_attrs.rolinherit OR login_attrs.rolbypassrls OR
       login_attrs.rolcreaterole OR login_attrs.rolcreatedb OR
       login_attrs.rolreplication THEN
      RAISE EXCEPTION 'Backend12 runtime role escalation: %',role_name;
    END IF;
    IF NOT pg_catalog.has_schema_privilege(role_name,'saas_data','USAGE') OR
       NOT pg_catalog.has_schema_privilege(role_name,'saas_acl','USAGE') OR
       pg_catalog.has_schema_privilege(role_name,'saas_data','CREATE') OR
       pg_catalog.has_table_privilege(role_name,'saas_acl.principal_tenants','SELECT') OR
       pg_catalog.has_table_privilege(role_name,'saas_acl.principal_tenants','INSERT') OR
       pg_catalog.has_table_privilege(role_name,
                                     'saas_bootstrap.schema_migrations','SELECT') THEN
      RAISE EXCEPTION 'Backend12 runtime role leaked private data: %',role_name;
    END IF;
    FOREACH tbl IN ARRAY ARRAY['tenants','projects'] LOOP
      IF NOT pg_catalog.has_table_privilege(role_name,'saas_data.'||tbl,'SELECT') OR
         pg_catalog.has_table_privilege(role_name,'saas_data.'||tbl,'INSERT') OR
         pg_catalog.has_table_privilege(role_name,'saas_data.'||tbl,'UPDATE') OR
         pg_catalog.has_table_privilege(role_name,'saas_data.'||tbl,'DELETE') OR
         pg_catalog.has_table_privilege(role_name,'saas_data.'||tbl,'TRUNCATE') THEN
        RAISE EXCEPTION 'Backend12 runtime role has inappropriate DML: % %',
          role_name,tbl;
      END IF;
    END LOOP;
  END LOOP;
  FOR tbl IN SELECT unnest(ARRAY['tenants','projects']) LOOP
    SELECT count(*) INTO n FROM pg_catalog.pg_policy
      WHERE polrelid=('saas_data.'||tbl)::regclass AND polcmd='r';
    IF n <> 1 OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_policy
      WHERE polrelid=('saas_data.'||tbl)::regclass AND polcmd <> 'r'
    ) OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_class
      WHERE oid=('saas_data.'||tbl)::regclass
        AND relrowsecurity AND relforcerowsecurity
    ) THEN
      RAISE EXCEPTION 'Backend12 READ-ONLY policy or FORCE RLS incorrect: %', tbl;
    END IF;
  END LOOP;
END $verify$;
SELECT 'PASS Backend12: private ACL, NOLOGIN roles, read-only FORCE RLS, no runtime credentials' AS result;
