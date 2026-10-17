\set ON_ERROR_STOP on
-- Backend16.4 structural contract, disposable GitHub PG16 AFTER exact SQL0008.
DO $verify$
DECLARE
  f record;
  r text;
  n integer;
BEGIN
  IF current_database() <> 'saas_staging_ci'
     OR session_user <> 'postgres'
     OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
     OR pg_catalog.pg_is_in_recovery() THEN
    RAISE EXCEPTION 'Backend16.4 contract refused non-disposable PG16';
  END IF;
  SELECT count(*) INTO n FROM saas_bootstrap.schema_migrations;
  IF n<>8 OR NOT EXISTS(
      SELECT 1 FROM saas_bootstrap.schema_migrations
      WHERE migration_id='0008_exact_subject_session_gate'
        AND source_sha256 ~ '^[a-f0-9]{64}$'
        AND source_commit ~ '^[a-f0-9]{40}$'
        AND applied_by='saas_schema_migrator'
    ) OR NOT EXISTS(
      SELECT 1 FROM saas_bootstrap.schema_migrations
      WHERE migration_id='0007_operator_subject_binding_fence'
        AND source_sha256=
          '1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0'
    ) THEN
    RAISE EXCEPTION 'Backend16.4 eight receipts or pinned SQL0007 chain missing';
  END IF;
  SELECT prosecdef,provolatile,proconfig,
         proowner::regrole::text AS owner_name
    INTO f FROM pg_catalog.pg_proc
    WHERE oid='saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)'::regprocedure;
  IF NOT FOUND OR f.prosecdef IS DISTINCT FROM true
     OR f.provolatile <> 'v'
     OR f.owner_name <> 'saas_schema_migrator'
     OR NOT (f.proconfig @> ARRAY['search_path=pg_catalog, pg_temp'])
     OR EXISTS(
       SELECT 1 FROM pg_catalog.pg_proc p
       CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a
       WHERE p.oid='saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)'::regprocedure
         AND a.grantee=0 AND a.privilege_type='EXECUTE')
     OR (SELECT count(*) FROM pg_catalog.pg_policy
         WHERE polrelid IN ('saas_data.tenants'::regclass,
                            'saas_data.projects'::regclass)
           AND polcmd='r') <> 2
     OR (SELECT count(*) FROM pg_catalog.pg_class
         WHERE oid IN ('saas_data.tenants'::regclass,
                       'saas_data.projects'::regclass)
           AND relrowsecurity AND relforcerowsecurity) <> 2 THEN
    RAISE EXCEPTION 'Backend16.4 exact definer or FORCE RLS catalog drift';
  END IF;
  FOR r IN SELECT unnest(ARRAY['saas_runtime_reader','saas_runtime_writer'])
  LOOP
    IF NOT pg_catalog.has_function_privilege(
         r,'saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)','EXECUTE')
       OR pg_catalog.has_schema_privilege(r,'saas_identity','USAGE')
       OR pg_catalog.has_table_privilege(
         r,'saas_identity.principal_sessions','SELECT')
       OR pg_catalog.has_table_privilege(
         r,'saas_identity.subject_bindings','SELECT')
       OR pg_catalog.has_table_privilege(
         r,'saas_identity.subject_binding_events','SELECT')
       OR pg_catalog.has_table_privilege(
         r,'saas_data.tenants','UPDATE')
       OR pg_catalog.has_table_privilege(
         r,'saas_data.projects','DELETE') THEN
      RAISE EXCEPTION 'Backend16.4 runtime template exceeded narrow EXECUTE: %',r;
    END IF;
  END LOOP;
  IF pg_catalog.has_function_privilege(
       'saas_schema_migrator',
       'saas_acl.can_read_tenant(uuid)','EXECUTE') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Backend16.4 original RLS function privilege changed';
  END IF;
END
$verify$;
SELECT 'PASS Backend16.4: exact session+binding digest, private tables, 8 receipts and FORCE RLS' AS result;
