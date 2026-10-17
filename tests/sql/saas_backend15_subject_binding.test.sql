\set ON_ERROR_STOP on
-- Backend15 contract: only isolated disposable PostgreSQL16 after 0007.
DO $verify$
DECLARE
  n integer;
  func record;
  role_name text;
BEGIN
  IF current_database()<>'saas_staging_ci' OR session_user<>'postgres'
     OR current_setting('server_version_num')::int NOT BETWEEN 160000 AND 169999 THEN
    RAISE EXCEPTION 'Backend15 contract refused non-disposable database';
  END IF;
  SELECT count(*) INTO n FROM saas_bootstrap.schema_migrations;
  IF n<>7 OR NOT EXISTS(
       SELECT 1 FROM saas_bootstrap.schema_migrations
       WHERE migration_id='0007_operator_subject_binding_fence'
         AND source_sha256 ~ '^[a-f0-9]{64}$'
         AND source_commit ~ '^[a-f0-9]{40}$'
         AND applied_by='saas_schema_migrator'
     ) OR NOT EXISTS(
       SELECT 1 FROM saas_bootstrap.schema_migrations
       WHERE migration_id='0006_principal_session_fence'
         AND source_sha256='b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505'
     ) THEN
    RAISE EXCEPTION 'Backend15 migration chain/attestation incorrect';
  END IF;
  IF to_regclass('saas_identity.subject_bindings') IS NULL OR
     to_regclass('saas_identity.subject_binding_events') IS NULL OR
     (SELECT count(*) FROM saas_identity.subject_bindings)<>0 OR
     (SELECT count(*) FROM saas_identity.subject_binding_events)<>0 OR
     (SELECT count(*) FROM pg_catalog.pg_policy
       WHERE polrelid IN ('saas_data.tenants'::regclass,
                          'saas_data.projects'::regclass))<>2 OR
     (SELECT count(*) FROM pg_catalog.pg_class
       WHERE oid IN ('saas_data.tenants'::regclass,
                     'saas_data.projects'::regclass)
         AND relrowsecurity AND relforcerowsecurity)<>2 THEN
    RAISE EXCEPTION 'Backend15 default deny/forced RLS not intact';
  END IF;
  SELECT prosecdef,provolatile,proconfig INTO func
    FROM pg_catalog.pg_proc
    WHERE oid='saas_acl.can_read_tenant(uuid)'::regprocedure;
  IF NOT FOUND OR func.prosecdef IS DISTINCT FROM true OR func.provolatile<>'v'
     OR NOT (func.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']) THEN
    RAISE EXCEPTION 'Backend15 scoped RLS definer lost hardening';
  END IF;
  FOR role_name IN
    SELECT unnest(ARRAY['saas_runtime_reader','saas_runtime_writer'])
  LOOP
    IF pg_catalog.has_schema_privilege(role_name,'saas_identity','USAGE')
       OR pg_catalog.has_table_privilege(role_name,
                 'saas_identity.subject_bindings','SELECT')
       OR pg_catalog.has_table_privilege(role_name,
                 'saas_identity.subject_binding_events','SELECT')
       OR pg_catalog.has_table_privilege(role_name,'saas_data.tenants','INSERT')
       OR pg_catalog.has_table_privilege(role_name,'saas_data.projects','UPDATE')
       OR pg_catalog.has_table_privilege(role_name,'saas_data.projects','DELETE') THEN
      RAISE EXCEPTION 'Backend15 runtime role privilege leak: %', role_name;
    END IF;
  END LOOP;
  IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid=
       'saas_identity.subject_bindings'::regclass
       AND NOT tgisinternal AND tgenabled='O')<>3 OR
     (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid=
       'saas_identity.subject_binding_events'::regclass
       AND NOT tgisinternal AND tgenabled='O')<>2 OR
     NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_trigger
       WHERE tgrelid='saas_identity.subject_bindings'::regclass
         AND tgname='b15_binding_audit'
         AND (tgtype & 2)=0
     ) THEN
    RAISE EXCEPTION 'Backend15 missing operator audit/tombstone triggers';
  END IF;
  FOR role_name IN
    SELECT unnest(ARRAY[
       'saas_identity.register_subject_binding(name,uuid,bigint,text,text)',
       'saas_identity.revoke_subject_binding(uuid,bigint,text)',
       'saas_identity.issue_principal_session(name,uuid,bigint,uuid,timestamptz,text)'
    ])
  LOOP
    SELECT prosecdef,proconfig INTO func
      FROM pg_catalog.pg_proc WHERE oid=role_name::regprocedure;
    IF NOT FOUND OR func.prosecdef IS DISTINCT FROM false OR
       NOT (func.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']) OR
       EXISTS(
         SELECT 1 FROM pg_catalog.pg_proc p,
           LATERAL pg_catalog.aclexplode(p.proacl) a
         WHERE p.oid=role_name::regprocedure AND a.grantee=0
           AND a.privilege_type='EXECUTE'
       ) THEN
      RAISE EXCEPTION 'Backend15 operator method not invoker-only: %',role_name;
    END IF;
  END LOOP;
END
$verify$;
SELECT 'PASS Backend15: private subject binding, operator CAS, no runtime grant, 7 receipts' AS result;
