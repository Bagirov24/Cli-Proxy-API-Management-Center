\set ON_ERROR_STOP on
-- Backend16.8: independent SQL0008 state observation. NEVER an installer.
-- Run only against isolated PG16 saas_staging (or ephemeral CI saas_staging_ci).
-- REQUIRED: psql -v b16_expected_state=absent|installed
-- Do NOT replay SQL0008 after an unknown COMMIT, even if ABSENT is observed.
\if :{?b16_expected_state}
\else
  \echo BACKEND16_READONLY_RECONCILE_STOP_MISSING_EXPECTATION
  \quit 2
\endif
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL statement_timeout = '15000ms';
SET LOCAL lock_timeout = '3000ms';
-- Transaction-local request label only; never used as an authorization GUC.
SELECT pg_catalog.set_config('saas.b16.reconcile_expected', :'b16_expected_state', true);
DO $b16_readonly$
DECLARE
  wanted text := current_setting('saas.b16.reconcile_expected',true);
  staging boolean := (current_database()='saas_staging');
  n integer;
  c record;
  f record;
BEGIN
  IF wanted NOT IN ('absent','installed')
     OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR current_setting('transaction_read_only') <> 'on'
     OR session_user <> 'postgres' OR current_user <> 'postgres'
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                     WHERE rolname='postgres' AND rolsuper AND rolcanlogin)
     OR pg_catalog.pg_is_in_recovery()
  THEN RAISE EXCEPTION 'B16_READONLY_STOP_CONTEXT'; END IF;

  SELECT count(*)::int INTO n
    FROM pg_catalog.pg_stat_activity
   WHERE datname=current_database()
     AND pid<>pg_catalog.pg_backend_pid() AND backend_type='client backend';
  IF staging AND n<>0 THEN
    RAISE EXCEPTION 'B16_READONLY_STOP_CONCURRENT_STAGING_CLIENT';
  END IF;

  SELECT r.rolcanlogin AS login, a.rolpassword IS NULL AS no_password,
         r.rolsuper OR r.rolbypassrls OR r.rolcreaterole
          OR r.rolcreatedb OR r.rolreplication AS privileged
    INTO c
    FROM pg_catalog.pg_roles r
    JOIN pg_catalog.pg_authid a ON a.oid=r.oid
   WHERE r.rolname='saas_schema_migrator';
  IF NOT FOUND OR c.login IS DISTINCT FROM false
     OR c.no_password IS DISTINCT FROM true
     OR c.privileged IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'B16_READONLY_STOP_MIGRATOR_NOT_SEALED';
  END IF;

  SELECT count(*)::int INTO n
    FROM pg_catalog.pg_roles
   WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer')
     AND NOT rolcanlogin AND NOT rolinherit
     AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole
     AND NOT rolcreatedb AND NOT rolreplication;
  IF n<>2 THEN RAISE EXCEPTION 'B16_READONLY_STOP_TEMPLATE_ROLES'; END IF;

  IF (SELECT count(*)::int FROM saas_bootstrap.schema_migrations)
     <> CASE wanted WHEN 'absent' THEN 7 ELSE 8 END
  THEN RAISE EXCEPTION 'B16_READONLY_STOP_RECEIPT_COUNT'; END IF;

  WITH expected(id,sha,author) AS (
    VALUES
      ('0001_ledger_only','7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279','saas_schema_migrator'),
      ('0002_tenant_projects_baseline','80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f','saas_schema_migrator'),
      ('0003_operator_runtime_roles','8bd26bb1e798e1196f64546a0bfd554cfe46c6a5cd9d4414d369bc1cbf98124e','postgres'),
      ('0004_principal_bound_read_rls','4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980','saas_schema_migrator'),
      ('0005_principal_lifecycle_revocation_fence','b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556','saas_schema_migrator'),
      ('0006_principal_session_fence','b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505','saas_schema_migrator'),
      ('0007_operator_subject_binding_fence','1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0','saas_schema_migrator')
  )
  SELECT count(*)::int INTO n
    FROM expected e
    FULL JOIN saas_bootstrap.schema_migrations m ON m.migration_id=e.id
   WHERE (m.migration_id IS NULL OR e.id IS NULL)
     OR m.source_sha256 IS DISTINCT FROM e.sha
     OR m.applied_by IS DISTINCT FROM e.author;
  -- An INSTALLED state has one additional, independently validated SQL0008
  -- receipt, so the FULL JOIN mismatch count is exactly one in that state.
  IF n<>CASE wanted WHEN 'absent' THEN 0 ELSE 1 END THEN
    RAISE EXCEPTION 'B16_READONLY_STOP_PREVIOUS_RECEIPTS';
  END IF;

  IF NOT EXISTS (
      SELECT 1 FROM saas_bootstrap.schema_migrations
       WHERE migration_id='0007_operator_subject_binding_fence'
         AND source_sha256='1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0'
         AND (NOT staging OR source_commit='6cc4a76a0b3144380ccc95f0ca1c275ae312cae3')
         AND source_commit ~ '^[a-f0-9]{40}$'
  ) THEN RAISE EXCEPTION 'B16_READONLY_STOP_SQL0007_PROVENANCE'; END IF;

  IF wanted='installed' AND NOT EXISTS (
      SELECT 1 FROM saas_bootstrap.schema_migrations
       WHERE migration_id='0008_exact_subject_session_gate'
         AND source_sha256='ef4858975fea0842ae16d1b572457641c0359fa9630f02a1d52ea972007c632b'
         AND applied_by='saas_schema_migrator'
         AND (NOT staging OR source_commit='314f0962f2d955241fb5ee7a29175bddb648c130')
         AND source_commit ~ '^[a-f0-9]{40}$'
  ) THEN RAISE EXCEPTION 'B16_READONLY_STOP_SQL0008_PROVENANCE'; END IF;

  SELECT count(*)::int INTO n FROM pg_catalog.pg_class
   WHERE oid IN ('saas_data.tenants'::regclass,
                 'saas_data.projects'::regclass)
     AND relrowsecurity AND relforcerowsecurity;
  IF n<>2 OR
    (SELECT count(*)::int FROM pg_catalog.pg_policy
      WHERE polrelid IN ('saas_data.tenants'::regclass,
                         'saas_data.projects'::regclass))<>2 OR
    (SELECT count(*)::int FROM pg_catalog.pg_policy
      WHERE polrelid IN ('saas_data.tenants'::regclass,
                         'saas_data.projects'::regclass) AND polcmd='r')<>2
  THEN RAISE EXCEPTION 'B16_READONLY_STOP_FORCE_RLS'; END IF;

  SELECT count(*)::int INTO n
    FROM pg_catalog.pg_trigger
   WHERE tgrelid IN ('saas_identity.principal_sessions'::regclass,
                     'saas_identity.session_events'::regclass)
     AND NOT tgisinternal AND tgenabled='O';
  IF n<>5 THEN RAISE EXCEPTION 'B16_READONLY_STOP_B14_TRIGGERS'; END IF;
  SELECT count(*)::int INTO n
    FROM pg_catalog.pg_trigger
   WHERE tgrelid IN ('saas_identity.subject_bindings'::regclass,
                     'saas_identity.subject_binding_events'::regclass)
     AND NOT tgisinternal AND tgenabled='O';
  IF n<>5 THEN RAISE EXCEPTION 'B16_READONLY_STOP_B15_TRIGGERS'; END IF;

  IF (SELECT count(*)::int FROM pg_catalog.pg_index
       WHERE indrelid='saas_identity.subject_bindings'::regclass
         AND indisunique)<>3
     OR (SELECT count(*)::int FROM pg_catalog.pg_constraint
       WHERE conrelid='saas_identity.subject_bindings'::regclass
         AND conname='b15_revoke_marker')<>1
  THEN RAISE EXCEPTION 'B16_READONLY_STOP_BINDING_CATALOG'; END IF;

  IF EXISTS (
     SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer')
        AND pg_catalog.has_schema_privilege(rolname,'saas_identity','USAGE')
  ) OR EXISTS (
     SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer')
        AND (pg_catalog.has_table_privilege(
                rolname,'saas_identity.principal_sessions','SELECT')
          OR pg_catalog.has_table_privilege(
                rolname,'saas_identity.subject_bindings','SELECT')
          OR pg_catalog.has_table_privilege(
                rolname,'saas_identity.subject_binding_events','SELECT')
          OR pg_catalog.has_table_privilege(
                rolname,'saas_data.tenants','INSERT, UPDATE, DELETE, TRUNCATE')
          OR pg_catalog.has_table_privilege(
                rolname,'saas_data.projects','INSERT, UPDATE, DELETE, TRUNCATE'))
  ) THEN RAISE EXCEPTION 'B16_READONLY_STOP_RUNTIME_PRIVILEGES'; END IF;

  SELECT count(*)::int INTO n
    FROM pg_catalog.pg_class c
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) acl
   WHERE c.oid IN (
     'saas_data.tenants'::regclass,'saas_data.projects'::regclass,
     'saas_acl.principal_tenants'::regclass,
     'saas_acl.principal_access_audit'::regclass,
     'saas_identity.principal_sessions'::regclass,
     'saas_identity.session_events'::regclass,
     'saas_identity.subject_bindings'::regclass,
     'saas_identity.subject_binding_events'::regclass)
     AND acl.grantee NOT IN (
       SELECT oid FROM pg_catalog.pg_roles WHERE rolname IN
        ('saas_schema_migrator','saas_runtime_reader','saas_runtime_writer'));
  IF n<>0 THEN RAISE EXCEPTION 'B16_READONLY_STOP_UNEXPECTED_TABLE_GRANTS'; END IF;

  IF staging THEN
    IF EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles WHERE left(rolname,5)='saas_'
        AND rolname NOT IN ('saas_schema_migrator',
                            'saas_runtime_reader','saas_runtime_writer')
    ) OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_auth_members
       WHERE roleid IN (SELECT oid FROM pg_catalog.pg_roles
                         WHERE left(rolname,5)='saas_')
          OR member IN (SELECT oid FROM pg_catalog.pg_roles
                         WHERE left(rolname,5)='saas_')
    ) OR
       (SELECT count(*) FROM saas_data.tenants)<>0 OR
       (SELECT count(*) FROM saas_data.projects)<>0 OR
       (SELECT count(*) FROM saas_acl.principal_tenants)<>0 OR
       (SELECT count(*) FROM saas_acl.principal_access_audit)<>0 OR
       (SELECT count(*) FROM saas_identity.principal_sessions)<>0 OR
       (SELECT count(*) FROM saas_identity.session_events)<>0 OR
       (SELECT count(*) FROM saas_identity.subject_bindings)<>0 OR
       (SELECT count(*) FROM saas_identity.subject_binding_events)<>0
    THEN RAISE EXCEPTION 'B16_READONLY_STOP_NONEMPTY_OR_ROLE_DRIFT'; END IF;
  END IF;

  IF wanted='absent' THEN
    IF to_regprocedure(
      'saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)')
      IS NOT NULL THEN
      RAISE EXCEPTION 'B16_READONLY_STOP_PARTIAL_SQL0008';
    END IF;
  ELSE
    SELECT p.prosecdef,p.provolatile,p.prorettype,
           pg_catalog.pg_get_userbyid(p.proowner) AS owner_name,
           p.proconfig,
           pg_catalog.has_function_privilege(
             'saas_runtime_reader',p.oid,'EXECUTE') AS reader_execute,
           pg_catalog.has_function_privilege(
             'saas_runtime_writer',p.oid,'EXECUTE') AS writer_execute,
           (SELECT count(*)::int FROM pg_catalog.aclexplode(
               coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
             WHERE a.grantee NOT IN (
               SELECT oid FROM pg_catalog.pg_roles WHERE rolname IN (
                 'saas_schema_migrator','saas_runtime_reader',
                 'saas_runtime_writer'))) AS foreign_grants,
           pg_catalog.pg_get_functiondef(p.oid) AS definition
      INTO f
      FROM pg_catalog.pg_proc p
     WHERE p.oid=to_regprocedure(
       'saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)');
    IF NOT FOUND OR f.prosecdef IS DISTINCT FROM true
       OR f.provolatile IS DISTINCT FROM 'v'
       OR f.prorettype IS DISTINCT FROM 'boolean'::regtype
       OR f.owner_name IS DISTINCT FROM 'saas_schema_migrator'
       OR f.proconfig IS NULL
       OR NOT (f.proconfig @> ARRAY['search_path=pg_catalog, pg_temp'])
       OR f.reader_execute IS DISTINCT FROM true
       OR f.writer_execute IS DISTINCT FROM true
       OR f.foreign_grants<>0
       OR f.definition NOT LIKE '%s.session_id=p_session%'
       OR f.definition NOT LIKE '%s.identity_binding_id=p_binding%'
       OR f.definition NOT LIKE '%b.subject_fingerprint=p_subject_sha256%'
       OR f.definition NOT LIKE '%FOR SHARE%'
    THEN RAISE EXCEPTION 'B16_READONLY_STOP_SQL0008_FUNCTION_DRIFT'; END IF;
  END IF;
END
$b16_readonly$;
COMMIT;
-- Marker is only reached after a complete, strict, read-only snapshot.
SELECT CASE :'b16_expected_state'
  WHEN 'absent' THEN 'PASS_BACKEND16_SQL0008_READONLY_ABSENT_SEALED_NEVER_AUTO_INSTALL'
  WHEN 'installed' THEN 'PASS_BACKEND16_SQL0008_READONLY_INSTALLED_SEALED'
  ELSE 'BACKEND16_SQL0008_READONLY_STOP'
END AS verified_state;
