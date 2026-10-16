\set ON_ERROR_STOP on
-- Backend14 contract, disposable GitHub PG16 ONLY, after 0006.
DO $verify$
DECLARE
  function_attr record;
  n integer;
  t text;
  role_name text;
  obj record;
BEGIN
  IF current_database() <> 'saas_staging_ci'
     OR session_user <> 'postgres'
     OR current_setting('server_version_num')::int NOT BETWEEN 160000 AND 169999 THEN
    RAISE EXCEPTION 'Backend14 PG16 schema acceptance refused non-CI database';
  END IF;
  SELECT count(*) INTO n FROM saas_bootstrap.schema_migrations;
  IF n <> 6 OR NOT EXISTS (
    SELECT 1 FROM saas_bootstrap.schema_migrations
    WHERE migration_id='0006_principal_session_fence'
      AND source_sha256 ~ '^[a-f0-9]{64}$'
      AND source_commit ~ '^[a-f0-9]{40}$'
      AND applied_by='saas_schema_migrator'
  ) THEN
    RAISE EXCEPTION 'Backend14 lacks sixth restricted-migrator receipt';
  END IF;
  SELECT count(*) INTO n FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace ns ON ns.oid=c.relnamespace
    WHERE ns.nspname='saas_identity' AND c.relname IN ('principal_sessions','session_events')
      AND pg_catalog.pg_get_userbyid(c.relowner)='saas_schema_migrator'
      AND c.relkind='r';
  IF n<>2 THEN RAISE EXCEPTION 'Backend14 private session tables missing'; END IF;
  IF (SELECT count(*) FROM saas_identity.principal_sessions) <> 0 OR
     (SELECT count(*) FROM saas_identity.session_events) <> 0 THEN
    RAISE EXCEPTION 'Backend14 migration must not create any real sessions';
  END IF;
  SELECT count(*) INTO n FROM pg_catalog.pg_index i
    JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
    WHERE c.relname='b14_single_unrevoked_login' AND i.indisunique
      AND i.indpred IS NOT NULL;
  IF n<>1 THEN RAISE EXCEPTION 'Backend14 one-unrevoked-session invariant missing'; END IF;
  SELECT count(*) INTO n FROM pg_catalog.pg_trigger
    WHERE tgrelid IN ('saas_identity.principal_sessions'::regclass,
                      'saas_identity.session_events'::regclass)
      AND NOT tgisinternal AND tgenabled = 'O';
  IF n<>5 THEN RAISE EXCEPTION 'Backend14 audit/immutability triggers missing'; END IF;
  FOR obj IN SELECT oid FROM (VALUES
    ('saas_identity.issue_principal_session(name,uuid,bigint,uuid,timestamptz,text)'::regprocedure),
    ('saas_identity.revoke_principal_session(uuid,bigint,text)'::regprocedure)
  ) f(oid) LOOP
    SELECT prosecdef,provolatile INTO function_attr
      FROM pg_catalog.pg_proc WHERE oid=obj.oid;
    IF NOT FOUND OR function_attr.prosecdef OR function_attr.provolatile <> 'v' THEN
      RAISE EXCEPTION 'Backend14 operator function must stay volatile invoker-only';
    END IF;
  END LOOP;
  SELECT prosecdef,provolatile,proconfig INTO function_attr
    FROM pg_catalog.pg_proc WHERE oid='saas_acl.can_read_tenant(uuid)'::regprocedure;
  IF NOT FOUND OR NOT function_attr.prosecdef OR function_attr.provolatile <> 'v'
     OR NOT function_attr.proconfig @> ARRAY['search_path=pg_catalog, pg_temp'] THEN
    RAISE EXCEPTION 'Backend14 tenant RLS function lost security isolation';
  END IF;
  FOR role_name IN SELECT unnest(ARRAY['saas_runtime_reader','saas_runtime_writer']) LOOP
    IF pg_catalog.has_schema_privilege(role_name,'saas_identity','USAGE')
       OR pg_catalog.has_table_privilege(role_name,'saas_identity.principal_sessions','SELECT')
       OR pg_catalog.has_table_privilege(role_name,'saas_identity.session_events','SELECT')
       OR pg_catalog.has_table_privilege(role_name,'saas_identity.principal_sessions','UPDATE')
       OR pg_catalog.has_function_privilege(role_name,
          'saas_identity.issue_principal_session(name,uuid,bigint,uuid,timestamptz,text)','EXECUTE')
       OR pg_catalog.has_function_privilege(role_name,
          'saas_identity.revoke_principal_session(uuid,bigint,text)','EXECUTE') THEN
      RAISE EXCEPTION 'Backend14 private sessions leaked to %', role_name;
    END IF;
  END LOOP;
  FOR t IN SELECT unnest(ARRAY['tenants','projects']) LOOP
    SELECT count(*) INTO n FROM pg_catalog.pg_policy
      WHERE polrelid=('saas_data.'||t)::regclass AND polcmd='r';
    IF n<>1 OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_policy
       WHERE polrelid=('saas_data.'||t)::regclass AND polcmd<>'r'
    ) OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_class
       WHERE oid=('saas_data.'||t)::regclass
         AND relrowsecurity AND relforcerowsecurity
    ) THEN
      RAISE EXCEPTION 'Backend14 changed FORCE RLS or added write policy for %', t;
    END IF;
  END LOOP;
END
$verify$;
SELECT 'PASS Backend14: one-session principal fence, private audit, no runtime grants, read-only FORCE RLS' AS result;
