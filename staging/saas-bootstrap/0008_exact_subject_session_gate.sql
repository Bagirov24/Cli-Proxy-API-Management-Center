-- Backend16.4 / SQL0008: exact token-verified subject/session/binding PG gate.
-- ISOLATED staging PG16 and disposable GitHub PG16 ONLY.
-- NO OIDC verifier, HTTP listener, token fingerprint storage, new identity,
-- tenant data, project data, role bootstrap, RLS bypass or production action.
-- Input subject digest MUST come from previously signature-verified issuer/sub;
-- this SQL function itself cannot authenticate OIDC or raw bearer tokens.
-- Reviewed ONE-SHOT migrator transaction after immutable SQL0007. UNKNOWN COMMIT
-- => read-only reconciliation, NEVER rerun this file speculatively.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL statement_timeout = '20s';
SET LOCAL lock_timeout = '3s';
-- psql variable expansion happens before DO (never interpolate inside $$).
SELECT pg_catalog.set_config('saas.b16.expected_0007', :'expected_0007_sha256', true);
SELECT pg_catalog.set_config('saas.b16.source_sha', :'migration_sha256', true);
SELECT pg_catalog.set_config('saas.b16.source_commit', :'source_commit', true);

DO $guard$
DECLARE
  migrator record;
  old_gate record;
BEGIN
  IF current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR current_setting('transaction_read_only') <> 'off'
     OR pg_catalog.pg_is_in_recovery()
     OR session_user <> 'saas_schema_migrator'
     OR current_user <> 'saas_schema_migrator' THEN
    RAISE EXCEPTION 'Backend16 SQL0008 refused untrusted PG16 migrator context';
  END IF;
  SELECT rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication
    INTO migrator FROM pg_catalog.pg_roles WHERE rolname=session_user;
  IF NOT FOUND OR migrator.rolsuper OR migrator.rolbypassrls
     OR migrator.rolcreaterole OR migrator.rolcreatedb
     OR migrator.rolreplication THEN
    RAISE EXCEPTION 'Backend16 SQL0008 refused privileged migrator';
  END IF;
  IF to_regclass('saas_bootstrap.schema_migrations') IS NULL
     OR to_regclass('saas_acl.principal_tenants') IS NULL
     OR to_regclass('saas_identity.principal_sessions') IS NULL
     OR to_regclass('saas_identity.subject_bindings') IS NULL
     OR to_regclass('saas_identity.subject_binding_events') IS NULL
     OR to_regprocedure('saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)')
        IS NOT NULL
     OR to_regnamespace('saas_rls') IS NOT NULL
     OR to_regnamespace('saas_rls_private') IS NOT NULL
     OR to_regnamespace('saas_m1_private') IS NOT NULL
     OR to_regnamespace('saas_m1_api') IS NOT NULL THEN
    RAISE EXCEPTION 'Backend16 SQL0008 catalog mismatch or attempted replay';
  END IF;
  IF (SELECT count(*) FROM saas_bootstrap.schema_migrations) <> 7
     OR (SELECT count(*) FROM saas_bootstrap.schema_migrations
         WHERE migration_id IN (
           '0001_ledger_only','0002_tenant_projects_baseline',
           '0003_operator_runtime_roles','0004_principal_bound_read_rls',
           '0005_principal_lifecycle_revocation_fence',
           '0006_principal_session_fence',
           '0007_operator_subject_binding_fence')) <> 7
     OR NOT EXISTS (
       SELECT 1 FROM saas_bootstrap.schema_migrations
        WHERE migration_id='0007_operator_subject_binding_fence'
          AND source_sha256=current_setting('saas.b16.expected_0007',true)
          AND applied_by='saas_schema_migrator')
     OR current_setting('saas.b16.expected_0007',true) IS DISTINCT FROM
       '1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0'
     OR current_setting('saas.b16.source_sha',true) !~ '^[a-f0-9]{64}$'
     OR current_setting('saas.b16.source_commit',true) !~ '^[a-f0-9]{40}$' THEN
    RAISE EXCEPTION 'Backend16 SQL0008 refused unverified seven-receipt chain';
  END IF;
  SELECT prosecdef,provolatile,proowner::regrole::text AS owner_name
    INTO old_gate FROM pg_catalog.pg_proc
    WHERE oid='saas_acl.can_read_tenant(uuid)'::regprocedure;
  IF NOT FOUND OR old_gate.prosecdef IS DISTINCT FROM true
     OR old_gate.provolatile <> 'v'
     OR old_gate.owner_name <> 'saas_schema_migrator'
     OR (SELECT count(*) FROM pg_catalog.pg_policy
          WHERE polrelid IN ('saas_data.tenants'::regclass,
                             'saas_data.projects'::regclass)
            AND polcmd='r') <> 2
     OR (SELECT count(*) FROM pg_catalog.pg_class
          WHERE oid IN ('saas_data.tenants'::regclass,
                        'saas_data.projects'::regclass)
            AND relrowsecurity AND relforcerowsecurity) <> 2
     OR pg_catalog.has_schema_privilege('saas_runtime_reader',
           'saas_identity','USAGE')
     OR pg_catalog.has_table_privilege('saas_runtime_reader',
           'saas_identity.principal_sessions','SELECT')
     OR pg_catalog.has_table_privilege('saas_runtime_reader',
           'saas_identity.subject_bindings','SELECT')
     OR pg_catalog.has_table_privilege('saas_runtime_writer',
           'saas_identity.subject_bindings','SELECT') THEN
    RAISE EXCEPTION 'Backend16 SQL0008 original RLS/ACL/privacy invariant drift';
  END IF;
END
$guard$;

-- SECURITY DEFINER reads the three PRIVATE tables; runtime principal does
-- NOT receive schema USAGE or table SELECT on saas_identity / saas_acl.
-- All references fully qualified; no dynamic SQL, no writable GUC, no tokens.
-- Caller must use its authenticated per-principal physical PostgreSQL LOGIN.
-- Like SQL0007, locks protect the grant/session/binding until caller COMMIT.
-- READ COMMITTED (NOT READ ONLY): PostgreSQL forbids FOR SHARE in READ ONLY.
CREATE FUNCTION saas_acl.exact_subject_session_authorized(
  p_tenant uuid, p_session uuid, p_binding uuid, p_subject_sha256 text
) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $exact$
DECLARE
  grant_record record;
  session_expiry timestamptz;
  expected_runtime_role text;
BEGIN
  IF p_tenant IS NULL OR p_session IS NULL OR p_binding IS NULL
     OR p_subject_sha256 IS NULL
     OR p_subject_sha256 !~ '^[a-f0-9]{64}$'
     OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR session_user IN ('postgres','saas_schema_migrator',
                         'saas_runtime_reader','saas_runtime_writer')
     OR session_user LIKE 'pg_%'
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_roles r
       WHERE r.rolname=session_user AND r.rolcanlogin
         AND NOT r.rolsuper AND NOT r.rolbypassrls
         AND NOT r.rolcreaterole AND NOT r.rolcreatedb
         AND NOT r.rolreplication) THEN
    RETURN false;
  END IF;

  -- Stable lock order: grant -> exact session -> exact subject binding.
  SELECT a.access_revision,a.access_level INTO grant_record
    FROM saas_acl.principal_tenants a
    WHERE a.principal_name=session_user::name
      AND a.tenant_id=p_tenant
      AND a.access_level IN ('reader','writer')
    FOR SHARE;
  IF NOT FOUND THEN RETURN false; END IF;

  expected_runtime_role :=
    CASE grant_record.access_level WHEN 'reader' THEN 'saas_runtime_reader'
                                   WHEN 'writer' THEN 'saas_runtime_writer'
                                   ELSE NULL END;
  IF expected_runtime_role IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_auth_members m
       JOIN pg_catalog.pg_roles granted ON granted.oid=m.roleid
       JOIN pg_catalog.pg_roles principal ON principal.oid=m.member
       WHERE principal.rolname=session_user
         AND granted.rolname=expected_runtime_role)
     OR EXISTS (
       SELECT 1 FROM pg_catalog.pg_auth_members m
       JOIN pg_catalog.pg_roles granted ON granted.oid=m.roleid
       JOIN pg_catalog.pg_roles principal ON principal.oid=m.member
       WHERE principal.rolname=session_user
         AND granted.rolname NOT IN ('saas_runtime_reader','saas_runtime_writer')
     ) THEN RETURN false; END IF;

  SELECT s.expires_at INTO session_expiry
    FROM saas_identity.principal_sessions s
    WHERE s.session_id=p_session
      AND s.principal_name=session_user::name
      AND s.tenant_id=p_tenant
      AND s.grant_revision=grant_record.access_revision
      AND s.identity_binding_id=p_binding
      AND s.revoked_at IS NULL
      AND s.expires_at>pg_catalog.clock_timestamp()
    FOR SHARE;
  IF NOT FOUND THEN RETURN false; END IF;

  PERFORM 1 FROM saas_identity.subject_bindings b
    WHERE b.binding_id=p_binding
      AND b.principal_name=session_user::name
      AND b.tenant_id=p_tenant
      AND b.grant_revision=grant_record.access_revision
      AND b.subject_fingerprint=p_subject_sha256
      AND b.status='active'
      AND b.revoked_at IS NULL
    FOR SHARE;
  IF NOT FOUND THEN RETURN false; END IF;

  -- An expired session must not become newly authorized while waiting.
  RETURN session_expiry>pg_catalog.clock_timestamp();
END
$exact$;

-- Never leave CREATE FUNCTION's implicit PUBLIC EXECUTE in the final COMMIT.
REVOKE ALL ON FUNCTION
  saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)
  TO saas_runtime_reader,saas_runtime_writer;
COMMENT ON FUNCTION
  saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text) IS
  'Staging PG16 only: exact authenticated LOGIN/grant/session/subject digest FOR SHARE boolean; signature and HTTP token verify externally';

-- The only persistent row change is a single immutable migration receipt.
INSERT INTO saas_bootstrap.schema_migrations
  (migration_id,source_sha256,source_commit)
VALUES ('0008_exact_subject_session_gate', :'migration_sha256', :'source_commit');
COMMIT;
