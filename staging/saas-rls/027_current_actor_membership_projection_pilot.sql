-- Backend 05: current active actor memberships, strictly disposable PG16.
-- Adds read-only SECURITY DEFINER projection for SQL026's existing isolated
-- NOLOGIN identity resolver. No dynamic SQL, HTTP authority, secrets or
-- grants of raw memberships/revision/actor tables to the runtime login.
-- NEVER apply this CI pilot to Railway or production PostgreSQL.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test'
    OR current_user<>'postgres'
    OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
    OR current_setting('server_version_num')::integer < 160000
    OR current_setting('server_version_num')::integer >= 170000
    OR to_regclass('saas_rls.memberships') IS NULL
    OR to_regclass('saas_rls_private.tenant_authorization_revisions') IS NULL
    OR to_regclass('saas_rls_private.actor_session_state') IS NULL
    OR to_regprocedure('saas_m1_api.resolve_verified_subject_actor(text,text)') IS NULL
    OR NOT EXISTS(SELECT 1 FROM pg_roles
      WHERE rolname='saas_rls_owner'
        AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
    OR NOT EXISTS(SELECT 1 FROM pg_roles
      WHERE rolname='saas_m1_identity_resolver'
        AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
        AND NOT rolinherit)
 THEN RAISE EXCEPTION 'SQL027 requires disposable PG16 plus signed SQL026 identity';
 END IF;
END $guard$;

-- Grant CREATE to the non-login function owner only inside the migration
-- transaction, then revoke before COMMIT. Owner never has a login.
GRANT USAGE,CREATE ON SCHEMA saas_m1_api TO saas_rls_owner;
CREATE FUNCTION saas_m1_api.resolve_current_actor_memberships(
  expected_actor TEXT
) RETURNS TABLE(
  tenant_id TEXT, membership_role TEXT, membership_status TEXT
)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
 SELECT m.tenant_id, m.role, m.status
 FROM saas_rls.memberships m
 JOIN saas_rls_private.tenant_authorization_revisions revision
   ON revision.tenant_id=m.tenant_id
 JOIN saas_rls_private.actor_session_state actor
   ON actor.actor_id=m.actor_id
 WHERE expected_actor ~ '^[A-Za-z0-9_-]{1,128}$'
   AND m.actor_id=expected_actor
   AND m.status='active'
   AND m.role IN ('tenant-owner','tenant-admin',
                  'tenant-viewer','tenant-auditor')
   AND revision.tenant_active=TRUE
   AND actor.status='active'
 ORDER BY m.tenant_id
 LIMIT 33
$fn$;
ALTER FUNCTION saas_m1_api.resolve_current_actor_memberships(text)
 OWNER TO saas_rls_owner;
REVOKE CREATE ON SCHEMA saas_m1_api FROM saas_rls_owner;

REVOKE ALL ON FUNCTION saas_m1_api.resolve_current_actor_memberships(text)
 FROM PUBLIC,saas_ci_runner,saas_rls_reader,
      saas_m1_project_executor,saas_issuer_provisioner,
      saas_issuer_directory_admin;
GRANT EXECUTE ON FUNCTION
 saas_m1_api.resolve_current_actor_memberships(text)
 TO saas_m1_identity_resolver;

-- No raw tenant/member/epoch access from either the NOLOGIN runtime role
-- or the actual CI login that is allowed to SET (not inherit) that role.
DO $assert$
BEGIN
 IF has_schema_privilege('saas_rls_owner','saas_m1_api','CREATE')
    OR has_table_privilege('saas_m1_identity_resolver',
      'saas_rls.memberships','SELECT')
    OR has_table_privilege('saas_m1_identity_resolver',
      'saas_rls_private.tenant_authorization_revisions','SELECT')
    OR has_table_privilege('saas_m1_identity_resolver',
      'saas_rls_private.actor_session_state','SELECT')
    OR has_function_privilege('saas_ci_runner',
      'saas_m1_api.resolve_current_actor_memberships(text)','EXECUTE')
    OR has_function_privilege('saas_m1_project_executor',
      'saas_m1_api.resolve_current_actor_memberships(text)','EXECUTE')
    OR has_function_privilege('saas_issuer_provisioner',
      'saas_m1_api.resolve_current_actor_memberships(text)','EXECUTE')
    OR NOT has_function_privilege('saas_m1_identity_resolver',
      'saas_m1_api.resolve_current_actor_memberships(text)','EXECUTE')
    OR NOT EXISTS(
      SELECT 1 FROM pg_proc
      WHERE oid='saas_m1_api.resolve_current_actor_memberships(text)'::regprocedure
        AND proowner='saas_rls_owner'::regrole
        AND prosecdef
    )
 THEN RAISE EXCEPTION 'SQL027 membership projection privilege fence unsafe';
 END IF;
END $assert$;
COMMIT;
\echo 'PASS SQL027: isolated current active membership projection; 0 raw table reads and 0 grant widening'
