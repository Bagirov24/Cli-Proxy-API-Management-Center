\set ON_ERROR_STOP on
-- M1a: actual PostgreSQL16 disposable signed-scope project CRUD acceptance.
-- Must execute AFTER 001,002,003,004 on ephemeral saas_ephemeral_test.
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
    OR to_regprocedure('saas_rls.authorized_revision(text,text,text,text)') IS NULL
    OR to_regprocedure('saas_rls_test.issue_scope(text,text,integer)') IS NULL
 THEN RAISE EXCEPTION 'M1a test refused outside isolated PG16 acceptance';
 END IF;
END
$guard$;

SET saas.staging_only = 'true';
\ir ../../staging/saas-rls/020_m1_project_metadata_pilot.sql
\ir ../../staging/saas-rls/020_m1_project_metadata_pilot.sql

-- The only exposed capability is a constrained function call, never SQL
-- table DML, raw memberships, HMAC signer or physical delete.
SELECT saas_rls_test.assert_true(
  has_function_privilege('saas_m1_project_executor',
     'saas_m1_api.create_project(text,text,text)', 'EXECUTE')
  AND has_function_privilege('saas_m1_project_executor',
     'saas_m1_api.rename_project(text,text,text,bigint)', 'EXECUTE')
  AND has_function_privilege('saas_m1_project_executor',
     'saas_m1_api.disable_project(text,text,bigint)', 'EXECUTE')
  AND has_function_privilege('saas_m1_project_executor',
     'saas_m1_api.get_project(text,text)', 'EXECUTE')
  AND NOT has_function_privilege('saas_ci_runner',
     'saas_m1_api.create_project(text,text,text)', 'EXECUTE')
  AND NOT has_function_privilege('saas_rls_reader',
     'saas_m1_api.create_project(text,text,text)', 'EXECUTE')
  AND NOT has_schema_privilege('saas_m1_project_executor',
     'saas_m1_private', 'USAGE')
  AND NOT has_table_privilege('saas_m1_project_executor',
     'saas_m1_private.projects','DELETE')
  AND NOT has_table_privilege('saas_m1_project_executor',
     'saas_m1_private.projects','UPDATE')
  AND NOT has_function_privilege('saas_m1_project_executor',
     'saas_rls_test.issue_scope(text,text,integer)','EXECUTE'),
  'M1a least-privilege role separation must reject direct table, signer and reader escalation'
);

-- No transaction-bound MAC -> NOT even a valid executor may write/read.
BEGIN;
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-north','m1-unauth','No Session')::TEXT AS denied_no_mac \gset
SELECT count(*)::TEXT AS no_untrusted_read FROM
 saas_m1_api.get_project('demo-north','m1-north') \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'denied_no_mac'='false' AND :'no_untrusted_read'='0',
 'Unsigned request must never create/read a project');
ROLLBACK;

-- Signed tenant-admin may create, but exact duplicate must never overwrite.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-north','m1-north','First Project')::TEXT AS created \gset
SELECT saas_m1_api.create_project('demo-north','m1-north','Forged Overwrite')::TEXT AS duplicate \gset
SELECT project_id AS visible_id, name AS visible_name, version AS visible_version
  FROM saas_m1_api.get_project('demo-north','m1-north') \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'created'='true' AND :'duplicate'='false'
 AND :'visible_id'='m1-north'
 AND :'visible_name'='First Project'
 AND (:'visible_version')::BIGINT=1,
 'Signed admin create + duplicate DENY and sanitized read');
COMMIT;

-- Signed same-tenant authorization expires at transaction boundary.
BEGIN;
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.rename_project('demo-north','m1-north','No MAC',1)::TEXT AS denied_no_scope \gset
SELECT count(*)::TEXT AS invisible_without_mac
  FROM saas_m1_api.get_project('demo-north','m1-north') \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'denied_no_scope'='false' AND :'invisible_without_mac'='0',
 'Committed read/write must require fresh transaction-bound scope');
ROLLBACK;

-- Viewer cannot write, even for their own tenant. Auditor can read
-- ordinary metadata but cannot mutate it or create records.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-orbit','m1-orbit','Viewer Attempt')::TEXT AS viewer_write \gset
SELECT saas_m1_api.rename_project('demo-orbit','m1-orbit','Viewer Rename',1)::TEXT AS viewer_rename \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'viewer_write'='false' AND :'viewer_rename'='false',
 'Tenant-viewer cannot write');
ROLLBACK;

BEGIN;
SELECT saas_rls_test.issue_scope('actor-auditor','demo-north',120);
SET LOCAL ROLE saas_m1_project_executor;
SELECT count(*)::TEXT AS auditor_read
 FROM saas_m1_api.get_project('demo-north','m1-north') \gset
SELECT saas_m1_api.disable_project('demo-north','m1-north',1)::TEXT AS auditor_disable \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'auditor_read'='1' AND :'auditor_disable'='false',
 'Auditor can read assigned metadata but cannot change its state');
ROLLBACK;

-- Signed North admin may not change target tenant to Orbit, even though
-- the public function accepts target strings. Cross-tenant read is empty.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-orbit','m1-stolen','Stolen')::TEXT AS cross_create \gset
SELECT count(*)::TEXT AS cross_read FROM
 saas_m1_api.get_project('demo-orbit','m1-stolen') \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'cross_create'='false' AND :'cross_read'='0',
 'Signed scope may not cross the actual tenant');
ROLLBACK;

-- Forged GUC, empty/bad input and an expired signed scope all fail closed.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL saas.scope_tenant='demo-orbit';
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-orbit','m1-bad','Wrong MAC')::TEXT AS forged_mac \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'forged_mac'='false','Tampered signed tenant scope must deny');
ROLLBACK;

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',-10);
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-north','m1-expired','Expired')::TEXT AS expired_mac \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'expired_mac'='false','Expired transaction MAC must deny');
ROLLBACK;

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-north','m1-invalid','  ')::TEXT AS blank_name \gset
SELECT saas_m1_api.create_project('demo-north','m1-invalid',repeat('A',121))::TEXT AS long_name \gset
SELECT saas_m1_api.create_project('demo-north','m1-invalid',E'Bad\nName')::TEXT AS control_name \gset
SELECT saas_m1_api.create_project('demo-north','a/b','Invalid ID')::TEXT AS invalid_id \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'blank_name'='false' AND :'long_name'='false'
 AND :'control_name'='false' AND :'invalid_id'='false',
 'Input bounds and canonical ID/name enforced in DB');
ROLLBACK;

-- Optimistic concurrency + monotonic revision + soft disable. Repeated
-- or stale updates are denied; there is no re-enable or physical DELETE.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.rename_project('demo-north','m1-north','Stale',0)::TEXT AS invalid_revision \gset
SELECT saas_m1_api.rename_project('demo-north','m1-north','Fresh Name',1)::TEXT AS rename_ok \gset
SELECT saas_m1_api.rename_project('demo-north','m1-north','Concurrent Stale',1)::TEXT AS lost_update \gset
SELECT name AS changed_name, version AS changed_version FROM
 saas_m1_api.get_project('demo-north','m1-north') \gset
SELECT saas_m1_api.disable_project('demo-north','m1-north',1)::TEXT AS stale_disable \gset
SELECT saas_m1_api.disable_project('demo-north','m1-north',2)::TEXT AS disabled \gset
SELECT saas_m1_api.disable_project('demo-north','m1-north',3)::TEXT AS repeated_disable \gset
SELECT saas_m1_api.rename_project('demo-north','m1-north','Reactivation',3)::TEXT AS terminal_rename \gset
SELECT status AS terminal_status, version AS terminal_version FROM
 saas_m1_api.get_project('demo-north','m1-north') \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'invalid_revision'='false' AND :'rename_ok'='true'
 AND :'lost_update'='false' AND :'changed_name'='Fresh Name'
 AND (:'changed_version')::BIGINT=2 AND :'stale_disable'='false'
 AND :'disabled'='true' AND :'repeated_disable'='false'
 AND :'terminal_rename'='false' AND :'terminal_status'='disabled'
 AND (:'terminal_version')::BIGINT=3,
 'CAS version cannot roll back, disabled project is terminal');
COMMIT;

-- Revocation or suspension immediately denies new writes even though
-- the exact signed scope was generated before the change.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
UPDATE saas_rls.memberships SET status='revoked'
 WHERE tenant_id='demo-north' AND actor_id='actor-north';
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-north','m1-revoked','Revoked')::TEXT AS revoke_denied \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'revoke_denied'='false','Revoked DB membership denies despite earlier MAC');
ROLLBACK;

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
UPDATE saas_rls.tenants SET status='suspended' WHERE id='demo-north';
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-north','m1-suspended','Suspended')::TEXT AS suspend_denied \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'suspend_denied'='false','Suspended tenant denies a signed admin');
ROLLBACK;

-- Rollback after a successful-looking function result must not publish
-- the project. Uses a completely new test-only synthetic ID.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-north','m1-rollback','Roll Back')::TEXT AS staged_mutation \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(:'staged_mutation'='true',
 'Staging a provisional mutation must be possible');
ROLLBACK;
SELECT saas_rls_test.assert_true(
 NOT EXISTS (SELECT 1 FROM saas_m1_private.projects
             WHERE tenant_id='demo-north' AND project_id='m1-rollback')
 AND (SELECT count(*)=1 FROM saas_m1_private.projects
      WHERE tenant_id='demo-north' AND project_id='m1-north'
        AND name='Fresh Name' AND status='disabled' AND version=3),
 'Atomic rollback and successful terminal commit must persist distinctly');

-- A repeated migration must not truncate or resurrect disabled projects.
\ir ../../staging/saas-rls/020_m1_project_metadata_pilot.sql
SELECT saas_rls_test.assert_true(
 (SELECT count(*)=1 FROM saas_m1_private.projects
  WHERE tenant_id='demo-north' AND project_id='m1-north'
    AND status='disabled' AND version=3),
 'Migration replay must preserve signed revision and disabled row');

\echo 'PASS M1a: signed tenant project create/read/rename/soft-disable, replay/rollback/CAS, owner-admin only, viewer/auditor/cross-tenant/forged/expired/revoked/suspended DENY; NO production/issuer/GC'
