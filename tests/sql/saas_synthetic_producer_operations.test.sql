\set ON_ERROR_STOP on
-- 2G.4d.7f: audited producer operation, one event on replay, no payload.
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
 OR to_regclass('saas_rls_private.synthetic_producer_operations') IS NULL
 THEN RAISE EXCEPTION 'Refusing operation tests outside disposable PG16'; END IF;
END
$guard$;

\set op_a 11111111-1111-4111-8111-111111111111
\set op_b 22222222-2222-4222-8222-222222222222

SELECT saas_rls_test.assert_true(
 NOT has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
 AND NOT has_table_privilege('saas_rls_reader',
  'saas_rls_private.synthetic_producer_operations','SELECT')
 AND NOT has_table_privilege('saas_ci_runner',
  'saas_rls_private.synthetic_producer_operations','INSERT')
 AND NOT has_table_privilege('saas_mock_receiver',
  'saas_rls_private.synthetic_producer_operations','SELECT')
 AND NOT has_function_privilege('saas_ci_runner',
  'saas_rls.record_signed_synthetic_operation(text,text,text,text,text,uuid,integer)','EXECUTE')
 AND has_function_privilege('saas_rls_reader',
  'saas_rls.record_signed_synthetic_operation(text,text,text,text,text,uuid,integer)','EXECUTE'),
 'Only signed reader may execute narrowly scoped private operation function');

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.record_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects','ci-op-first',
 (:'op_a')::UUID,1)::TEXT AS op_first \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(:'op_first'='true'
 AND (SELECT COUNT(*)=1
  FROM saas_rls_private.synthetic_producer_operations
  WHERE operation_id=(:'op_a')::UUID)
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.local_publication_audit_outbox
  WHERE correlation_id='ci-op-first')
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_delivery_intents i
   JOIN saas_rls_private.local_publication_audit_outbox e USING(event_id)
   WHERE e.correlation_id='ci-op-first'),
 'One committed producer operation atomically stages signed 009+013');
SELECT (SELECT event_id::TEXT FROM saas_rls_private.synthetic_producer_operations
 WHERE operation_id=(:'op_a')::UUID) AS op_a_event \gset

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.record_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects','ci-op-replay',
 (:'op_a')::UUID,1)::TEXT AS op_replayed \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'op_replayed'='true'
 AND NOT EXISTS (SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
 WHERE correlation_id='ci-op-replay')
 AND (SELECT event_id::TEXT=:'op_a_event'
  FROM saas_rls_private.synthetic_producer_operations
  WHERE operation_id=(:'op_a')::UUID),
 'Re-authenticated same UUID binds to original committed intent');

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.record_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects','ci-op-shape',
 (:'op_a')::UUID,2)::TEXT AS op_wrong_limit \gset
SELECT saas_rls.record_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','accounts','ci-op-collection',
 (:'op_a')::UUID,1)::TEXT AS op_wrong_collection \gset
SELECT saas_rls.record_signed_synthetic_operation(
 'demo-north','actor-north','tenant-viewer','projects','ci-op-role',
 (:'op_a')::UUID,1)::TEXT AS op_wrong_role \gset
SELECT saas_rls.record_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects','ci-op-null',
 NULL::UUID,1)::TEXT AS op_null \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'op_wrong_limit'='false' AND :'op_wrong_collection'='false'
 AND :'op_wrong_role'='false' AND :'op_null'='false'
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
 WHERE correlation_id IN ('ci-op-shape','ci-op-collection','ci-op-role','ci-op-null')),
 'Different request shape, role and null UUID must not produce new event');

BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.record_signed_synthetic_operation(
 'demo-orbit','actor-orbit','tenant-viewer','projects','ci-op-cross-tenant',
 (:'op_a')::UUID,1)::TEXT AS op_foreign \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'op_foreign'='false'
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
  WHERE correlation_id='ci-op-cross-tenant'),
 'Global UUID collision with different tenant/actor never reuses authority');

-- COMMIT did not happen: the registry, signed audit and derived 013 intent
-- all vanish. Retrying identical UUID may now create the FIRST event.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.record_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects','ci-op-rollback',
 (:'op_b')::UUID,1)::TEXT AS op_rollback_staged \gset
RESET ROLE;
ROLLBACK;
SELECT saas_rls_test.assert_true(
 :'op_rollback_staged'='true'
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.synthetic_producer_operations
 WHERE operation_id=(:'op_b')::UUID)
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
 WHERE correlation_id='ci-op-rollback'),
 'Uncommitted operation identity and intent cannot survive SQL ROLLBACK');
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.record_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects','ci-op-after-rollback',
 (:'op_b')::UUID,1)::TEXT AS op_after_rollback \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'op_after_rollback'='true'
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_producer_operations
  WHERE operation_id=(:'op_b')::UUID),
 'Retry after a true rollback creates first committed operation exactly once');

DO $immutable$
DECLARE rejected BOOLEAN:=FALSE;
BEGIN
 BEGIN
  UPDATE saas_rls_private.synthetic_producer_operations
  SET requested_limit=5 WHERE operation_id='11111111-1111-4111-8111-111111111111';
 EXCEPTION WHEN OTHERS THEN rejected:=TRUE; END;
 PERFORM saas_rls_test.assert_true(rejected,'Immutable producer binding is append-only');
END
$immutable$;
\echo 'PASS: signed producer operation replay, conflict/IDOR, rollback and ACL'
