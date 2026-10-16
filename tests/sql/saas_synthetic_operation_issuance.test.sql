\set ON_ERROR_STOP on
-- Stage 2G.4d.7g: signed UUID issuance, TTL, recovery and fail-closed IDOR.
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
 OR to_regclass('saas_rls_private.synthetic_operation_issues') IS NULL
 OR to_regprocedure('saas_rls.issue_signed_synthetic_operation(text,text,text,text,uuid,integer,integer)') IS NULL
 THEN RAISE EXCEPTION 'Refusing producer issue/recovery acceptance outside disposable PG16'; END IF;
END
$guard$;
\set issue_a 44444444-4444-4444-8444-444444444444
\set issue_b 55555555-5555-4555-8555-555555555555
\set issue_c 66666666-6666-4666-8666-666666666666
\set issue_d 77777777-7777-4777-8777-777777777777

SELECT saas_rls_test.assert_true(
 NOT has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
 AND NOT has_table_privilege('saas_rls_reader',
  'saas_rls_private.synthetic_operation_issues','SELECT')
 AND NOT has_table_privilege('saas_ci_runner',
  'saas_rls_private.synthetic_operation_issues','INSERT')
 AND NOT has_table_privilege('saas_mock_receiver',
  'saas_rls_private.synthetic_operation_issues','SELECT')
 AND NOT has_function_privilege('saas_ci_runner',
  'saas_rls.issue_signed_synthetic_operation(text,text,text,text,uuid,integer,integer)','EXECUTE')
 AND NOT has_function_privilege('saas_ci_runner',
  'saas_rls.read_signed_synthetic_operation_status(text,text,text,text,uuid,integer)','EXECUTE')
 AND NOT has_function_privilege('saas_mock_delivery_worker',
  'saas_rls.record_signed_reserved_operation(text,text,text,text,text,uuid,integer)','EXECUTE')
 AND has_function_privilege('saas_rls_reader',
  'saas_rls.record_signed_reserved_operation(text,text,text,text,text,uuid,integer)','EXECUTE'),
 'Issuer/recovery SQL is callable only by signed tenant reader');

-- Issue does NOT create a signed outbox / intent or expose any private row.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.issue_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects',
 (:'issue_a')::UUID,1,120)::TEXT AS issue_success \gset
SELECT saas_rls.issue_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects',
 (:'issue_a')::UUID,1,120)::TEXT AS duplicate_issue \gset
SELECT saas_rls.read_signed_synthetic_operation_status(
 'demo-north','actor-north','tenant-admin','projects',
 (:'issue_a')::UUID,1) AS issued_status \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'issue_success'='true' AND :'duplicate_issue'='false'
 AND :'issued_status'='issued'
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.synthetic_producer_operations
   WHERE operation_id=(:'issue_a')::UUID)
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_operation_issues
   WHERE operation_id=(:'issue_a')::UUID),
 'A single UUID may be issued only once; still no deliverable intent');

-- Foreign actor cannot discover existence, even with correct UUID.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT COALESCE(saas_rls.read_signed_synthetic_operation_status(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 (:'issue_a')::UUID,1),'') AS foreign_status \gset
SELECT saas_rls.record_signed_reserved_operation(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 'ci-issue-foreign',( :'issue_a')::UUID,1)::TEXT AS foreign_commit \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(:'foreign_status'='' AND :'foreign_commit'='false'
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
  WHERE correlation_id='ci-issue-foreign'),
 'Foreign UUID is neither an authorization token nor a tenant existence oracle');

-- The original signed issuer can commit its event with this UUID only once.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT COALESCE(saas_rls.read_signed_synthetic_operation_status(
 'demo-north','actor-north','tenant-admin','projects',
 (:'issue_a')::UUID,2),'') AS wrong_limit_status \gset
SELECT saas_rls.record_signed_reserved_operation(
 'demo-north','actor-north','tenant-admin','projects','ci-issue-wrong',
 (:'issue_a')::UUID,2)::TEXT AS wrong_limit_commit \gset
SELECT saas_rls.record_signed_reserved_operation(
 'demo-north','actor-north','tenant-admin','projects','ci-issue-first',
 (:'issue_a')::UUID,1)::TEXT AS first_commit \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(:'wrong_limit_status'=''
 AND :'wrong_limit_commit'='false' AND :'first_commit'='true'
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
  WHERE correlation_id='ci-issue-wrong'),
 'Matching issued shape is required before first committed audit/intent');

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.read_signed_synthetic_operation_status(
 'demo-north','actor-north','tenant-admin','projects',
 (:'issue_a')::UUID,1) AS committed_status \gset
SELECT saas_rls.record_signed_reserved_operation(
 'demo-north','actor-north','tenant-admin','projects','ci-issue-replayed',
 (:'issue_a')::UUID,1)::TEXT AS replay_commit \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'committed_status'='committed' AND :'replay_commit'='true'
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_producer_operations
  WHERE operation_id=(:'issue_a')::UUID)
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
   WHERE correlation_id='ci-issue-replayed')
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_delivery_intents i
  JOIN saas_rls_private.synthetic_producer_operations p ON p.event_id=i.event_id
  WHERE p.operation_id=(:'issue_a')::UUID),
 'Status and replay observe exactly one committed event, never delivery ACK');

-- The issue deadline is a strict database-clock upper bound. An expired
-- UNUSED reservation is tombstoned (no new event and no re-issuance).
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.issue_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects',
 (:'issue_b')::UUID,1,2)::TEXT AS short_issued \gset
RESET ROLE;
COMMIT;
SELECT pg_sleep(2.15);
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.read_signed_synthetic_operation_status(
 'demo-north','actor-north','tenant-admin','projects',
 (:'issue_b')::UUID,1) AS expired_status \gset
SELECT saas_rls.record_signed_reserved_operation(
 'demo-north','actor-north','tenant-admin','projects',
 'ci-expired-attempt',( :'issue_b')::UUID,1)::TEXT AS expired_commit \gset
SELECT saas_rls.issue_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects',
 (:'issue_b')::UUID,1,120)::TEXT AS expired_reissue \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'short_issued'='true' AND :'expired_status'='expired'
 AND :'expired_commit'='false' AND :'expired_reissue'='false'
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_operation_issues
  WHERE operation_id=(:'issue_b')::UUID)
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
  WHERE correlation_id='ci-expired-attempt'),
 'Expired pending UUID is a permanent tombstone, never resurrected');

-- Issuance itself is transactional. ROLLBACK removes an uncommitted issue.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.issue_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects',
 (:'issue_c')::UUID,1,120)::TEXT AS rolled_issue \gset
RESET ROLE;
ROLLBACK;
SELECT saas_rls_test.assert_true(:'rolled_issue'='true'
 AND NOT EXISTS (SELECT 1 FROM saas_rls_private.synthetic_operation_issues
  WHERE operation_id=(:'issue_c')::UUID),
 'ROLLED BACK issuer has no durable issued token');
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.issue_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects',
 (:'issue_c')::UUID,1,120)::TEXT AS reissued_after_rollback \gset
RESET ROLE;
COMMIT;

-- A failed publication ROLLBACK preserves an already-committed issue
-- but creates no event. The same UUID can safely try again before expiry.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.record_signed_reserved_operation(
 'demo-north','actor-north','tenant-admin','projects','ci-issued-rolled-commit',
 (:'issue_c')::UUID,1)::TEXT AS rolled_commit \gset
RESET ROLE;
ROLLBACK;
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.read_signed_synthetic_operation_status(
 'demo-north','actor-north','tenant-admin','projects',
 (:'issue_c')::UUID,1) AS still_issued \gset
SELECT saas_rls.record_signed_reserved_operation(
 'demo-north','actor-north','tenant-admin','projects','ci-issued-after-rollback',
 (:'issue_c')::UUID,1)::TEXT AS successful_after_rollback \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'reissued_after_rollback'='true' AND :'rolled_commit'='true'
 AND :'still_issued'='issued' AND :'successful_after_rollback'='true'
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
  WHERE correlation_id='ci-issued-rolled-commit')
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_producer_operations
  WHERE operation_id=(:'issue_c')::UUID),
 'Committed issue survives publication rollback, later retry creates one event');

-- Committed producer event can be RECONFIRMED after short issuance TTL
-- (within recovery window), without creating another audit.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.issue_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects',
 (:'issue_d')::UUID,1,2)::TEXT AS brief_issued \gset
SELECT saas_rls.record_signed_reserved_operation(
 'demo-north','actor-north','tenant-admin','projects','ci-brief-committed',
 (:'issue_d')::UUID,1)::TEXT AS brief_committed \gset
RESET ROLE;
COMMIT;
SELECT pg_sleep(2.15);
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.read_signed_synthetic_operation_status(
 'demo-north','actor-north','tenant-admin','projects',
 (:'issue_d')::UUID,1) AS status_after_issue_ttl \gset
SELECT saas_rls.record_signed_reserved_operation(
 'demo-north','actor-north','tenant-admin','projects','ci-brief-replay',
 (:'issue_d')::UUID,1)::TEXT AS replay_after_issue_ttl \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'brief_issued'='true' AND :'brief_committed'='true'
 AND :'status_after_issue_ttl'='committed' AND :'replay_after_issue_ttl'='true'
 AND NOT EXISTS (SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
  WHERE correlation_id='ci-brief-replay'),
 'Committed event recoverable past issue TTL but before recovery window closes');

DO $immutable$
DECLARE blocked_issue BOOLEAN:=FALSE;
BEGIN
 BEGIN
  UPDATE saas_rls_private.synthetic_operation_issues
   SET issue_expires_at=issue_expires_at+interval '1 day'
   WHERE operation_id='44444444-4444-4444-8444-444444444444';
 EXCEPTION WHEN OTHERS THEN blocked_issue:=TRUE; END;
 PERFORM saas_rls_test.assert_true(blocked_issue,
  'Issued UUID TTL may never be extended through direct update');
END
$immutable$;
\echo 'PASS: guarded PG16 issue/recovery, expiry, tombstone, ROLLBACK, IDOR, ACL'
