\set ON_ERROR_STOP on
-- 2G.4d.7h: disposable PostgreSQL16 quotas, tombstones and IDOR.
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
 OR to_regclass('saas_rls_private.synthetic_operation_budgets') IS NULL
 OR to_regprocedure('saas_rls.issue_signed_synthetic_operation_bounded(text,text,text,text,uuid,integer,integer)') IS NULL
 THEN RAISE EXCEPTION 'Refusing operation budget tests outside PG16'; END IF;
END
$guard$;

SELECT saas_rls_test.assert_true(
 NOT has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
 AND NOT has_table_privilege('saas_rls_reader',
   'saas_rls_private.synthetic_operation_budgets','SELECT')
 AND NOT has_table_privilege('saas_ci_runner',
   'saas_rls_private.synthetic_operation_budgets','UPDATE')
 AND NOT has_table_privilege('saas_mock_receiver',
   'saas_rls_private.synthetic_operation_budgets','SELECT')
 AND NOT has_function_privilege('saas_rls_reader',
   'saas_rls_private.consume_synthetic_operation_budget(text,text,text)','EXECUTE')
 AND NOT has_function_privilege('saas_ci_runner',
   'saas_rls.read_signed_synthetic_operation_status_bounded(text,text,text,text,uuid,integer)','EXECUTE')
 AND has_function_privilege('saas_rls_reader',
   'saas_rls.read_signed_synthetic_operation_status_bounded(text,text,text,text,uuid,integer)','EXECUTE'),
 'No untrusted SQL or worker can tamper with private counters');

-- The same valid actor is allowed exactly 4 issued UUIDs / 5 minutes.
-- Direct 016 function remains for previous synthetic fixtures; 017 is new.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.issue_signed_synthetic_operation_bounded(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 '88888888-8888-4888-8888-888888888881'::UUID,1,120)::TEXT AS quota_1 \gset
SELECT saas_rls.issue_signed_synthetic_operation_bounded(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 '88888888-8888-4888-8888-888888888882'::UUID,1,120)::TEXT AS quota_2 \gset
SELECT saas_rls.issue_signed_synthetic_operation_bounded(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 '88888888-8888-4888-8888-888888888883'::UUID,1,120)::TEXT AS quota_3 \gset
SELECT saas_rls.issue_signed_synthetic_operation_bounded(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 '88888888-8888-4888-8888-888888888884'::UUID,1,120)::TEXT AS quota_4 \gset
SELECT saas_rls.issue_signed_synthetic_operation_bounded(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 '88888888-8888-4888-8888-888888888885'::UUID,1,120)::TEXT AS quota_denied \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'quota_1'='true' AND :'quota_2'='true'
 AND :'quota_3'='true' AND :'quota_4'='true'
 AND :'quota_denied'='false'
 AND (SELECT COUNT(*)=4 FROM saas_rls_private.synthetic_operation_issues
      WHERE tenant_id='demo-orbit' AND actor_id='actor-orbit')
 AND (SELECT used_count=4 FROM saas_rls_private.synthetic_operation_budgets
      WHERE tenant_id='demo-orbit' AND actor_id='actor-orbit'
        AND scope_kind='actor' AND action_kind='issue')
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.synthetic_operation_issues
      WHERE operation_id='88888888-8888-4888-8888-888888888885'::UUID),
 'Issue quota is atomic and refuses 5th UUID without a tombstone');

-- Unauthorized tenant/actor NEVER spends another principal's bucket.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.issue_signed_synthetic_operation_bounded(
 'demo-north','actor-north','tenant-admin','projects',
 '88888888-8888-4888-8888-888888888886'::UUID,1,120)::TEXT AS forged_issue \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(:'forged_issue'='false'
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.synthetic_operation_budgets
   WHERE tenant_id='demo-north' AND actor_id='actor-orbit'),
 'Cross-tenant signed scope mismatch never charges or creates target UUID');

-- Polling guessed UUIDs is charged BEFORE lookup and commits a debit,
-- even for an absent or foreign operation. No unbounded attempt rows.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
DO $probe$
DECLARE state TEXT;
DECLARE absent_count INTEGER:=0;
DECLARE blocked_count INTEGER:=0;
BEGIN
 FOR n IN 1..21 LOOP
   SELECT saas_rls.read_signed_synthetic_operation_status_bounded(
     'demo-orbit','actor-orbit','tenant-viewer','projects',
     '44444444-4444-4444-8444-444444444444'::UUID,1)
     INTO state;
   IF state='absent' THEN
     absent_count:=absent_count+1;
   ELSIF state='throttled' THEN
     blocked_count:=blocked_count+1;
   ELSE
     RAISE EXCEPTION 'Unexpected private status from guessed foreign UUID';
   END IF;
 END LOOP;
 IF absent_count<1 OR blocked_count<1 THEN
   RAISE EXCEPTION 'Expected both bounded lookup and throttle';
 END IF;
END
$probe$;
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 (SELECT used_count=16 FROM saas_rls_private.synthetic_operation_budgets
  WHERE scope_kind='actor' AND tenant_id='demo-orbit'
    AND actor_id='actor-orbit' AND action_kind='status')
 AND (SELECT used_count=16 FROM saas_rls_private.synthetic_operation_budgets
  WHERE scope_kind='tenant' AND tenant_id='demo-orbit'
    AND actor_id='*' AND action_kind='status')
 AND (SELECT COUNT(*)=2 FROM saas_rls_private.synthetic_operation_budgets
    WHERE tenant_id='demo-orbit' AND action_kind='status'),
 'Unknown-ID flood persists capped status budget; no one-row-per-request growth');

-- A valid UUID also receives only the INTERNAL throttle marker and cannot
-- infer whether another actor's operation exists once this window saturates.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.read_signed_synthetic_operation_status_bounded(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 '88888888-8888-4888-8888-888888888881'::UUID,1) AS saturated_status \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'saturated_status'='throttled',
 'Legitimate owner and foreign guess both fail closed under same rate limit');

-- Expired windows are reset IN PLACE, not via deleting history or UUIDs.
UPDATE saas_rls_private.synthetic_operation_budgets
 SET window_until=clock_timestamp()-interval '2 seconds'
 WHERE tenant_id='demo-orbit' AND action_kind='status';
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.read_signed_synthetic_operation_status_bounded(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 '88888888-8888-4888-8888-888888888881'::UUID,1) AS refreshed_status \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(:'refreshed_status'='issued'
 AND (SELECT used_count=1 FROM saas_rls_private.synthetic_operation_budgets
  WHERE scope_kind='actor' AND tenant_id='demo-orbit'
    AND actor_id='actor-orbit' AND action_kind='status'),
 'Window resets in place and can read a valid issued UUID after expiry');

-- Direct privileged staging insertion simulates historical tombstones and
-- proves the HARD actor cap, even after a budget window is reset.
UPDATE saas_rls_private.synthetic_operation_budgets
 SET window_until=clock_timestamp()-interval '2 seconds'
 WHERE tenant_id='demo-orbit' AND action_kind='issue';
INSERT INTO saas_rls_private.synthetic_operation_issues
 (operation_id,tenant_id,actor_id,membership_role,collection,
  requested_limit,issued_at,issue_expires_at,recovery_expires_at)
SELECT gen_random_uuid(),'demo-orbit','actor-orbit','tenant-viewer',
 'projects',1,clock_timestamp(),clock_timestamp()+interval '2 minutes',
 clock_timestamp()+interval '2 hours'
FROM generate_series(1,(
  SELECT 12-COUNT(*) FROM saas_rls_private.synthetic_operation_issues
  WHERE tenant_id='demo-orbit' AND actor_id='actor-orbit'));
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.issue_signed_synthetic_operation_bounded(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 '88888888-8888-4888-8888-888888888887'::UUID,1,120)::TEXT AS lifetime_actor_deny \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(:'lifetime_actor_deny'='false'
 AND (SELECT COUNT(*)=12 FROM saas_rls_private.synthetic_operation_issues
   WHERE tenant_id='demo-orbit' AND actor_id='actor-orbit'),
 'No actor can create an unlimited history of permanent tombstones');

-- The separate TENANT hard cap works even if that actor is under cap.
-- These rows are synthetic fixtures inserted only as disposable postgres.
INSERT INTO saas_rls_private.synthetic_operation_issues
 (operation_id,tenant_id,actor_id,membership_role,collection,
  requested_limit,issued_at,issue_expires_at,recovery_expires_at)
SELECT gen_random_uuid(),'demo-north','ci-staging-other-actor','tenant-viewer',
 'projects',1,clock_timestamp(),clock_timestamp()+interval '2 minutes',
 clock_timestamp()+interval '2 hours'
FROM generate_series(1,(
  SELECT 48-COUNT(*) FROM saas_rls_private.synthetic_operation_issues
  WHERE tenant_id='demo-north'));
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.issue_signed_synthetic_operation_bounded(
 'demo-north','actor-north','tenant-admin','projects',
 '88888888-8888-4888-8888-888888888888'::UUID,1,120)::TEXT AS lifetime_tenant_deny \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'lifetime_tenant_deny'='false'
 AND (SELECT COUNT(*)=48 FROM saas_rls_private.synthetic_operation_issues
  WHERE tenant_id='demo-north')
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.synthetic_operation_issues
  WHERE operation_id='88888888-8888-4888-8888-888888888888'::UUID),
 'Tenant cap is independent of per-actor limit, with no tombstone purge');

-- Reapply 017 must preserve ALL issue tombstones, state and counters.
DO $immutable$
DECLARE blocked_update BOOLEAN:=FALSE;
DECLARE blocked_delete BOOLEAN:=FALSE;
BEGIN
 BEGIN
  UPDATE saas_rls_private.synthetic_operation_issues
  SET issue_expires_at=issue_expires_at+interval '1 day'
  WHERE operation_id='88888888-8888-4888-8888-888888888881'::UUID;
 EXCEPTION WHEN OTHERS THEN blocked_update:=TRUE; END;
 BEGIN
  DELETE FROM saas_rls_private.synthetic_operation_issues
  WHERE operation_id='88888888-8888-4888-8888-888888888881'::UUID;
 EXCEPTION WHEN OTHERS THEN blocked_delete:=TRUE; END;
 PERFORM saas_rls_test.assert_true(blocked_update AND blocked_delete,
   'Tombstone remains immutable even when budget rolls to new window');
END
$immutable$;
\echo 'PASS: signed 017 bounded issuance/status, IDOR, window reset, lifetime caps and no GC'
