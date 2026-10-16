\set ON_ERROR_STOP on
-- Stage 2G.4d.7i. Disposable PG16, migration 018 applied AFTER
-- privileged replays of 015/016/017. Never test this against /data.
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
 OR to_regclass('saas_rls_private.synthetic_operation_budgets') IS NULL
 OR to_regprocedure('saas_rls_private.synthetic_operation_retention_health(text)') IS NULL
 THEN RAISE EXCEPTION 'Refusing retention hard-stop test outside PG16'; END IF;
END
$guard$;

SELECT saas_rls_test.assert_true(
 NOT has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
 AND NOT has_function_privilege('saas_rls_reader',
   'saas_rls_private.issue_signed_synthetic_operation_core(text,text,text,text,uuid,integer,integer)','EXECUTE')
 AND NOT has_function_privilege('saas_rls_reader',
   'saas_rls_private.read_signed_synthetic_operation_status_core(text,text,text,text,uuid,integer)','EXECUTE')
 AND NOT has_function_privilege('saas_rls_reader',
   'saas_rls_private.record_signed_synthetic_operation_core(text,text,text,text,text,uuid,integer)','EXECUTE')
 AND NOT has_function_privilege('saas_ci_runner',
   'saas_rls_private.synthetic_operation_retention_health(text)','EXECUTE')
 AND NOT has_table_privilege('saas_rls_reader',
   'saas_rls_private.synthetic_operation_issues','TRUNCATE')
 AND NOT has_table_privilege('saas_rls_reader',
   'saas_rls_private.synthetic_producer_operations','DELETE'),
 'Raw SQL principals cannot use private retention, core bypass or table mutation');

-- 017 fixture already filled North's 48 and Orbit's 12 immutable
-- issue tombstones. Even legacy exposed 016 function must now fail CLOSED.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.issue_signed_synthetic_operation(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'::UUID,1,120)::TEXT AS legacy_exhausted \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'legacy_exhausted'='false'
 AND (SELECT COUNT(*)=12 FROM saas_rls_private.synthetic_operation_issues
      WHERE tenant_id='demo-orbit' AND actor_id='actor-orbit')
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.synthetic_operation_issues
      WHERE operation_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'::UUID),
 'Direct legacy 016 caller cannot bypass lifetime cap or create a new tombstone');

-- 016 SQL status is now a separate authenticated legacy bucket, not
-- an unmetered route. It returns NULL to direct SQL for a throttle.
-- Earlier 016 acceptance has already performed one foreign UUID probe:
-- the invariant is increment-by-one, not absolute used_count=1.
SELECT COALESCE((SELECT used_count FROM
 saas_rls_private.synthetic_operation_budgets
 WHERE tenant_id='demo-orbit' AND actor_id='actor-orbit'
 AND scope_kind='actor' AND action_kind='legacy_status'),0)
 AS legacy_status_before \gset
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.read_signed_synthetic_operation_status(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 '88888888-8888-4888-8888-888888888881'::UUID,1) AS legacy_valid \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'legacy_valid'='issued'
 AND (SELECT used_count=(:'legacy_status_before')::INTEGER+1
  FROM saas_rls_private.synthetic_operation_budgets
  WHERE tenant_id='demo-orbit' AND actor_id='actor-orbit'
    AND scope_kind='actor' AND action_kind='legacy_status'),
 'Legacy status route consumes private quota without disclosing another actor');

-- PostgreSQL superuser fixture saturates the disposable legacy counter,
-- WITHOUT modifying any issued UUID or production data.
UPDATE saas_rls_private.synthetic_operation_budgets
 SET used_count=16,window_until=clock_timestamp()+interval '45 seconds'
 WHERE tenant_id='demo-orbit' AND action_kind='legacy_status';
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT COALESCE(saas_rls.read_signed_synthetic_operation_status(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 '88888888-8888-4888-8888-888888888881'::UUID,1),'')
 AS direct_legacy_throttled \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'direct_legacy_throttled'=''
 AND (SELECT used_count=16 FROM saas_rls_private.synthetic_operation_budgets
  WHERE tenant_id='demo-orbit' AND actor_id='actor-orbit'
    AND scope_kind='actor' AND action_kind='legacy_status'),
 'Legacy direct SQL lookup cannot read known UUID after exhausting status quota');

-- One real signed 015 producer event is allowed despite Orbit's issuer cap:
-- legacy 015 remains a deliberately separate NO-PAYLOAD event-only path,
-- now protected by an insert budget and producer lifetime ceiling.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.record_signed_synthetic_operation(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 'ci-018-producer-first',
 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'::UUID,1)::TEXT
 AS first_legacy_event \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'first_legacy_event'='true'
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_producer_operations
   WHERE operation_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'::UUID)
 AND (SELECT used_count>=1 FROM saas_rls_private.synthetic_operation_budgets
   WHERE scope_kind='actor' AND tenant_id='demo-orbit'
     AND actor_id='actor-orbit' AND action_kind='producer_event'),
 'Direct 015 signed insertion is metered and atomically creates one intent');

-- The next new UUID hits the 018 INSERT guard AFTER its 009 audit has
-- staged; a caught exception must ROLLBACK the entire nested operation.
UPDATE saas_rls_private.synthetic_operation_budgets
 SET used_count=32,window_until=clock_timestamp()+interval '45 seconds'
 WHERE tenant_id='demo-orbit' AND action_kind='producer_event'
   AND scope_kind='actor' AND actor_id='actor-orbit';
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
DO $probe$
DECLARE blocked BOOLEAN:=FALSE;
BEGIN
 BEGIN
  PERFORM saas_rls.record_signed_synthetic_operation(
   'demo-orbit','actor-orbit','tenant-viewer','projects',
   'ci-018-producer-throttled',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'::UUID,1);
 EXCEPTION WHEN check_violation THEN blocked:=TRUE; END;
 IF NOT blocked THEN
   RAISE EXCEPTION 'Legacy producer event bypassed append-only insert quota';
 END IF;
END
$probe$;
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 NOT EXISTS(SELECT 1 FROM saas_rls_private.synthetic_producer_operations
  WHERE operation_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'::UUID)
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
  WHERE correlation_id='ci-018-producer-throttled')
 AND (SELECT used_count=32 FROM saas_rls_private.synthetic_operation_budgets
   WHERE tenant_id='demo-orbit' AND actor_id='actor-orbit'
   AND scope_kind='actor' AND action_kind='producer_event'),
 'Producer insert guard rolls back 009/013 on exhausted budget');

-- Exact replay still reuses committed event even though NEW event
-- creation is now refused by the producer insert quota.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.record_signed_synthetic_operation(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 'ci-018-producer-replay',
 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'::UUID,1)::TEXT
 AS replay_old_event \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'replay_old_event'='true'
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
  WHERE correlation_id='ci-018-producer-replay'),
 'Insert quota cannot cause a duplicate event or suppress idempotent replay');

-- All expired identifiers still occupy immutable storage. The private
-- report is an INTERNAL non-destructive capacity snapshot, not a seal.
SELECT saas_rls_test.assert_true(
 (SELECT issued_total=48 AND issue_capacity_left=0
  AND producer_capacity_left>=0 AND gc_permitted=FALSE
  FROM saas_rls_private.synthetic_operation_retention_health('demo-north'))
 AND (SELECT issued_total=12 AND gc_permitted=FALSE
  FROM saas_rls_private.synthetic_operation_retention_health('demo-orbit'))
 AND NOT EXISTS(SELECT 1
  FROM saas_rls_private.synthetic_operation_retention_health('invalid tenant !')),
 'Private capacity report never suggests destructive GC or exposes UUIDs');

DO $immutability$
DECLARE blocked_truncate BOOLEAN:=FALSE;
DECLARE blocked_producer_update BOOLEAN:=FALSE;
DECLARE before_count BIGINT;
BEGIN
 SELECT COUNT(*) INTO before_count FROM saas_rls_private.synthetic_operation_issues;
 BEGIN
  TRUNCATE TABLE saas_rls_private.synthetic_operation_issues;
 EXCEPTION WHEN OTHERS THEN blocked_truncate:=TRUE; END;
 BEGIN
  UPDATE saas_rls_private.synthetic_producer_operations
    SET requested_limit=2
  WHERE operation_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'::UUID;
 EXCEPTION WHEN OTHERS THEN blocked_producer_update:=TRUE; END;
 PERFORM saas_rls_test.assert_true(
  blocked_truncate AND blocked_producer_update
  AND (SELECT COUNT(*)=before_count
   FROM saas_rls_private.synthetic_operation_issues),
  'Even privileged TRUNCATE/UPDATE is rejected by triggers (not DDL-proof)');
END
$immutability$;

-- Detect a privileged out-of-order 015/016/017 replay before release:
-- migration 018 must be the last writer of the public wrapper functions.
SELECT saas_rls_test.assert_true(
 position('legacy_issue' IN pg_get_functiondef(
  'saas_rls.issue_signed_synthetic_operation(text,text,text,text,uuid,integer,integer)'::regprocedure))>0
 AND position('legacy_status' IN pg_get_functiondef(
  'saas_rls.read_signed_synthetic_operation_status(text,text,text,text,uuid,integer)'::regprocedure))>0
 AND position('issue_signed_synthetic_operation_core' IN pg_get_functiondef(
  'saas_rls.issue_signed_synthetic_operation_bounded(text,text,text,text,uuid,integer,integer)'::regprocedure))>0
 AND position('read_signed_synthetic_operation_status_core' IN pg_get_functiondef(
  'saas_rls.read_signed_synthetic_operation_status_bounded(text,text,text,text,uuid,integer)'::regprocedure))>0,
 '018 final wrappers must remain metered after older migration replay');
\echo 'PASS: PG16 legacy 015/016 metered, retention GC=FALSE, TRUNCATE blocked, 018 last-writer'
