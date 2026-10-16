\set ON_ERROR_STOP on
-- 2G.4d.7c: committed-only local audit observation, bounded fencing,
-- transactional rollback and no privileges for ordinary readers.
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
 OR to_regclass('saas_rls_private.local_audit_reconciliation_state') IS NULL
 OR to_regclass('saas_rls_private.local_audit_reconciliation_history') IS NULL
 THEN RAISE EXCEPTION 'Refusing reconciler acceptance outside disposable PG16'; END IF;
END
$guard$;

-- A harmless assertion helper is explicitly granted for the disposable
-- acceptance role and REVOKED again before this script exits. Migration 012
-- itself grants neither application nor production testing permissions.
GRANT USAGE ON SCHEMA saas_rls_test TO saas_audit_reconciler;
GRANT EXECUTE ON FUNCTION saas_rls_test.assert_true(BOOLEAN,TEXT)
 TO saas_audit_reconciler;

SELECT saas_rls_test.assert_true(
 NOT has_table_privilege('saas_rls_reader',
  'saas_rls_private.local_audit_reconciliation_state','SELECT')
 AND NOT has_table_privilege('saas_ci_runner',
  'saas_rls_private.local_audit_reconciliation_history','INSERT')
 AND NOT has_table_privilege('saas_audit_reconciler',
  'saas_rls_private.local_publication_audit_outbox','SELECT')
 AND NOT has_table_privilege('saas_audit_reconciler',
  'saas_rls_private.local_audit_reconciliation_state','UPDATE')
 AND NOT has_function_privilege('saas_ci_runner',
  'saas_rls_private.claim_committed_local_audit(integer,integer,bigint)','EXECUTE')
 AND NOT has_function_privilege('saas_rls_reader',
  'saas_rls_private.mark_local_audit_reconciled(bigint,bigint,uuid)','EXECUTE')
 AND has_function_privilege('saas_audit_reconciler',
  'saas_rls_private.claim_committed_local_audit(integer,integer,bigint)','EXECUTE'),
 'Only NOLOGIN reconciler capability may lease/observe, without direct SQL access');

-- A signed Allow outbox INSERT is pending until COMMIT; rollback does NOT
-- leave a claimable event for another worker. No remote bytes are modeled.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.record_signed_local_publication(
  'demo-north','actor-north','tenant-admin','projects','ci-reconcile-rollback'),
 'Synthetic signed Allow can be staged before transaction rollback');
RESET ROLE;
ROLLBACK;
SELECT saas_rls_test.assert_true(
 NOT EXISTS(SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
 WHERE correlation_id='ci-reconcile-rollback'),
 'Rolled-back signed Allow cannot ever enter reconciliation');

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.record_signed_local_publication(
  'demo-north','actor-north','tenant-admin','projects','ci-reconcile-seeded'),
 'Only signed Allow can create a pending private event');
RESET ROLE;
COMMIT;
SELECT event_id::TEXT AS seeded_event
 FROM saas_rls_private.local_publication_audit_outbox
 WHERE correlation_id='ci-reconcile-seeded' AND result='allow' \gset

-- Committed audit event + uncommitted reconciler claim is NOT durable.
BEGIN;
SET LOCAL ROLE saas_audit_reconciler;
SELECT event_id::TEXT AS rolled_claim_event,
 generation::TEXT AS rolled_claim_generation,
 lease_token::TEXT AS rolled_claim_token
 FROM saas_rls_private.claim_committed_local_audit(
  1,5,(:'seeded_event')::BIGINT) \gset
RESET ROLE;
ROLLBACK;
SELECT saas_rls_test.assert_true(
 :'rolled_claim_event'=:'seeded_event'
 AND :'rolled_claim_generation'='1'
 AND NOT EXISTS(
   SELECT 1 FROM saas_rls_private.local_audit_reconciliation_state
   WHERE event_id=(:'seeded_event')::BIGINT)
 AND NOT EXISTS(
   SELECT 1 FROM saas_rls_private.local_audit_reconciliation_history
   WHERE event_id=(:'seeded_event')::BIGINT),
 'ROLLBACK of a claim removes its lease, generation and append-only history');

-- Lease is only durable AFTER worker COMMIT, never on client receipt.
BEGIN;
SET LOCAL ROLE saas_audit_reconciler;
SELECT event_id::TEXT AS first_event,
 generation::TEXT AS first_generation,
 lease_token::TEXT AS first_token
 FROM saas_rls_private.claim_committed_local_audit(
  1,1,(:'seeded_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'first_event'=:'seeded_event' AND :'first_generation'='1'
 AND (SELECT status='leased' AND generation=1
   FROM saas_rls_private.local_audit_reconciliation_state
   WHERE event_id=(:'seeded_event')::BIGINT)
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.local_audit_reconciliation_history
   WHERE event_id=(:'seeded_event')::BIGINT AND action='claimed'),
 'Committed lease exists once and history has only one claimed event');

BEGIN;
SET LOCAL ROLE saas_audit_reconciler;
SELECT saas_rls_test.assert_true(
 NOT EXISTS(SELECT 1 FROM saas_rls_private.claim_committed_local_audit(
  1,1,(:'seeded_event')::BIGINT)),
 'An unexpired lease must not be handed to another caller');
SELECT saas_rls_test.assert_true(
 NOT saas_rls_private.mark_local_audit_reconciled(
  (:'seeded_event')::BIGINT,1,gen_random_uuid())
 AND NOT saas_rls_private.mark_local_audit_reconciled(
  (:'seeded_event')::BIGINT,2,(:'first_token')::UUID),
 'Wrong fencing UUID or generation cannot acknowledge');
RESET ROLE;
ROLLBACK;

SELECT pg_sleep(1.2);
BEGIN;
SET LOCAL ROLE saas_audit_reconciler;
SELECT event_id::TEXT AS second_event,
 generation::TEXT AS second_generation,
 lease_token::TEXT AS second_token
 FROM saas_rls_private.claim_committed_local_audit(
  1,30,(:'seeded_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'second_event'=:'seeded_event'
 AND :'second_generation'='2'
 AND :'second_token'<>:'first_token'
 AND (SELECT COUNT(*)=2 FROM saas_rls_private.local_audit_reconciliation_history
     WHERE event_id=(:'seeded_event')::BIGINT),
 'Expired lease can be reclaimed with a new UUID/generation and audit trail');

BEGIN;
SET LOCAL ROLE saas_audit_reconciler;
SELECT saas_rls_test.assert_true(
 NOT saas_rls_private.mark_local_audit_reconciled(
  (:'seeded_event')::BIGINT,(:'first_generation')::BIGINT,
  (:'first_token')::UUID),
 'Stale former worker cannot ACK after newer claim');
SELECT saas_rls_test.assert_true(
 saas_rls_private.mark_local_audit_reconciled(
  (:'seeded_event')::BIGINT,(:'second_generation')::BIGINT,
  (:'second_token')::UUID),
 'Lease holder may durably observe the committed PostgreSQL event');
RESET ROLE;
ROLLBACK;
SELECT saas_rls_test.assert_true(
 (SELECT status='leased' AND generation=2
  FROM saas_rls_private.local_audit_reconciliation_state
  WHERE event_id=(:'seeded_event')::BIGINT)
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.local_audit_reconciliation_history
  WHERE event_id=(:'seeded_event')::BIGINT AND action='reconciled_local'),
 'ROLLBACK of ACK leaves lease and no false reconciliation history');

BEGIN;
SET LOCAL ROLE saas_audit_reconciler;
SELECT saas_rls_test.assert_true(
 saas_rls_private.mark_local_audit_reconciled(
  (:'seeded_event')::BIGINT,(:'second_generation')::BIGINT,
  (:'second_token')::UUID)
 AND NOT saas_rls_private.mark_local_audit_reconciled(
  (:'seeded_event')::BIGINT,(:'second_generation')::BIGINT,
  (:'second_token')::UUID),
 'Exactly one final local observation; duplicate ACK is false');
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 (SELECT status='reconciled_local' AND reconciled_at IS NOT NULL
    AND generation=2 AND lease_token IS NULL AND lease_until IS NULL
  FROM saas_rls_private.local_audit_reconciliation_state
  WHERE event_id=(:'seeded_event')::BIGINT)
 AND (SELECT COUNT(*)=3 FROM saas_rls_private.local_audit_reconciliation_history
  WHERE event_id=(:'seeded_event')::BIGINT)
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.local_audit_reconciliation_history
  WHERE event_id=(:'seeded_event')::BIGINT AND action='reconciled_local')
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.local_publication_audit_outbox
  WHERE event_id=(:'seeded_event')::BIGINT AND result='allow'),
 'Durable reconciliation is terminal with exactly one committed local ACK');

BEGIN;
SET LOCAL ROLE saas_audit_reconciler;
SELECT saas_rls_test.assert_true(
 NOT EXISTS (SELECT 1 FROM saas_rls_private.claim_committed_local_audit(
  1,2,(:'seeded_event')::BIGINT))
 AND NOT saas_rls_private.mark_local_audit_reconciled(
  (:'seeded_event')::BIGINT,2,(:'second_token')::UUID)
 AND NOT EXISTS (SELECT 1 FROM saas_rls_private.claim_committed_local_audit(
  1,2,9223372036854775807)),
 'Terminal event and unknown event cannot be claimed/observed again');
RESET ROLE;
ROLLBACK;

DO $immutable$
DECLARE update_denied BOOLEAN:=FALSE;
DECLARE delete_denied BOOLEAN:=FALSE;
BEGIN
 BEGIN
  UPDATE saas_rls_private.local_audit_reconciliation_history
   SET action='reclaimed' WHERE event_id=(SELECT event_id
     FROM saas_rls_private.local_publication_audit_outbox
     WHERE correlation_id='ci-reconcile-seeded');
 EXCEPTION WHEN OTHERS THEN update_denied:=TRUE; END;
 BEGIN
  DELETE FROM saas_rls_private.local_audit_reconciliation_history
   WHERE event_id=(SELECT event_id
     FROM saas_rls_private.local_publication_audit_outbox
     WHERE correlation_id='ci-reconcile-seeded');
 EXCEPTION WHEN OTHERS THEN delete_denied:=TRUE; END;
 PERFORM saas_rls_test.assert_true(update_denied AND delete_denied,
 'History is append only even for test fixture SQL mutation');
END
$immutable$;
REVOKE EXECUTE ON FUNCTION saas_rls_test.assert_true(BOOLEAN,TEXT)
 FROM saas_audit_reconciler;
REVOKE USAGE ON SCHEMA saas_rls_test FROM saas_audit_reconciler;
SELECT saas_rls_test.assert_true(
 NOT has_schema_privilege('saas_audit_reconciler','saas_rls_test','USAGE'),
 'Temporary PG16 test-helper privilege must not remain granted');
\echo 'PASS: committed-only local audit, lease fencing, retry, ACK rollback and terminal idempotency'
