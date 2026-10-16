\set ON_ERROR_STOP on
-- 2G.4d.7d: synthetic event-only intent, mock ACK and no network payload.
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
 OR to_regclass('saas_rls_private.synthetic_delivery_intents') IS NULL
 OR to_regclass('saas_rls_private.synthetic_delivery_state') IS NULL
 THEN RAISE EXCEPTION 'Refusing synthetic delivery acceptance outside CI'; END IF;
END
$guard$;
SELECT saas_rls_test.assert_true(
 NOT has_table_privilege('saas_rls_reader',
  'saas_rls_private.synthetic_delivery_intents','SELECT')
 AND NOT has_table_privilege('saas_ci_runner',
  'saas_rls_private.synthetic_delivery_state','INSERT')
 AND NOT has_table_privilege('saas_mock_delivery_worker',
  'saas_rls_private.synthetic_delivery_history','SELECT')
 AND NOT has_function_privilege('saas_rls_reader',
  'saas_rls_private.claim_synthetic_delivery(integer,integer,bigint)','EXECUTE')
 AND NOT has_function_privilege('saas_audit_reconciler',
  'saas_rls_private.mark_mock_delivery_ack(bigint,bigint,uuid,uuid)','EXECUTE')
 AND NOT has_function_privilege('saas_ci_runner',
  'saas_rls_private.mark_mock_delivery_ack(bigint,bigint,uuid,uuid)','EXECUTE')
 AND has_function_privilege('saas_mock_delivery_worker',
  'saas_rls_private.claim_synthetic_delivery(integer,integer,bigint)','EXECUTE'),
 'Synthetic delivery role isolated from app, reader and audit reconciler');

-- An intent and source audit must disappear together if an earlier local
-- handoff fails SQL COMMIT/transaction. This does NOT undo emitted bytes.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.record_signed_local_publication(
  'demo-north','actor-north','tenant-admin','projects','ci-synthetic-rollback'),
 'Signed staging source may insert audit + intent in same transaction');
RESET ROLE;
SELECT saas_rls_test.assert_true(
 (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_delivery_intents i
 JOIN saas_rls_private.local_publication_audit_outbox e
 ON e.event_id=i.event_id WHERE e.correlation_id='ci-synthetic-rollback'),
 'Intent is staged in same transaction before COMMIT');
ROLLBACK;
SELECT saas_rls_test.assert_true(
 NOT EXISTS(SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
 WHERE correlation_id='ci-synthetic-rollback')
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.synthetic_delivery_intents i
 JOIN saas_rls_private.local_publication_audit_outbox e
 ON e.event_id=i.event_id WHERE e.correlation_id='ci-synthetic-rollback'),
 'No uncommitted audit / delivery intent is claimable after ROLLBACK');

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.record_signed_local_publication(
  'demo-north','actor-north','tenant-admin','projects','ci-synthetic-ack'),
 'Signed Allow creates one committed immutable simulation intent');
RESET ROLE;
COMMIT;
SELECT i.event_id::TEXT AS delivery_event,i.idempotency_key::TEXT AS delivery_key
 FROM saas_rls_private.synthetic_delivery_intents i
 JOIN saas_rls_private.local_publication_audit_outbox e
 ON e.event_id=i.event_id WHERE e.correlation_id='ci-synthetic-ack' \gset
SELECT saas_rls_test.assert_true(
 (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_delivery_intents
  WHERE event_id=(:'delivery_event')::BIGINT)
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.synthetic_delivery_state
  WHERE event_id=(:'delivery_event')::BIGINT),
 'Committed source+intent are durable before any worker lease');

-- A committed intent cannot be consumed before separate LOCAL audit
-- observation has itself committed. No fake downstream effect yet.
BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT COUNT(*)::TEXT AS gated_count
 FROM saas_rls_private.claim_synthetic_delivery(
  1,1,(:'delivery_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'gated_count'='0', 'Unobserved local audit cannot enter mock delivery');

BEGIN;
SET LOCAL ROLE saas_audit_reconciler;
SELECT generation::TEXT AS observed_generation,lease_token::TEXT AS observed_token
 FROM saas_rls_private.claim_committed_local_audit(
  1,10,(:'delivery_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
BEGIN;
SET LOCAL ROLE saas_audit_reconciler;
SELECT saas_rls_private.mark_local_audit_reconciled(
 (:'delivery_event')::BIGINT,(:'observed_generation')::BIGINT,
 (:'observed_token')::UUID)::TEXT AS local_observed \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'local_observed'='true',
 'Only a separately committed local observation unlocks mock dispatch');

BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT delivery_event_id::TEXT AS first_event,
 delivery_generation::TEXT AS first_gen,
 fencing_token::TEXT AS first_fence,
 idempotency_key::TEXT AS first_key,
 attempt_number::TEXT AS first_attempt
 FROM saas_rls_private.claim_synthetic_delivery(
  1,1,(:'delivery_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'first_event'=:'delivery_event' AND :'first_gen'='1'
 AND :'first_key'=:'delivery_key' AND :'first_attempt'='1'
 AND (SELECT status='leased' AND attempts=1
  FROM saas_rls_private.synthetic_delivery_state
  WHERE event_id=(:'delivery_event')::BIGINT),
 'First mock delivery uses immutable event idempotency key');

BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT COUNT(*)::TEXT AS duplicate_claim
 FROM saas_rls_private.claim_synthetic_delivery(
  1,1,(:'delivery_event')::BIGINT) \gset
SELECT saas_rls_private.mark_mock_delivery_ack(
 (:'delivery_event')::BIGINT,1,(:'first_fence')::UUID,
 gen_random_uuid())::TEXT AS wrong_key \gset
SELECT saas_rls_private.mark_mock_delivery_ack(
 (:'delivery_event')::BIGINT,2,(:'first_fence')::UUID,
 (:'first_key')::UUID)::TEXT AS wrong_generation \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'duplicate_claim'='0' AND :'wrong_key'='false'
 AND :'wrong_generation'='false',
 'Wrong key/generation and unexpired duplicate claim are denied');

SELECT pg_sleep(1.3);
BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT delivery_event_id::TEXT AS second_event,
 delivery_generation::TEXT AS second_gen,
 fencing_token::TEXT AS second_fence,
 idempotency_key::TEXT AS second_key,
 attempt_number::TEXT AS second_attempt
 FROM saas_rls_private.claim_synthetic_delivery(
  1,25,(:'delivery_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'second_event'=:'delivery_event' AND :'second_gen'='2'
 AND :'second_attempt'='2' AND :'second_key'=:'first_key'
 AND :'second_fence'<>:'first_fence',
 'After missing ACK, retry uses SAME stable idempotency key and NEW fence');

BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT saas_rls_private.mark_mock_delivery_ack(
 (:'delivery_event')::BIGINT,1,(:'first_fence')::UUID,
 (:'first_key')::UUID)::TEXT AS stale_mock_ack \gset
SELECT saas_rls_private.mark_mock_delivery_ack(
 (:'delivery_event')::BIGINT,2,(:'second_fence')::UUID,
 (:'second_key')::UUID)::TEXT AS rollback_mock_ack \gset
RESET ROLE;
ROLLBACK;
SELECT saas_rls_test.assert_true(
 :'stale_mock_ack'='false' AND :'rollback_mock_ack'='true'
 AND (SELECT status='leased' AND generation=2
 FROM saas_rls_private.synthetic_delivery_state
 WHERE event_id=(:'delivery_event')::BIGINT)
 AND NOT EXISTS(SELECT 1 FROM saas_rls_private.synthetic_delivery_history
 WHERE event_id=(:'delivery_event')::BIGINT AND action='mock_acked'),
 'Stale worker denied; lost DB COMMIT does not persist mock ACK');

BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT saas_rls_private.mark_mock_delivery_ack(
 (:'delivery_event')::BIGINT,2,(:'second_fence')::UUID,
 (:'second_key')::UUID)::TEXT AS final_mock_ack \gset
RESET ROLE;
COMMIT;
BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT saas_rls_private.mark_mock_delivery_ack(
 (:'delivery_event')::BIGINT,2,(:'second_fence')::UUID,
 (:'second_key')::UUID)::TEXT AS repeated_mock_ack \gset
SELECT COUNT(*)::TEXT AS after_terminal_claim
 FROM saas_rls_private.claim_synthetic_delivery(
  1,1,(:'delivery_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'final_mock_ack'='true' AND :'repeated_mock_ack'='false'
 AND :'after_terminal_claim'='0'
 AND (SELECT status='mock_acked' AND attempts=2 AND mock_acked_at IS NOT NULL
  FROM saas_rls_private.synthetic_delivery_state
  WHERE event_id=(:'delivery_event')::BIGINT)
 AND (SELECT COUNT(*)=3 FROM saas_rls_private.synthetic_delivery_history
 WHERE event_id=(:'delivery_event')::BIGINT)
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_delivery_history
 WHERE event_id=(:'delivery_event')::BIGINT AND action='mock_acked'),
 'Mock ACK terminal once, no duplicated durable simulated effect');

-- No infinite retry loops: three expired attempts are recorded and
-- exhausted on the next scan, NOT misreported as remotely delivered.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.record_signed_local_publication(
  'demo-north','actor-north','tenant-admin','projects','ci-synthetic-exhaust'),
 'Synthetic exhaustion fixture is signed');
RESET ROLE;
COMMIT;
SELECT i.event_id::TEXT AS exhaust_event
 FROM saas_rls_private.synthetic_delivery_intents i
 JOIN saas_rls_private.local_publication_audit_outbox e
 ON e.event_id=i.event_id WHERE e.correlation_id='ci-synthetic-exhaust' \gset

BEGIN;
SET LOCAL ROLE saas_audit_reconciler;
SELECT generation::TEXT AS ex_audit_gen, lease_token::TEXT AS ex_audit_fence
 FROM saas_rls_private.claim_committed_local_audit(
  1,10,(:'exhaust_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
BEGIN;
SET LOCAL ROLE saas_audit_reconciler;
SELECT saas_rls_private.mark_local_audit_reconciled(
 (:'exhaust_event')::BIGINT,(:'ex_audit_gen')::BIGINT,
 (:'ex_audit_fence')::UUID)::TEXT AS ex_locally_observed \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(:'ex_locally_observed'='true',
 'Exhaustion fixture must first be locally observed');

BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT attempt_number::TEXT AS ex_attempt1
 FROM saas_rls_private.claim_synthetic_delivery(
  1,1,(:'exhaust_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
SELECT pg_sleep(1.15);
BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT attempt_number::TEXT AS ex_attempt2
 FROM saas_rls_private.claim_synthetic_delivery(
  1,1,(:'exhaust_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
SELECT pg_sleep(1.15);
BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT attempt_number::TEXT AS ex_attempt3
 FROM saas_rls_private.claim_synthetic_delivery(
  1,1,(:'exhaust_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
SELECT pg_sleep(1.15);
BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT COUNT(*)::TEXT AS no_attempt4 FROM
 saas_rls_private.claim_synthetic_delivery(
  1,1,(:'exhaust_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'ex_attempt1'='1' AND :'ex_attempt2'='2' AND :'ex_attempt3'='3'
 AND :'no_attempt4'='0'
 AND (SELECT status='retry_exhausted' AND attempts=3
  AND mock_acked_at IS NULL AND exhausted_at IS NOT NULL
 FROM saas_rls_private.synthetic_delivery_state
 WHERE event_id=(:'exhaust_event')::BIGINT)
 AND (SELECT COUNT(*)=4 FROM saas_rls_private.synthetic_delivery_history
  WHERE event_id=(:'exhaust_event')::BIGINT),
 'After three unacked mock attempts, terminal exhaustion is NOT an ACK');

DO $immutable$
DECLARE denied_intent BOOLEAN:=FALSE;
DECLARE denied_history BOOLEAN:=FALSE;
BEGIN
 BEGIN
  UPDATE saas_rls_private.synthetic_delivery_intents
  SET idempotency_key=gen_random_uuid()
  WHERE event_id=(SELECT event_id FROM
   saas_rls_private.local_publication_audit_outbox
   WHERE correlation_id='ci-synthetic-ack');
 EXCEPTION WHEN OTHERS THEN denied_intent:=TRUE; END;
 BEGIN
  DELETE FROM saas_rls_private.synthetic_delivery_history
  WHERE event_id=(SELECT event_id FROM
   saas_rls_private.local_publication_audit_outbox
   WHERE correlation_id='ci-synthetic-ack');
 EXCEPTION WHEN OTHERS THEN denied_history:=TRUE; END;
 PERFORM saas_rls_test.assert_true(denied_intent AND denied_history,
  'Immutable key and append-only history cannot be tampered with');
END
$immutable$;
\echo 'PASS: mock delivery intents, strict local observation gate, dedup ACK/retry/exhaustion'
