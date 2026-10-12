\set ON_ERROR_STOP on
-- Real disposable PG16 receiver: local transactional effect != HTTP delivery.
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
 OR to_regclass('saas_rls_private.synthetic_receiver_effects') IS NULL
 THEN RAISE EXCEPTION 'Refusing receiver acceptance outside disposable PG16'; END IF;
END
$guard$;

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.record_signed_local_publication(
  'demo-north','actor-north','tenant-admin','projects','ci-receiver-durable'),
 'Receiver test requires a signed committed source');
RESET ROLE;
COMMIT;
SELECT i.event_id::TEXT AS rx_event,i.idempotency_key::TEXT AS rx_key
 FROM saas_rls_private.synthetic_delivery_intents i
 JOIN saas_rls_private.local_publication_audit_outbox e USING(event_id)
 WHERE e.correlation_id='ci-receiver-durable' \gset

-- No uncommitted/reconciliation-incomplete event can reach the receiver.
BEGIN;
SET LOCAL ROLE saas_mock_receiver;
SELECT COUNT(*)::TEXT AS rx_preobserve FROM
 saas_rls_private.receive_synthetic_delivery(
 (:'rx_event')::BIGINT,(:'rx_key')::UUID,'audit_observed_v1') \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(:'rx_preobserve'='0',
 'No synthetic logical effect before committed local audit and sender claim');

BEGIN;
SET LOCAL ROLE saas_audit_reconciler;
SELECT generation::TEXT AS rx_obgen,lease_token::TEXT AS rx_obtoken
 FROM saas_rls_private.claim_committed_local_audit(
  1,10,(:'rx_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
BEGIN;
SET LOCAL ROLE saas_audit_reconciler;
SELECT saas_rls_private.mark_local_audit_reconciled(
 (:'rx_event')::BIGINT,(:'rx_obgen')::BIGINT,(:'rx_obtoken')::UUID)::TEXT
 AS rx_observed \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(:'rx_observed'='true',
 'Local observation committed before recipient attempt');

BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT delivery_generation::TEXT AS rx_gen1,
 fencing_token::TEXT AS rx_fence1,idempotency_key::TEXT AS rx_claimkey1
 FROM saas_rls_private.claim_synthetic_delivery(
  1,1,(:'rx_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(:'rx_claimkey1'=:'rx_key',
 'Sender must carry immutable source key');

-- Receiver failure BEFORE its COMMIT leaves neither effect nor receipt.
BEGIN;
SET LOCAL ROLE saas_mock_receiver;
SELECT receiver_receipt::TEXT AS rx_rolled_receipt,
 applied_now::TEXT AS rx_rolled_applied
 FROM saas_rls_private.receive_synthetic_delivery(
 (:'rx_event')::BIGINT,(:'rx_key')::UUID,'audit_observed_v1') \gset
RESET ROLE;
ROLLBACK;
SELECT saas_rls_test.assert_true(
 :'rx_rolled_applied'='true' AND
 NOT EXISTS(SELECT 1 FROM saas_rls_private.synthetic_receiver_effects
 WHERE event_id=(:'rx_event')::BIGINT),
 'Receiver rollback must erase uncommitted local effect and receipt');

-- The committed receiver effect is the row itself. Its ACK is deliberately
-- lost: sender is NOT marked. A new connection replays the same UUID.
BEGIN;
SET LOCAL ROLE saas_mock_receiver;
SELECT receiver_receipt::TEXT AS rx_receipt1,
 applied_now::TEXT AS rx_applied1
 FROM saas_rls_private.receive_synthetic_delivery(
 (:'rx_event')::BIGINT,(:'rx_key')::UUID,'audit_observed_v1') \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'rx_applied1'='true'
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_receiver_effects
 WHERE event_id=(:'rx_event')::BIGINT)
 AND (SELECT status='leased' FROM saas_rls_private.synthetic_delivery_state
 WHERE event_id=(:'rx_event')::BIGINT),
 'Committed effect exists while sender has UNKNOWN ACK outcome');

SELECT pg_sleep(1.3);
BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT delivery_generation::TEXT AS rx_gen2,
 fencing_token::TEXT AS rx_fence2,idempotency_key::TEXT AS rx_claimkey2
 FROM saas_rls_private.claim_synthetic_delivery(
  1,15,(:'rx_event')::BIGINT) \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'rx_gen2'='2' AND :'rx_claimkey2'=:'rx_key'
 AND :'rx_fence1'<>:'rx_fence2',
 'Crash or lost ACK recovery must retain receiver identity and rotate fence');

BEGIN;
SET LOCAL ROLE saas_mock_receiver;
SELECT receiver_receipt::TEXT AS rx_receipt2,
 applied_now::TEXT AS rx_applied2
 FROM saas_rls_private.receive_synthetic_delivery(
 (:'rx_event')::BIGINT,(:'rx_key')::UUID,'audit_observed_v1') \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'rx_receipt2'=:'rx_receipt1' AND :'rx_applied2'='false'
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_receiver_effects
 WHERE event_id=(:'rx_event')::BIGINT),
 'Replay after receiver restart returns OLD receipt, never reapplies effect');

-- Conflict/invalid identity should never create a second effect.
BEGIN;
SET LOCAL ROLE saas_mock_receiver;
SELECT COUNT(*)::TEXT AS rx_bad_key_count FROM
 saas_rls_private.receive_synthetic_delivery(
 (:'rx_event')::BIGINT,gen_random_uuid(),'audit_observed_v1') \gset
SELECT COUNT(*)::TEXT AS rx_bad_kind_count FROM
 saas_rls_private.receive_synthetic_delivery(
 (:'rx_event')::BIGINT,(:'rx_key')::UUID,'different_effect') \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'rx_bad_key_count'='0' AND :'rx_bad_kind_count'='0',
 'Mismatched key or effect must be fail-closed');

BEGIN;
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT saas_rls_private.mark_mock_receiver_ack(
 (:'rx_event')::BIGINT,(:'rx_gen1')::BIGINT,
 (:'rx_fence1')::UUID,(:'rx_receipt1')::UUID)::TEXT AS rx_old_ack \gset
SELECT saas_rls_private.mark_mock_receiver_ack(
 (:'rx_event')::BIGINT,(:'rx_gen2')::BIGINT,
 (:'rx_fence2')::UUID,gen_random_uuid())::TEXT AS rx_fake_ack \gset
SELECT saas_rls_private.mark_mock_receiver_ack(
 (:'rx_event')::BIGINT,(:'rx_gen2')::BIGINT,
 (:'rx_fence2')::UUID,(:'rx_receipt2')::UUID)::TEXT AS rx_good_ack \gset
SELECT saas_rls_private.mark_mock_receiver_ack(
 (:'rx_event')::BIGINT,(:'rx_gen2')::BIGINT,
 (:'rx_fence2')::UUID,(:'rx_receipt2')::UUID)::TEXT AS rx_duplicate_ack \gset
RESET ROLE;
COMMIT;
SELECT saas_rls_test.assert_true(
 :'rx_old_ack'='false' AND :'rx_fake_ack'='false'
 AND :'rx_good_ack'='true' AND :'rx_duplicate_ack'='false'
 AND (SELECT status='mock_acked' FROM saas_rls_private.synthetic_delivery_state
 WHERE event_id=(:'rx_event')::BIGINT),
 'Only current fenced worker plus durable receipt may record synthetic ACK');

SELECT saas_rls_test.assert_true(
 NOT has_table_privilege('saas_rls_reader',
  'saas_rls_private.synthetic_receiver_effects','SELECT')
 AND NOT has_table_privilege('saas_mock_receiver',
  'saas_rls_private.synthetic_receiver_effects','INSERT')
 AND NOT has_function_privilege('saas_ci_runner',
  'saas_rls_private.receive_synthetic_delivery(bigint,uuid,text)','EXECUTE')
 AND NOT has_function_privilege('saas_mock_receiver',
  'saas_rls_private.mark_mock_receiver_ack(bigint,bigint,uuid,uuid)','EXECUTE')
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.synthetic_receiver_effects
 WHERE event_id=(:'rx_event')::BIGINT),
 'Reader/worker isolation and exactly one LOCAL receiver effect');

\echo 'PASS: PG16 durable receiver receipt, rollback, lost ACK, restart/retry, fencing and ACL'
