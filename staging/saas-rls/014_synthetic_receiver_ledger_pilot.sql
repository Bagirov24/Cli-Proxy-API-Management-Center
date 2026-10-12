-- Stage 2G.4d.7d follow-up: a DURABLE, synthetic PostgreSQL receiver.
-- This is a local transactional effect ledger, not network delivery.
-- It does not replace 013's mock ACK interface or fix pre-COMMIT handoff.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
  OR current_setting('saas.staging_only',TRUE) IS DISTINCT FROM 'true'
  OR to_regclass('saas_rls_private.synthetic_delivery_intents') IS NULL
  OR to_regclass('saas_rls_private.synthetic_delivery_state') IS NULL
  OR to_regprocedure('saas_rls_private.mark_mock_delivery_ack(bigint,bigint,uuid,uuid)') IS NULL
  OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_rls_owner'
    AND NOT rolsuper AND NOT rolbypassrls)
 THEN RAISE EXCEPTION 'Refusing receiver ledger outside disposable PostgreSQL16';
 END IF;
END
$guard$;

DO $role$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_mock_receiver') THEN
   CREATE ROLE saas_mock_receiver NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_mock_receiver'
   AND NOT rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls)
 THEN RAISE EXCEPTION 'Synthetic receiver must be NOLOGIN/no-bypass';
 END IF;
END
$role$;
GRANT USAGE ON SCHEMA saas_rls_private TO saas_mock_receiver;

-- In this deliberately local receiver the durable row IS the entire
-- synthetic logical effect and its receipt. Both are committed atomically.
-- A real remote side effect cannot be made atomic with this database.
CREATE TABLE IF NOT EXISTS saas_rls_private.synthetic_receiver_effects (
 idempotency_key UUID PRIMARY KEY,
 event_id BIGINT NOT NULL UNIQUE REFERENCES
   saas_rls_private.synthetic_delivery_intents(event_id),
 effect_kind TEXT NOT NULL CHECK (effect_kind='audit_observed_v1'),
 receipt_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
 applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE saas_rls_private.synthetic_receiver_effects OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.synthetic_receiver_effects
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_audit_reconciler,
      saas_mock_delivery_worker,saas_mock_receiver;
DROP TRIGGER IF EXISTS saas_synthetic_receiver_append_only
 ON saas_rls_private.synthetic_receiver_effects;
CREATE TRIGGER saas_synthetic_receiver_append_only
 BEFORE UPDATE OR DELETE ON saas_rls_private.synthetic_receiver_effects
 FOR EACH ROW EXECUTE FUNCTION saas_rls_private.reject_local_audit_mutation();

-- Caller sees a minimal UUID receipt and "applied_now"; no audit, tenant,
-- actor, SQL row or payload content. The active 013 claim is mandatory.
-- Concurrent same-key calls serialize on the PK; the loser rereads the
-- committed receipt and does NOT apply another effect.
CREATE OR REPLACE FUNCTION saas_rls_private.receive_synthetic_delivery(
 expected_event BIGINT, expected_key UUID, expected_kind TEXT
) RETURNS TABLE(receiver_receipt UUID,applied_now BOOLEAN)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE saved_event BIGINT;
DECLARE saved_kind TEXT;
DECLARE saved_receipt UUID;
BEGIN
 IF expected_event IS NULL OR expected_event<=0 OR expected_key IS NULL
    OR expected_kind IS DISTINCT FROM 'audit_observed_v1'
 THEN RETURN; END IF;
 IF NOT EXISTS (
   SELECT 1 FROM saas_rls_private.synthetic_delivery_intents i
   JOIN saas_rls_private.synthetic_delivery_state s ON s.event_id=i.event_id
   WHERE i.event_id=expected_event AND i.idempotency_key=expected_key
     AND s.status='leased' AND s.lease_until>clock_timestamp()
 ) THEN RETURN; END IF;

 INSERT INTO saas_rls_private.synthetic_receiver_effects AS e
   (idempotency_key,event_id,effect_kind)
 VALUES(expected_key,expected_event,expected_kind)
 ON CONFLICT(idempotency_key) DO NOTHING
 RETURNING e.receipt_id INTO saved_receipt;
 IF saved_receipt IS NOT NULL THEN
   receiver_receipt:=saved_receipt; applied_now:=TRUE;
   RETURN NEXT;
   RETURN;
 END IF;
 SELECT e.event_id,e.effect_kind,e.receipt_id
   INTO saved_event,saved_kind,saved_receipt
 FROM saas_rls_private.synthetic_receiver_effects e
 WHERE e.idempotency_key=expected_key;
 IF saved_receipt IS NULL OR saved_event<>expected_event
    OR saved_kind<>expected_kind THEN
   RAISE EXCEPTION 'Synthetic receiver idempotency binding conflict';
 END IF;
 receiver_receipt:=saved_receipt; applied_now:=FALSE;
 RETURN NEXT;
END
$fn$;
ALTER FUNCTION saas_rls_private.receive_synthetic_delivery(BIGINT,UUID,TEXT)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION
 saas_rls_private.receive_synthetic_delivery(BIGINT,UUID,TEXT)
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_audit_reconciler,
      saas_mock_delivery_worker;
GRANT EXECUTE ON FUNCTION
 saas_rls_private.receive_synthetic_delivery(BIGINT,UUID,TEXT)
 TO saas_mock_receiver;

-- Optional STRONGER synthetic marker: verify an actual committed receiver
-- ledger receipt before delegating to 013's unchanged fenced state machine.
-- 013's original key-only mock ACK intentionally remains available for
-- backwards-compatible pilot tests; it is NOT a production receipt gate.
CREATE OR REPLACE FUNCTION saas_rls_private.mark_mock_receiver_ack(
 expected_event BIGINT,expected_generation BIGINT,
 expected_token UUID,expected_receipt UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE stable_key UUID;
BEGIN
 IF expected_event IS NULL OR expected_event<=0 OR
    expected_generation IS NULL OR expected_generation<=0 OR
    expected_token IS NULL OR expected_receipt IS NULL
 THEN RETURN FALSE; END IF;
 SELECT i.idempotency_key INTO stable_key
 FROM saas_rls_private.synthetic_delivery_intents i
 JOIN saas_rls_private.synthetic_receiver_effects e
   ON e.event_id=i.event_id AND e.idempotency_key=i.idempotency_key
 WHERE i.event_id=expected_event AND e.receipt_id=expected_receipt
   AND e.effect_kind='audit_observed_v1';
 IF stable_key IS NULL THEN RETURN FALSE; END IF;
 RETURN saas_rls_private.mark_mock_delivery_ack(
   expected_event,expected_generation,expected_token,stable_key);
END
$fn$;
ALTER FUNCTION saas_rls_private.mark_mock_receiver_ack(BIGINT,BIGINT,UUID,UUID)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION
 saas_rls_private.mark_mock_receiver_ack(BIGINT,BIGINT,UUID,UUID)
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_audit_reconciler,
      saas_mock_receiver;
GRANT EXECUTE ON FUNCTION
 saas_rls_private.mark_mock_receiver_ack(BIGINT,BIGINT,UUID,UUID)
 TO saas_mock_delivery_worker;

DO $assert$
BEGIN
 IF has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
 OR has_schema_privilege('saas_ci_runner','saas_rls_private','USAGE')
 OR has_table_privilege('saas_mock_receiver',
   'saas_rls_private.synthetic_receiver_effects','SELECT')
 OR has_table_privilege('saas_mock_receiver',
   'saas_rls_private.synthetic_receiver_effects','INSERT')
 OR has_table_privilege('saas_mock_delivery_worker',
   'saas_rls_private.synthetic_receiver_effects','SELECT')
 OR has_table_privilege('saas_mock_receiver',
   'saas_rls_private.synthetic_delivery_state','SELECT')
 OR has_function_privilege('saas_rls_reader',
   'saas_rls_private.receive_synthetic_delivery(bigint,uuid,text)','EXECUTE')
 OR has_function_privilege('saas_ci_runner',
   'saas_rls_private.mark_mock_receiver_ack(bigint,bigint,uuid,uuid)','EXECUTE')
 OR has_function_privilege('saas_mock_receiver',
   'saas_rls_private.mark_mock_receiver_ack(bigint,bigint,uuid,uuid)','EXECUTE')
 OR NOT has_function_privilege('saas_mock_receiver',
   'saas_rls_private.receive_synthetic_delivery(bigint,uuid,text)','EXECUTE')
 OR NOT has_function_privilege('saas_mock_delivery_worker',
   'saas_rls_private.mark_mock_receiver_ack(bigint,bigint,uuid,uuid)','EXECUTE')
 THEN RAISE EXCEPTION 'Synthetic receiver least-privilege failure'; END IF;
END
$assert$;
COMMIT;
\echo 'PASS: guarded transactional synthetic receiver ledger and receipt-gated ACK'