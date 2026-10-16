-- 2G.4d.7d: SYNTHETIC local event delivery intent and MOCK ACK only.
-- No resource/HTTP payload, external network send, real receiver or client ACK.
-- Disposable PostgreSQL16 CI. An intent is created in the SAME transaction
-- as signed 009 Allow audit; an independent worker sees it only after COMMIT.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
 OR current_setting('saas.staging_only',TRUE) IS DISTINCT FROM 'true'
 OR to_regclass('saas_rls_private.local_publication_audit_outbox') IS NULL
 OR to_regclass('saas_rls_private.local_audit_reconciliation_state') IS NULL
 OR to_regprocedure('saas_rls_private.reject_local_audit_mutation()') IS NULL
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='saas_rls_owner'
   AND NOT rolsuper AND NOT rolbypassrls)
 THEN RAISE EXCEPTION 'Refusing synthetic delivery outside disposable PG16 CI';
 END IF;
END
$guard$;

DO $role$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='saas_mock_delivery_worker') THEN
  CREATE ROLE saas_mock_delivery_worker NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='saas_mock_delivery_worker'
    AND NOT rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls)
 THEN RAISE EXCEPTION 'Synthetic delivery worker must never have login/bypass'; END IF;
END
$role$;
GRANT USAGE ON SCHEMA saas_rls_private TO saas_mock_delivery_worker;

-- The idempotency key is a random immutable label for one PG event, not
-- client/HTTP authority. NO payload/tenant/actor/SQL row is persisted here.
CREATE TABLE IF NOT EXISTS saas_rls_private.synthetic_delivery_intents (
 event_id BIGINT PRIMARY KEY REFERENCES
  saas_rls_private.local_publication_audit_outbox(event_id),
 idempotency_key UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE saas_rls_private.synthetic_delivery_intents OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.synthetic_delivery_intents
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_mock_delivery_worker;
DROP TRIGGER IF EXISTS saas_synthetic_intent_immutable
 ON saas_rls_private.synthetic_delivery_intents;
CREATE TRIGGER saas_synthetic_intent_immutable BEFORE UPDATE OR DELETE
 ON saas_rls_private.synthetic_delivery_intents
 FOR EACH ROW EXECUTE FUNCTION saas_rls_private.reject_local_audit_mutation();

CREATE OR REPLACE FUNCTION saas_rls_private.stage_synthetic_delivery_intent()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
 INSERT INTO saas_rls_private.synthetic_delivery_intents(event_id)
 VALUES(NEW.event_id);
 RETURN NULL;
END
$fn$;
ALTER FUNCTION saas_rls_private.stage_synthetic_delivery_intent()
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.stage_synthetic_delivery_intent()
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_mock_delivery_worker;
DROP TRIGGER IF EXISTS saas_synthetic_intent_on_signed_audit
 ON saas_rls_private.local_publication_audit_outbox;
CREATE TRIGGER saas_synthetic_intent_on_signed_audit
 AFTER INSERT ON saas_rls_private.local_publication_audit_outbox
 FOR EACH ROW EXECUTE FUNCTION saas_rls_private.stage_synthetic_delivery_intent();

-- Existing pre-013 source events are backfilled as LOCAL simulation only.
-- This does not mean any historical event was remotely delivered.
INSERT INTO saas_rls_private.synthetic_delivery_intents(event_id)
 SELECT e.event_id FROM saas_rls_private.local_publication_audit_outbox e
 ON CONFLICT(event_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS saas_rls_private.synthetic_delivery_state (
 event_id BIGINT PRIMARY KEY REFERENCES
  saas_rls_private.synthetic_delivery_intents(event_id),
 status TEXT NOT NULL CHECK
  (status IN ('leased','mock_acked','retry_exhausted')),
 generation BIGINT NOT NULL CHECK(generation>0),
 attempts INTEGER NOT NULL CHECK(attempts BETWEEN 1 AND 3),
 lease_token UUID,
 lease_until TIMESTAMPTZ,
 mock_acked_at TIMESTAMPTZ,
 exhausted_at TIMESTAMPTZ,
 CHECK(
  (status='leased' AND lease_token IS NOT NULL AND lease_until IS NOT NULL
     AND mock_acked_at IS NULL AND exhausted_at IS NULL)
  OR
  (status='mock_acked' AND lease_token IS NULL AND lease_until IS NULL
     AND mock_acked_at IS NOT NULL AND exhausted_at IS NULL)
  OR
  (status='retry_exhausted' AND lease_token IS NULL AND lease_until IS NULL
     AND mock_acked_at IS NULL AND exhausted_at IS NOT NULL)
 )
);
ALTER TABLE saas_rls_private.synthetic_delivery_state OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.synthetic_delivery_state
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_mock_delivery_worker;
CREATE INDEX IF NOT EXISTS synthetic_delivery_pending_idx
 ON saas_rls_private.synthetic_delivery_state(status,lease_until);

CREATE TABLE IF NOT EXISTS saas_rls_private.synthetic_delivery_history (
 history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 event_id BIGINT NOT NULL REFERENCES
  saas_rls_private.synthetic_delivery_intents(event_id),
 generation BIGINT NOT NULL CHECK(generation>0),
 action TEXT NOT NULL CHECK
  (action IN ('claimed','reclaimed','mock_acked','retry_exhausted')),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(event_id,generation,action)
);
ALTER TABLE saas_rls_private.synthetic_delivery_history OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.synthetic_delivery_history
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_mock_delivery_worker;
REVOKE ALL ON SEQUENCE
 saas_rls_private.synthetic_delivery_history_history_id_seq
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_mock_delivery_worker;
DROP TRIGGER IF EXISTS saas_synthetic_delivery_history_immutable
 ON saas_rls_private.synthetic_delivery_history;
CREATE TRIGGER saas_synthetic_delivery_history_immutable
 BEFORE UPDATE OR DELETE ON saas_rls_private.synthetic_delivery_history
 FOR EACH ROW EXECUTE FUNCTION saas_rls_private.reject_local_audit_mutation();

-- Only locally observed, committed signed events may become mock-delivery
-- candidates. Lock immutable INTENT row so concurrent workers SKIP it.
-- A vanished worker can be retried only after its lease expires.
-- MAX THREE claims; the fourth scan terminates as retry_exhausted.
CREATE OR REPLACE FUNCTION saas_rls_private.claim_synthetic_delivery(
 max_events INTEGER, lease_seconds INTEGER, target_event BIGINT DEFAULT NULL
) RETURNS TABLE(delivery_event_id BIGINT,delivery_generation BIGINT,
                fencing_token UUID,idempotency_key UUID,attempt_number INTEGER)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE selected RECORD;
DECLARE token UUID;
DECLARE next_generation BIGINT;
DECLARE next_attempt INTEGER;
DECLARE changed INTEGER;
BEGIN
 IF max_events IS NULL OR max_events<1 OR max_events>16
    OR lease_seconds IS NULL OR lease_seconds<1 OR lease_seconds>30
    OR (target_event IS NOT NULL AND target_event<=0) THEN
  RAISE EXCEPTION 'Invalid synthetic claim bounds';
 END IF;
 FOR selected IN
  SELECT i.event_id,i.idempotency_key,s.status,s.attempts,s.generation
  FROM saas_rls_private.synthetic_delivery_intents i
  JOIN saas_rls_private.local_audit_reconciliation_state o
    ON o.event_id=i.event_id AND o.status='reconciled_local'
  LEFT JOIN saas_rls_private.synthetic_delivery_state s ON s.event_id=i.event_id
  WHERE (target_event IS NULL OR i.event_id=target_event)
    AND (s.event_id IS NULL OR
      (s.status='leased' AND s.lease_until<=clock_timestamp()))
  ORDER BY i.event_id LIMIT max_events
  FOR UPDATE OF i SKIP LOCKED
 LOOP
  IF selected.attempts>=3 THEN
    UPDATE saas_rls_private.synthetic_delivery_state s
      SET status='retry_exhausted',lease_token=NULL,lease_until=NULL,
          exhausted_at=clock_timestamp()
      WHERE s.event_id=selected.event_id AND s.status='leased'
        AND s.lease_until<=clock_timestamp() AND s.attempts=3;
    GET DIAGNOSTICS changed=ROW_COUNT;
    -- ACK may have committed while this claimer waited for the state row.
    -- Never write an "exhausted" history event unless THIS transaction
    -- actually changed that exact state row to retry_exhausted.
    IF changed=1 THEN
      INSERT INTO saas_rls_private.synthetic_delivery_history
        (event_id,generation,action)
      VALUES(selected.event_id,selected.generation,'retry_exhausted');
    END IF;
    CONTINUE;
  END IF;
  token:=gen_random_uuid();
  next_generation:=NULL;
  next_attempt:=NULL;
  INSERT INTO saas_rls_private.synthetic_delivery_state AS state
      (event_id,status,generation,attempts,lease_token,lease_until)
  VALUES(selected.event_id,'leased',1,1,token,
         clock_timestamp()+make_interval(secs=>lease_seconds))
  ON CONFLICT ON CONSTRAINT synthetic_delivery_state_pkey
  DO UPDATE SET
    status='leased',
    generation=state.generation+1,
    attempts=state.attempts+1,
    lease_token=EXCLUDED.lease_token,
    lease_until=EXCLUDED.lease_until,
    mock_acked_at=NULL,
    exhausted_at=NULL
  WHERE state.status='leased' AND state.attempts<3
    AND state.lease_until<=clock_timestamp()
  RETURNING state.generation,state.attempts INTO next_generation,next_attempt;
  IF next_generation IS NOT NULL THEN
    INSERT INTO saas_rls_private.synthetic_delivery_history
      (event_id,generation,action)
    VALUES(selected.event_id,next_generation,
      CASE WHEN next_generation=1 THEN 'claimed' ELSE 'reclaimed' END);
    delivery_event_id:=selected.event_id;
    delivery_generation:=next_generation;
    fencing_token:=token;
    idempotency_key:=selected.idempotency_key;
    attempt_number:=next_attempt;
    RETURN NEXT;
  END IF;
 END LOOP;
END
$fn$;
ALTER FUNCTION saas_rls_private.claim_synthetic_delivery(INTEGER,INTEGER,BIGINT)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.claim_synthetic_delivery(INTEGER,INTEGER,BIGINT)
 FROM PUBLIC,saas_rls_reader,saas_ci_runner;
GRANT EXECUTE ON FUNCTION
 saas_rls_private.claim_synthetic_delivery(INTEGER,INTEGER,BIGINT)
 TO saas_mock_delivery_worker;

-- A worker supplies an ACK marker from an injected TEST fake sink.
-- PostgreSQL verifies that its idempotency key matches the same immutable
-- event and its active generation/UUID. A forged or stale marker denies,
-- but NONE of this cryptographically proves an actual external recipient.
CREATE OR REPLACE FUNCTION saas_rls_private.mark_mock_delivery_ack(
 expected_event BIGINT,expected_generation BIGINT,
 expected_token UUID,ack_idempotency_key UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE changed INTEGER:=0;
BEGIN
 IF expected_event IS NULL OR expected_event<=0 OR
    expected_generation IS NULL OR expected_generation<=0 OR
    expected_token IS NULL OR ack_idempotency_key IS NULL THEN RETURN FALSE; END IF;
 UPDATE saas_rls_private.synthetic_delivery_state s
  SET status='mock_acked',lease_token=NULL,lease_until=NULL,
      mock_acked_at=clock_timestamp()
 WHERE s.event_id=expected_event AND s.status='leased'
   AND s.generation=expected_generation AND s.lease_token=expected_token
   AND s.lease_until>clock_timestamp()
   AND EXISTS (
    SELECT 1 FROM saas_rls_private.synthetic_delivery_intents i
    WHERE i.event_id=s.event_id AND i.idempotency_key=ack_idempotency_key
   );
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RETURN FALSE; END IF;
 INSERT INTO saas_rls_private.synthetic_delivery_history
  (event_id,generation,action)
 VALUES(expected_event,expected_generation,'mock_acked');
 RETURN TRUE;
END
$fn$;
ALTER FUNCTION saas_rls_private.mark_mock_delivery_ack(BIGINT,BIGINT,UUID,UUID)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION
 saas_rls_private.mark_mock_delivery_ack(BIGINT,BIGINT,UUID,UUID)
 FROM PUBLIC,saas_rls_reader,saas_ci_runner;
GRANT EXECUTE ON FUNCTION
 saas_rls_private.mark_mock_delivery_ack(BIGINT,BIGINT,UUID,UUID)
 TO saas_mock_delivery_worker;

DO $assert$
BEGIN
 IF has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
 OR has_schema_privilege('saas_ci_runner','saas_rls_private','USAGE')
 OR has_table_privilege('saas_rls_reader',
  'saas_rls_private.synthetic_delivery_intents','SELECT')
 OR has_table_privilege('saas_mock_delivery_worker',
  'saas_rls_private.synthetic_delivery_state','UPDATE')
 OR has_table_privilege('saas_mock_delivery_worker',
  'saas_rls_private.local_publication_audit_outbox','SELECT')
 OR has_table_privilege('saas_ci_runner',
  'saas_rls_private.synthetic_delivery_history','INSERT')
 OR has_function_privilege('saas_rls_reader',
  'saas_rls_private.claim_synthetic_delivery(integer,integer,bigint)','EXECUTE')
 OR has_function_privilege('saas_ci_runner',
  'saas_rls_private.mark_mock_delivery_ack(bigint,bigint,uuid,uuid)','EXECUTE')
 OR NOT has_function_privilege('saas_mock_delivery_worker',
  'saas_rls_private.claim_synthetic_delivery(integer,integer,bigint)','EXECUTE')
 OR NOT has_function_privilege('saas_mock_delivery_worker',
  'saas_rls_private.mark_mock_delivery_ack(bigint,bigint,uuid,uuid)','EXECUTE')
 THEN RAISE EXCEPTION 'Synthetic delivery privilege leak'; END IF;
END
$assert$;
COMMIT;
\echo 'PASS: committed synthetic intent + bounded attempts + fenced mock ACK'
