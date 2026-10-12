-- 2G.4d.7c: committed local security-audit reconciliation (PG16 staging).
-- A reconciled_local row proves only that a committed PG audit event was
-- observed durably. It NEVER attests HTTP delivery, an external ACK, or
-- whether synchronous local handoff happened before a failed PG COMMIT.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
    OR current_setting('saas.staging_only',TRUE) IS DISTINCT FROM 'true'
    OR to_regclass('saas_rls_private.local_publication_audit_outbox') IS NULL
    OR to_regprocedure('saas_rls_private.reject_local_audit_mutation()') IS NULL
    OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_rls_owner'
                   AND NOT rolsuper AND NOT rolbypassrls)
 THEN RAISE EXCEPTION 'Refusing audit reconciliation outside disposable PG16'; END IF;
END
$guard$;

-- NOLOGIN capability usable only by a supervised privileged CI fixture.
-- Neither the SaaS SQL reader nor the CI runner can claim or acknowledge.
DO $role$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_audit_reconciler') THEN
  CREATE ROLE saas_audit_reconciler NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles
   WHERE rolname='saas_audit_reconciler' AND NOT rolcanlogin
     AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit)
 THEN RAISE EXCEPTION 'Audit reconciler role must be NOLOGIN/no-bypass'; END IF;
END
$role$;
GRANT USAGE ON SCHEMA saas_rls_private TO saas_audit_reconciler;

-- One state per original append-only, committed Allow audit event.
-- There is no remote receipt, tenant resource row, bearer, or secret here.
CREATE TABLE IF NOT EXISTS saas_rls_private.local_audit_reconciliation_state (
 event_id BIGINT PRIMARY KEY REFERENCES
   saas_rls_private.local_publication_audit_outbox(event_id),
 status TEXT NOT NULL CHECK(status IN ('leased','reconciled_local')),
 generation BIGINT NOT NULL CHECK(generation>0),
 lease_token UUID,
 lease_until TIMESTAMPTZ,
 reconciled_at TIMESTAMPTZ,
 CHECK (
   (status='leased' AND lease_token IS NOT NULL AND lease_until IS NOT NULL
     AND reconciled_at IS NULL)
   OR
   (status='reconciled_local' AND lease_token IS NULL AND lease_until IS NULL
     AND reconciled_at IS NOT NULL)
 )
);
ALTER TABLE saas_rls_private.local_audit_reconciliation_state OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.local_audit_reconciliation_state FROM PUBLIC,
 saas_rls_reader,saas_ci_runner,saas_audit_reconciler;
CREATE INDEX IF NOT EXISTS local_audit_reconcile_pending_idx
 ON saas_rls_private.local_audit_reconciliation_state(status,lease_until);

-- Durable append-only local history, NOT a tamper-evident external store.
CREATE TABLE IF NOT EXISTS saas_rls_private.local_audit_reconciliation_history (
 history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 event_id BIGINT NOT NULL REFERENCES
   saas_rls_private.local_publication_audit_outbox(event_id),
 generation BIGINT NOT NULL CHECK(generation>0),
 action TEXT NOT NULL CHECK(action IN ('claimed','reclaimed','reconciled_local')),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(event_id,generation,action)
);
ALTER TABLE saas_rls_private.local_audit_reconciliation_history OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.local_audit_reconciliation_history FROM PUBLIC,
 saas_rls_reader,saas_ci_runner,saas_audit_reconciler;
REVOKE ALL ON SEQUENCE
 saas_rls_private.local_audit_reconciliation_history_history_id_seq
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_audit_reconciler;

DROP TRIGGER IF EXISTS saas_local_reconciliation_history_append_only
 ON saas_rls_private.local_audit_reconciliation_history;
CREATE TRIGGER saas_local_reconciliation_history_append_only
 BEFORE UPDATE OR DELETE ON saas_rls_private.local_audit_reconciliation_history
 FOR EACH ROW EXECUTE FUNCTION saas_rls_private.reject_local_audit_mutation();

-- A committed audit event is the ONLY source for a lease. FOR UPDATE
-- SKIP LOCKED on the immutable event row serializes concurrent claimers
-- while independent events remain claimable. A crashed/uncommitted claim
-- rolls back; a committed but unacknowledged lease can be reclaimed after
-- bounded expiry. The random UUID and monotonic generation fence stale ACKs.
CREATE OR REPLACE FUNCTION saas_rls_private.claim_committed_local_audit(
 max_events INTEGER, lease_seconds INTEGER, target_event BIGINT DEFAULT NULL
) RETURNS TABLE(event_id BIGINT,generation BIGINT,lease_token UUID)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $fn$
DECLARE candidate RECORD;
DECLARE next_gen BIGINT;
DECLARE next_token UUID;
BEGIN
 IF max_events IS NULL OR max_events<1 OR max_events>16
    OR lease_seconds IS NULL OR lease_seconds<1 OR lease_seconds>30
    OR (target_event IS NOT NULL AND target_event<=0) THEN
  RAISE EXCEPTION 'Invalid local reconciliation claim bounds';
 END IF;
 FOR candidate IN
  SELECT e.event_id FROM saas_rls_private.local_publication_audit_outbox e
  LEFT JOIN saas_rls_private.local_audit_reconciliation_state s
    ON s.event_id=e.event_id
  WHERE (target_event IS NULL OR e.event_id=target_event)
    AND (s.event_id IS NULL OR (s.status='leased' AND
       s.lease_until<=clock_timestamp()))
  ORDER BY e.event_id
  LIMIT max_events
  FOR UPDATE OF e SKIP LOCKED
 LOOP
  next_gen:=NULL;
  next_token:=gen_random_uuid();
  INSERT INTO saas_rls_private.local_audit_reconciliation_state AS state
     (event_id,status,generation,lease_token,lease_until)
  VALUES (candidate.event_id,'leased',1,next_token,
          clock_timestamp()+make_interval(secs=>lease_seconds))
  ON CONFLICT ON CONSTRAINT local_audit_reconciliation_state_pkey DO UPDATE SET
     status='leased',
     generation=state.generation+1,
     lease_token=EXCLUDED.lease_token,
     lease_until=EXCLUDED.lease_until,
     reconciled_at=NULL
   WHERE state.status='leased' AND state.lease_until<=clock_timestamp()
  RETURNING state.generation INTO next_gen;
  IF next_gen IS NOT NULL THEN
   INSERT INTO saas_rls_private.local_audit_reconciliation_history
    (event_id,generation,action)
   VALUES(candidate.event_id,next_gen,
          CASE WHEN next_gen=1 THEN 'claimed' ELSE 'reclaimed' END);
   event_id:=candidate.event_id;
   generation:=next_gen;
   lease_token:=next_token;
   RETURN NEXT;
  END IF;
 END LOOP;
END
$fn$;
ALTER FUNCTION saas_rls_private.claim_committed_local_audit(INTEGER,INTEGER,BIGINT)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.claim_committed_local_audit(INTEGER,INTEGER,BIGINT)
 FROM PUBLIC,saas_rls_reader,saas_ci_runner;
GRANT EXECUTE ON FUNCTION
 saas_rls_private.claim_committed_local_audit(INTEGER,INTEGER,BIGINT)
 TO saas_audit_reconciler;

-- "ACK" means this worker durably observed the committed PostgreSQL Allow
-- audit event. It NEVER means remote transport delivery. Once reconciled,
-- a row is terminal. Stale/expired/wrong token or generation -> FALSE.
CREATE OR REPLACE FUNCTION saas_rls_private.mark_local_audit_reconciled(
 expected_event BIGINT,expected_generation BIGINT,expected_token UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $fn$
DECLARE changed INTEGER:=0;
BEGIN
 IF expected_event IS NULL OR expected_event<=0 OR
    expected_generation IS NULL OR expected_generation<=0 OR
    expected_token IS NULL THEN RETURN FALSE; END IF;
 UPDATE saas_rls_private.local_audit_reconciliation_state s
 SET status='reconciled_local',lease_token=NULL,lease_until=NULL,
     reconciled_at=clock_timestamp()
 WHERE s.event_id=expected_event AND s.generation=expected_generation
   AND s.lease_token=expected_token AND s.status='leased'
   AND s.lease_until>clock_timestamp();
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RETURN FALSE; END IF;
 INSERT INTO saas_rls_private.local_audit_reconciliation_history
  (event_id,generation,action)
 VALUES (expected_event,expected_generation,'reconciled_local');
 RETURN TRUE;
END
$fn$;
ALTER FUNCTION saas_rls_private.mark_local_audit_reconciled(BIGINT,BIGINT,UUID)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.mark_local_audit_reconciled(BIGINT,BIGINT,UUID)
 FROM PUBLIC,saas_rls_reader,saas_ci_runner;
GRANT EXECUTE ON FUNCTION
 saas_rls_private.mark_local_audit_reconciled(BIGINT,BIGINT,UUID)
 TO saas_audit_reconciler;

DO $assert$
BEGIN
 IF has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
    OR has_schema_privilege('saas_ci_runner','saas_rls_private','USAGE')
    OR has_table_privilege('saas_rls_reader',
       'saas_rls_private.local_audit_reconciliation_state','SELECT')
    OR has_table_privilege('saas_ci_runner',
       'saas_rls_private.local_audit_reconciliation_history','INSERT')
    OR has_table_privilege('saas_audit_reconciler',
       'saas_rls_private.local_publication_audit_outbox','SELECT')
    OR has_table_privilege('saas_audit_reconciler',
       'saas_rls_private.local_audit_reconciliation_state','UPDATE')
    OR has_function_privilege('saas_rls_reader',
       'saas_rls_private.claim_committed_local_audit(integer,integer,bigint)','EXECUTE')
    OR has_function_privilege('saas_ci_runner',
       'saas_rls_private.mark_local_audit_reconciled(bigint,bigint,uuid)','EXECUTE')
    OR NOT has_function_privilege('saas_audit_reconciler',
       'saas_rls_private.mark_local_audit_reconciled(bigint,bigint,uuid)','EXECUTE')
    OR NOT has_function_privilege('saas_audit_reconciler',
       'saas_rls_private.claim_committed_local_audit(integer,integer,bigint)','EXECUTE')
 THEN RAISE EXCEPTION 'Local audit reconciliation capability exposed'; END IF;
END
$assert$;
COMMIT;
\echo 'PASS: guarded PG16 committed-only audit reconciliation with fenced local ACK'
