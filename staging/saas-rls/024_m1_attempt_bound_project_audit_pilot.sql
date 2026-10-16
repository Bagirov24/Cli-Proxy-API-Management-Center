-- M1g: same-COMMIT binding of ONE server-generated CI attempt UUID to
-- ONE existing mandatory M1c/M1d project audit event. Disposable PG16 ONLY.
-- No retry, idempotency claim, durable external intent, signer or release.
BEGIN;
DO $guard$
BEGIN
  IF current_database()<>'saas_ephemeral_test'
    OR current_user<>'postgres'
    OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
    OR to_regprocedure('saas_m1_private.append_project_write_audit_fenced()') IS NULL
    OR to_regprocedure('saas_m1_review.inspect_unknown_project_commit(text,text,text,bigint,text)') IS NULL
    OR to_regclass('saas_m1_private.project_write_audit_outbox') IS NULL
    OR to_regclass('saas_m1_private.projects') IS NULL
    OR NOT EXISTS (SELECT 1 FROM pg_roles
      WHERE rolname='saas_m1_review_owner'
        AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
    OR NOT EXISTS (SELECT 1 FROM pg_roles
      WHERE rolname='saas_m1_project_executor'
        AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
  THEN
    RAISE EXCEPTION 'M1g attempt binding refused outside disposable signed PG16';
  END IF;
END
$guard$;

DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_m1_attempt_owner') THEN
    CREATE ROLE saas_m1_attempt_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
  END IF;
END
$role$;
ALTER ROLE saas_m1_attempt_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA saas_m1_private TO saas_m1_attempt_owner;

-- No payload, token, project name or caller-supplied actor is persisted.
-- UUID uniqueness blocks reuse AFTER a successful DB COMMIT, even against
-- another project/tenant. It does NOT prove uncommitted IDs were attempted
-- or settle a partially completed COMMIT by itself.
CREATE TABLE IF NOT EXISTS saas_m1_private.project_attempt_bindings (
  attempt_id UUID PRIMARY KEY,
  event_id BIGINT NOT NULL UNIQUE REFERENCES
    saas_m1_private.project_write_audit_outbox(event_id),
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE saas_m1_private.project_attempt_bindings OWNER TO saas_m1_attempt_owner;
REVOKE ALL ON saas_m1_private.project_attempt_bindings FROM
  PUBLIC,saas_ci_runner,saas_rls_reader,saas_m1_project_executor,
  saas_m1_project_owner,saas_m1_audit_owner,saas_m1_review_operator;
ALTER TABLE saas_m1_private.project_attempt_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_m1_private.project_attempt_bindings FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS m1_attempt_owner_insert
  ON saas_m1_private.project_attempt_bindings;
CREATE POLICY m1_attempt_owner_insert ON saas_m1_private.project_attempt_bindings
  FOR INSERT TO saas_m1_attempt_owner WITH CHECK (true);
DROP POLICY IF EXISTS m1_attempt_reviewer_select
  ON saas_m1_private.project_attempt_bindings;
CREATE POLICY m1_attempt_reviewer_select ON saas_m1_private.project_attempt_bindings
  FOR SELECT TO saas_m1_review_owner USING (true);
GRANT SELECT ON saas_m1_private.project_attempt_bindings TO saas_m1_review_owner;

-- Trigger owner may only SELECT the row the existing M1d signed audit
-- trigger already inserted, with FORCE RLS, then append its own binding.
-- This is not an alternative writer, role, signer or authorization source.
GRANT SELECT ON saas_m1_private.project_write_audit_outbox
  TO saas_m1_attempt_owner;
DROP POLICY IF EXISTS m1_attempt_owner_audit_select
  ON saas_m1_private.project_write_audit_outbox;
CREATE POLICY m1_attempt_owner_audit_select
  ON saas_m1_private.project_write_audit_outbox
  FOR SELECT TO saas_m1_attempt_owner USING (true);

DROP TRIGGER IF EXISTS m1_attempt_binding_append_only
  ON saas_m1_private.project_attempt_bindings;
CREATE TRIGGER m1_attempt_binding_append_only
  BEFORE UPDATE OR DELETE ON saas_m1_private.project_attempt_bindings
  FOR EACH ROW EXECUTE FUNCTION saas_m1_private.reject_project_audit_change();

CREATE OR REPLACE FUNCTION saas_m1_private.bind_project_attempt_to_audit()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $fn$
DECLARE
  raw_attempt TEXT := current_setting('saas.m1_attempt_id',true);
  signed_actor TEXT := current_setting('saas.scope_actor',true);
  event_match BIGINT;
  event_count BIGINT;
BEGIN
  -- The fixed, server-side CI adapter minted UUIDv4 before the attempted
  -- mutation and set it via SET LOCAL on the SAME signed transaction.
  -- PostgreSQL itself cannot attest the provenance of this custom GUC:
  -- therefore NO production authorization or retry derives from it.
  IF raw_attempt IS NULL
     OR raw_attempt !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR signed_actor IS NULL
     OR signed_actor !~ '^[A-Za-z0-9_-]{1,128}$' THEN
    RAISE EXCEPTION 'M1g missing server-stamped signed attempt context';
  END IF;

  -- Both triggers are AFTER ROW, alphabetically ordered by name:
  -- m1_project_atomic_audit MUST run before m1_project_attempt_binding.
  -- The mandatory first trigger has already verified the signed tenant
  -- epoch fence, current actor and RLS, and appended the local audit.
  SELECT COUNT(*),MAX(a.event_id) INTO event_count,event_match
  FROM saas_m1_private.project_write_audit_outbox a
  WHERE a.tenant_id=NEW.tenant_id
    AND a.project_id=NEW.project_id
    AND a.project_version=NEW.version
    AND a.actor_id=signed_actor
    AND a.pg_txid=txid_current()::TEXT
    AND a.operation=CASE
      WHEN TG_OP='INSERT' THEN 'create'
      WHEN NEW.status='disabled' THEN 'disable'
      ELSE 'rename' END;
  IF event_count<>1 OR event_match IS NULL THEN
    RAISE EXCEPTION 'M1g missing matching mandatory signed project audit';
  END IF;
  INSERT INTO saas_m1_private.project_attempt_bindings(attempt_id,event_id)
  VALUES(raw_attempt::UUID,event_match);
  RETURN NULL;
END
$fn$;
ALTER FUNCTION saas_m1_private.bind_project_attempt_to_audit()
  OWNER TO saas_m1_attempt_owner;
REVOKE ALL ON FUNCTION saas_m1_private.bind_project_attempt_to_audit()
  FROM PUBLIC,saas_ci_runner,saas_rls_reader,
       saas_m1_project_executor,saas_m1_project_owner,
       saas_m1_audit_owner,saas_m1_review_operator;
DROP TRIGGER IF EXISTS m1_project_attempt_binding
  ON saas_m1_private.projects;
CREATE TRIGGER m1_project_attempt_binding
  AFTER INSERT OR UPDATE ON saas_m1_private.projects
  FOR EACH ROW EXECUTE FUNCTION saas_m1_private.bind_project_attempt_to_audit();

-- Read-only operator evidence with exact per-attempt ID, never auto retry.
-- Reuses the existing M1f full-version-chain review; doesn't copy logic.
CREATE OR REPLACE FUNCTION saas_m1_review.inspect_project_attempt(
  target_tenant TEXT, target_project TEXT, target_attempt UUID,
  claimed_operation TEXT, claimed_version BIGINT, claimed_actor TEXT
) RETURNS TABLE(
  evidence_code TEXT,
  local_audit_event BIGINT,
  observed_project_version BIGINT
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $fn$
DECLARE
  found_event BIGINT;
  found_tenant TEXT;
  found_project TEXT;
  found_operation TEXT;
  found_actor TEXT;
  found_version BIGINT;
  prior_code TEXT;
  prior_event BIGINT;
  prior_version BIGINT;
  candidate_count BIGINT;
BEGIN
  IF current_setting('transaction_isolation') <> 'read committed'
     OR current_setting('transaction_read_only') <> 'on' THEN
    RAISE EXCEPTION 'M1g inspection requires READ COMMITTED READ ONLY';
  END IF;
  IF target_tenant IS NULL OR target_tenant !~ '^[A-Za-z0-9_-]{1,64}$'
     OR target_project IS NULL OR target_project !~ '^[A-Za-z0-9_-]{1,64}$'
     OR target_attempt IS NULL
     OR claimed_actor IS NULL OR claimed_actor !~ '^[A-Za-z0-9_-]{1,128}$'
     OR claimed_operation IS NULL
     OR claimed_operation NOT IN ('create','rename','disable')
     OR claimed_version IS NULL OR claimed_version<1 THEN
    RAISE EXCEPTION 'M1g invalid operator inspection input';
  END IF;
  SELECT b.event_id,a.tenant_id,a.project_id,a.operation,a.actor_id,a.project_version
   INTO found_event,found_tenant,found_project,
        found_operation,found_actor,found_version
  FROM saas_m1_private.project_attempt_bindings b
  JOIN saas_m1_private.project_write_audit_outbox a
    ON a.event_id=b.event_id
  WHERE b.attempt_id=target_attempt;

  IF found_event IS NULL THEN
    -- If the named project has locally visible prior state, we cannot
    -- claim the (possibly absent) requested attempt is the same state.
    SELECT COUNT(*) INTO candidate_count
    FROM saas_m1_private.project_write_audit_outbox a
    WHERE a.tenant_id=target_tenant AND a.project_id=target_project;
    IF candidate_count>0 OR EXISTS (
      SELECT 1 FROM saas_m1_private.projects p
      WHERE p.tenant_id=target_tenant AND p.project_id=target_project
    ) THEN
      RETURN QUERY SELECT 'INCONSISTENT_STOP'::TEXT,NULL::BIGINT,NULL::BIGINT;
    ELSE
      RETURN QUERY SELECT 'NO_LOCAL_ATTEMPT_EVIDENCE'::TEXT,NULL::BIGINT,NULL::BIGINT;
    END IF;
    RETURN;
  END IF;
  IF found_tenant IS DISTINCT FROM target_tenant
     OR found_project IS DISTINCT FROM target_project
     OR found_operation IS DISTINCT FROM claimed_operation
     OR found_version IS DISTINCT FROM claimed_version
     OR found_actor IS DISTINCT FROM claimed_actor THEN
    RETURN QUERY SELECT 'INCONSISTENT_STOP'::TEXT,NULL::BIGINT,NULL::BIGINT;
    RETURN;
  END IF;

  SELECT r.evidence_code,r.local_audit_event,r.observed_project_version
   INTO prior_code,prior_event,prior_version
  FROM saas_m1_review.inspect_unknown_project_commit(
    target_tenant,target_project,claimed_operation,claimed_version,claimed_actor
  ) r;
  IF prior_code='LOCAL_PAIR_OBSERVED' AND prior_event=found_event THEN
    RETURN QUERY SELECT 'LOCAL_ATTEMPT_PAIR_OBSERVED'::TEXT,found_event,prior_version;
  ELSE
    RETURN QUERY SELECT 'INCONSISTENT_STOP'::TEXT,NULL::BIGINT,NULL::BIGINT;
  END IF;
END
$fn$;
ALTER FUNCTION saas_m1_review.inspect_project_attempt(TEXT,TEXT,UUID,TEXT,BIGINT,TEXT)
  OWNER TO saas_m1_review_owner;
REVOKE ALL ON FUNCTION saas_m1_review.inspect_project_attempt(TEXT,TEXT,UUID,TEXT,BIGINT,TEXT)
  FROM PUBLIC,saas_ci_runner,saas_rls_reader,
       saas_m1_project_executor,saas_m1_project_owner,saas_m1_audit_owner;
GRANT EXECUTE ON FUNCTION
  saas_m1_review.inspect_project_attempt(TEXT,TEXT,UUID,TEXT,BIGINT,TEXT)
  TO saas_m1_review_operator;

DO $assert$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid='saas_m1_private.projects'::regclass
      AND tgname='m1_project_attempt_binding'
      AND tgfoid='saas_m1_private.bind_project_attempt_to_audit()'::regprocedure
      AND NOT tgisinternal)
    OR NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid='saas_m1_private.projects'::regclass
      AND tgname='m1_project_atomic_audit'
      AND tgfoid='saas_m1_private.append_project_write_audit_fenced()'::regprocedure
      AND NOT tgisinternal)
    OR NOT ('m1_project_atomic_audit' < 'm1_project_attempt_binding')
    OR NOT (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
       WHERE oid='saas_m1_private.project_attempt_bindings'::regclass)
    OR has_table_privilege('saas_ci_runner',
      'saas_m1_private.project_attempt_bindings','SELECT')
    OR has_table_privilege('saas_m1_project_executor',
      'saas_m1_private.project_attempt_bindings','INSERT')
    OR has_table_privilege('saas_m1_review_operator',
      'saas_m1_private.project_attempt_bindings','SELECT')
    OR has_table_privilege('saas_m1_attempt_owner',
      'saas_rls_private.scope_signers','SELECT')
    OR has_table_privilege('saas_m1_attempt_owner',
      'saas_m1_private.projects','UPDATE')
    OR has_function_privilege('saas_ci_runner',
      'saas_m1_review.inspect_project_attempt(text,text,uuid,text,bigint,text)','EXECUTE')
    OR has_function_privilege('saas_m1_project_executor',
      'saas_m1_review.inspect_project_attempt(text,text,uuid,text,bigint,text)','EXECUTE')
    OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_m1_attempt_owner'
       AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit)
  THEN
    RAISE EXCEPTION 'M1g attempt binding, audit or reviewer privileges unsafe';
  END IF;
END
$assert$;
COMMIT;
\echo 'PASS M1g: guarded server UUIDv4 to project/audit SAME COMMIT binding, read-only reviewer; no retry, release or external WORM'