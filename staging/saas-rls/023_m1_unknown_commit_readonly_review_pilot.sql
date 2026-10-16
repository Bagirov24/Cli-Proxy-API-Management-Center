-- M1f: read-only, operator-gated LOCAL evidence for UNKNOWN project COMMIT.
-- Ephemeral PostgreSQL16 GitHub CI ONLY; not recovery, a signer or production.
-- No write/claim/lease/idempotency/retry/repair actions are exposed.
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
     OR current_user <> 'postgres'
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR to_regprocedure('saas_m1_private.append_project_write_audit_fenced()') IS NULL
     OR to_regclass('saas_m1_private.projects') IS NULL
     OR to_regclass('saas_m1_private.project_write_audit_outbox') IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM pg_roles WHERE rolname='saas_m1_project_executor'
       AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
     OR NOT EXISTS (
       SELECT 1 FROM pg_class WHERE
       oid='saas_m1_private.projects'::regclass AND relrowsecurity AND relforcerowsecurity)
     OR NOT EXISTS (
       SELECT 1 FROM pg_class WHERE
       oid='saas_m1_private.project_write_audit_outbox'::regclass
       AND relrowsecurity AND relforcerowsecurity)
  THEN
    RAISE EXCEPTION 'M1f review installation denied outside signed disposable PG16';
  END IF;
END
$guard$;

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_m1_review_owner') THEN
    CREATE ROLE saas_m1_review_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_m1_review_operator') THEN
    CREATE ROLE saas_m1_review_operator NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
  END IF;
END
$roles$;
ALTER ROLE saas_m1_review_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_m1_review_operator NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;

-- A separate NOLOGIN function owner has only SELECT, subject to FORCE RLS.
-- The NOLOGIN operator can ONLY invoke one sanitized function; the normal
-- M1 executor/runner/reader cannot use either schema or function.
CREATE SCHEMA IF NOT EXISTS saas_m1_review;
REVOKE ALL ON SCHEMA saas_m1_review
  FROM PUBLIC,saas_ci_runner,saas_rls_reader,saas_m1_project_executor;
GRANT USAGE ON SCHEMA saas_m1_review TO
  saas_m1_review_owner,saas_m1_review_operator;
GRANT USAGE ON SCHEMA saas_m1_private TO saas_m1_review_owner;
GRANT SELECT ON saas_m1_private.projects TO saas_m1_review_owner;
GRANT SELECT ON saas_m1_private.project_write_audit_outbox
  TO saas_m1_review_owner;

DROP POLICY IF EXISTS m1_operator_evidence_project_select
  ON saas_m1_private.projects;
CREATE POLICY m1_operator_evidence_project_select
  ON saas_m1_private.projects
  FOR SELECT TO saas_m1_review_owner USING (true);
DROP POLICY IF EXISTS m1_operator_evidence_audit_select
  ON saas_m1_private.project_write_audit_outbox;
CREATE POLICY m1_operator_evidence_audit_select
  ON saas_m1_private.project_write_audit_outbox
  FOR SELECT TO saas_m1_review_owner USING (true);

-- This is observation, NEVER resolution of the original request. There is
-- no immutable per-attempt ID in M1a/M1c, and an admin could later alter
-- this whole PostgreSQL trust domain. Even a matching pair is not proof
-- that *the uncertain original attempt* caused these rows.
CREATE OR REPLACE FUNCTION saas_m1_review.inspect_unknown_project_commit(
  target_tenant TEXT, target_project TEXT, claimed_operation TEXT,
  claimed_version BIGINT, claimed_actor TEXT
) RETURNS TABLE (
  evidence_code TEXT,
  local_audit_event BIGINT,
  observed_project_version BIGINT
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $fn$
DECLARE
  project_count BIGINT;
  current_version BIGINT;
  audit_total BIGINT;
  audit_min_version BIGINT;
  audit_max_version BIGINT;
  exact_count BIGINT;
  exact_event BIGINT;
  exact_operation TEXT;
  exact_actor TEXT;
BEGIN
  IF current_setting('transaction_isolation') <> 'read committed'
     OR current_setting('transaction_read_only') <> 'on' THEN
    RAISE EXCEPTION 'M1f inspection requires explicit READ COMMITTED READ ONLY transaction';
  END IF;
  IF target_tenant IS NULL OR target_tenant !~ '^[A-Za-z0-9_-]{1,64}$'
     OR target_project IS NULL OR target_project !~ '^[A-Za-z0-9_-]{1,64}$'
     OR claimed_actor IS NULL OR claimed_actor !~ '^[A-Za-z0-9_-]{1,128}$'
     OR claimed_operation IS NULL
     OR claimed_operation NOT IN ('create','rename','disable')
     OR claimed_version IS NULL OR claimed_version<1
  THEN
    RAISE EXCEPTION 'M1f inspection arguments denied';
  END IF;

  -- A STABLE function reads a single statement snapshot. It CANNOT see
  -- concurrent uncommitted writes. Absence is always inconclusive.
  SELECT COUNT(*),MAX(p.version) INTO project_count,current_version
    FROM saas_m1_private.projects p
    WHERE p.tenant_id=target_tenant AND p.project_id=target_project;
  SELECT COUNT(*),MIN(a.project_version),MAX(a.project_version)
    INTO audit_total,audit_min_version,audit_max_version
    FROM saas_m1_private.project_write_audit_outbox a
    WHERE a.tenant_id=target_tenant AND a.project_id=target_project;
  SELECT COUNT(*),MAX(a.event_id),MAX(a.operation),MAX(a.actor_id)
    INTO exact_count,exact_event,exact_operation,exact_actor
    FROM saas_m1_private.project_write_audit_outbox a
    WHERE a.tenant_id=target_tenant AND a.project_id=target_project
      AND a.project_version=claimed_version;

  IF project_count=0 AND audit_total=0 THEN
    RETURN QUERY SELECT 'NO_LOCAL_EVIDENCE'::TEXT,NULL::BIGINT,NULL::BIGINT;
  ELSIF project_count=1 AND exact_count=1
    AND exact_operation=claimed_operation AND exact_actor=claimed_actor
    AND current_version>=claimed_version
    -- If any audit row is missing from the 1..current-version chain,
    -- a single matching row alone must NOT produce a positive observation.
    AND audit_total=current_version
    AND audit_min_version=1 AND audit_max_version=current_version
  THEN
    RETURN QUERY SELECT 'LOCAL_PAIR_OBSERVED'::TEXT,
                        exact_event,current_version;
  ELSE
    RETURN QUERY SELECT 'INCONSISTENT_STOP'::TEXT,
                        NULL::BIGINT,NULL::BIGINT;
  END IF;
END
$fn$;
ALTER FUNCTION saas_m1_review.inspect_unknown_project_commit(TEXT,TEXT,TEXT,BIGINT,TEXT)
  OWNER TO saas_m1_review_owner;
REVOKE ALL ON FUNCTION
  saas_m1_review.inspect_unknown_project_commit(TEXT,TEXT,TEXT,BIGINT,TEXT)
  FROM PUBLIC,saas_ci_runner,saas_rls_reader,
       saas_m1_project_executor,saas_m1_project_owner,saas_m1_audit_owner;
GRANT EXECUTE ON FUNCTION
  saas_m1_review.inspect_unknown_project_commit(TEXT,TEXT,TEXT,BIGINT,TEXT)
  TO saas_m1_review_operator;

DO $assert$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_m1_review_owner'
       AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit)
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_m1_review_operator'
       AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit)
     OR pg_has_role('saas_m1_review_operator','saas_m1_review_owner','MEMBER')
     OR pg_has_role('saas_ci_runner','saas_m1_review_owner','MEMBER')
     OR pg_has_role('saas_ci_runner','saas_m1_review_operator','MEMBER')
     OR NOT has_function_privilege('saas_m1_review_operator',
       'saas_m1_review.inspect_unknown_project_commit(text,text,text,bigint,text)','EXECUTE')
     OR has_function_privilege('saas_ci_runner',
       'saas_m1_review.inspect_unknown_project_commit(text,text,text,bigint,text)','EXECUTE')
     OR has_function_privilege('saas_m1_project_executor',
       'saas_m1_review.inspect_unknown_project_commit(text,text,text,bigint,text)','EXECUTE')
     OR has_schema_privilege('saas_ci_runner','saas_m1_review','USAGE')
     OR has_schema_privilege('saas_m1_project_executor','saas_m1_review','USAGE')
     OR has_table_privilege('saas_m1_review_operator','saas_m1_private.projects','SELECT')
     OR has_table_privilege('saas_m1_review_operator',
          'saas_m1_private.project_write_audit_outbox','SELECT')
     OR has_table_privilege('saas_m1_review_owner',
          'saas_m1_private.projects','INSERT')
     OR has_table_privilege('saas_m1_review_owner',
          'saas_m1_private.project_write_audit_outbox','UPDATE')
     OR has_table_privilege('saas_m1_review_owner',
          'saas_rls_private.scope_signers','SELECT')
     OR NOT (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
             WHERE oid='saas_m1_private.projects'::regclass)
     OR NOT (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
             WHERE oid='saas_m1_private.project_write_audit_outbox'::regclass)
  THEN
    RAISE EXCEPTION 'M1f operator evidence capability violates least privilege';
  END IF;
END
$assert$;
COMMIT;
\echo 'PASS M1f: guarded READ ONLY local project+audit evidence, operator NOLOGIN, no retry/resolution capabilities'