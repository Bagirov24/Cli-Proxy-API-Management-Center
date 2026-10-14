\set ON_ERROR_STOP on
-- M1g: server-minted UUIDv4 is bound to M1c/M1d audited COMMIT,
-- deterministic uniqueness and read-only evidence; disposable PG16 only.
DO $guard$
BEGIN
  IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
    OR to_regclass('saas_m1_private.project_attempt_bindings') IS NULL
    OR to_regprocedure('saas_m1_review.inspect_project_attempt(text,text,uuid,text,bigint,text)') IS NULL
  THEN RAISE EXCEPTION 'M1g acceptance denied outside disposable PostgreSQL16'; END IF;
END
$guard$;

-- The separate native Bun.SQL process used pinned RS256 -> trusted actor
-- and generated UUIDv4 per approved command, independent of JWT fields.
-- All project/audit/binding rows COMMIT together. The later failed CAS,
-- missing attempt stamp and reuse of a committed ID have no ghost rows.
SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*)=3 FROM saas_m1_private.project_write_audit_outbox a
   WHERE a.tenant_id='demo-north' AND a.project_id='m1g-first')
  AND (SELECT COUNT(*)=3
       FROM saas_m1_private.project_attempt_bindings b
       JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
       WHERE a.tenant_id='demo-north' AND a.project_id='m1g-first')
  AND (SELECT ARRAY_AGG(a.operation ORDER BY a.project_version)
       =ARRAY['create','rename','disable']::TEXT[]
       FROM saas_m1_private.project_attempt_bindings b
       JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
       WHERE a.tenant_id='demo-north' AND a.project_id='m1g-first')
  AND (SELECT ARRAY_AGG(a.project_version ORDER BY a.project_version)
       =ARRAY[1,2,3]::BIGINT[]
       FROM saas_m1_private.project_attempt_bindings b
       JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
       WHERE a.tenant_id='demo-north' AND a.project_id='m1g-first')
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.project_attempt_bindings b
       JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
       WHERE a.tenant_id='demo-north' AND a.project_id='m1g-lost-ack'
         AND a.project_version=1 AND a.operation='create')
  AND NOT EXISTS (
    SELECT 1 FROM saas_m1_private.projects
    WHERE project_id IN ('m1g-reused-attempt','m1g-no-stamp'))
  AND NOT EXISTS (
    SELECT 1 FROM saas_m1_private.project_write_audit_outbox
    WHERE project_id IN ('m1g-reused-attempt','m1g-no-stamp'))
  AND (SELECT status='disabled' AND version=3
       FROM saas_m1_private.projects
       WHERE tenant_id='demo-north' AND project_id='m1g-first'),
  'M1g 3 valid bound writes and 1 lost ACK; UUID reuse/unstamped writer have 0 project/0 audit'
);

SELECT saas_rls_test.assert_true(
  NOT EXISTS (
    SELECT 1 FROM saas_m1_private.project_attempt_bindings b
    LEFT JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
    WHERE a.event_id IS NULL
  )
  AND (SELECT COUNT(*)=COUNT(DISTINCT attempt_id)
       FROM saas_m1_private.project_attempt_bindings)
  AND NOT EXISTS (
    SELECT 1 FROM saas_m1_private.project_attempt_bindings b
    JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
    WHERE a.pg_txid !~ '^[0-9]{1,19}$' OR a.actor_id<>'actor-north'
  ),
  'Each attempt binds exactly one existing signed audit event and valid actor'
);

-- The one-time UUID is stored server side; fetch it only in privileged
-- synthetic CI fixture, then exercise the NOLOGIN reviewer capability.
SELECT b.attempt_id::TEXT AS committed_attempt FROM
 saas_m1_private.project_attempt_bindings b
 JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
 WHERE a.tenant_id='demo-north' AND a.project_id='m1g-lost-ack'
   AND a.project_version=1 AND a.operation='create' \gset
SELECT b.attempt_id::TEXT AS earlier_attempt FROM
 saas_m1_private.project_attempt_bindings b
 JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
 WHERE a.tenant_id='demo-north' AND a.project_id='m1g-first'
   AND a.project_version=1 AND a.operation='create' \gset
SELECT b.attempt_id::TEXT AS final_attempt FROM
 saas_m1_private.project_attempt_bindings b
 JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
 WHERE a.tenant_id='demo-north' AND a.project_id='m1g-first'
   AND a.project_version=3 AND a.operation='disable' \gset

BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY;
SET LOCAL ROLE saas_m1_review_operator;
SELECT evidence_code AS committed_evidence,
       local_audit_event AS committed_event,
       observed_project_version AS committed_version
  FROM saas_m1_review.inspect_project_attempt(
    'demo-north','m1g-lost-ack',(:'committed_attempt')::UUID,
    'create',1,'actor-north') \gset
SELECT evidence_code AS earlier_evidence,
       observed_project_version AS earlier_version
  FROM saas_m1_review.inspect_project_attempt(
    'demo-north','m1g-first',(:'earlier_attempt')::UUID,
    'create',1,'actor-north') \gset
SELECT evidence_code AS final_evidence
  FROM saas_m1_review.inspect_project_attempt(
    'demo-north','m1g-first',(:'final_attempt')::UUID,
    'disable',3,'actor-north') \gset
SELECT evidence_code AS wrong_actor
  FROM saas_m1_review.inspect_project_attempt(
    'demo-north','m1g-lost-ack',(:'committed_attempt')::UUID,
    'create',1,'actor-orbit') \gset
SELECT evidence_code AS wrong_operation
  FROM saas_m1_review.inspect_project_attempt(
    'demo-north','m1g-lost-ack',(:'committed_attempt')::UUID,
    'rename',1,'actor-north') \gset
SELECT evidence_code AS wrong_version
  FROM saas_m1_review.inspect_project_attempt(
    'demo-north','m1g-lost-ack',(:'committed_attempt')::UUID,
    'create',2,'actor-north') \gset
SELECT evidence_code AS wrong_project
  FROM saas_m1_review.inspect_project_attempt(
    'demo-north','m1g-first',(:'committed_attempt')::UUID,
    'create',1,'actor-north') \gset
SELECT evidence_code AS unknown_existing
  FROM saas_m1_review.inspect_project_attempt(
    'demo-north','m1g-lost-ack',
    '00000000-0000-4000-8000-000000000001'::UUID,
    'create',1,'actor-north') \gset
SELECT evidence_code AS missing_evidence
  FROM saas_m1_review.inspect_project_attempt(
    'demo-north','m1g-never-attempted',
    '00000000-0000-4000-8000-000000000002'::UUID,
    'create',1,'actor-north') \gset
SELECT evidence_code AS legacy_unlinked
  FROM saas_m1_review.inspect_project_attempt(
    'demo-north','m1b-first',
    '00000000-0000-4000-8000-000000000003'::UUID,
    'create',1,'actor-north') \gset
RESET ROLE;
COMMIT;

SELECT saas_rls_test.assert_true(
  :'committed_evidence'='LOCAL_ATTEMPT_PAIR_OBSERVED'
  AND (:'committed_event')::BIGINT>0
  AND (:'committed_version')::BIGINT=1
  AND :'earlier_evidence'='LOCAL_ATTEMPT_PAIR_OBSERVED'
  AND (:'earlier_version')::BIGINT=3
  AND :'final_evidence'='LOCAL_ATTEMPT_PAIR_OBSERVED'
  AND :'wrong_actor'='INCONSISTENT_STOP'
  AND :'wrong_operation'='INCONSISTENT_STOP'
  AND :'wrong_version'='INCONSISTENT_STOP'
  AND :'wrong_project'='INCONSISTENT_STOP'
  AND :'unknown_existing'='INCONSISTENT_STOP'
  AND :'legacy_unlinked'='INCONSISTENT_STOP'
  AND :'missing_evidence'='NO_LOCAL_ATTEMPT_EVIDENCE',
  'UUID-linked same-DB evidence is bounded, mismatch STOP, missing is INCONCLUSIVE'
);

-- Normal READ WRITE and REPEATABLE READ contexts may never query this
-- privileged evidence. A reviewer has EXECUTE only, no table reads.
DO $deny_write$
DECLARE denied BOOLEAN:=FALSE;
BEGIN
  BEGIN
    PERFORM * FROM saas_m1_review.inspect_project_attempt(
      'demo-north','m1g-first',(:'earlier_attempt')::UUID,
      'create',1,'actor-north');
  EXCEPTION WHEN raise_exception THEN
    denied:=SQLERRM='M1g inspection requires READ COMMITTED READ ONLY';
  END;
  IF NOT denied THEN RAISE EXCEPTION 'M1g accepted READ WRITE evidence query'; END IF;
END
$deny_write$;

BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
DO $deny_repeatable$
DECLARE denied BOOLEAN:=FALSE;
BEGIN
  BEGIN
    PERFORM * FROM saas_m1_review.inspect_project_attempt(
      'demo-north','m1g-first',(:'earlier_attempt')::UUID,
      'create',1,'actor-north');
  EXCEPTION WHEN raise_exception THEN
    denied:=SQLERRM='M1g inspection requires READ COMMITTED READ ONLY';
  END;
  IF NOT denied THEN RAISE EXCEPTION 'M1g accepted stale snapshot'; END IF;
END
$deny_repeatable$;
ROLLBACK;

DO $append_only$
DECLARE update_denied BOOLEAN:=FALSE;
DECLARE delete_denied BOOLEAN:=FALSE;
BEGIN
  BEGIN
    UPDATE saas_m1_private.project_attempt_bindings
      SET attempt_id='00000000-0000-4000-8000-000000000004'::UUID
    WHERE attempt_id=(:'committed_attempt')::UUID;
  EXCEPTION WHEN raise_exception THEN update_denied:=TRUE; END;
  BEGIN
    DELETE FROM saas_m1_private.project_attempt_bindings
    WHERE attempt_id=(:'committed_attempt')::UUID;
  EXCEPTION WHEN raise_exception THEN delete_denied:=TRUE; END;
  IF NOT update_denied OR NOT delete_denied THEN
    RAISE EXCEPTION 'M1g binding accepted forbidden UPDATE/DELETE';
  END IF;
END
$append_only$;

SELECT saas_rls_test.assert_true(
  NOT has_schema_privilege('saas_ci_runner','saas_m1_private','USAGE')
  AND NOT has_function_privilege('saas_ci_runner',
     'saas_m1_review.inspect_project_attempt(text,text,uuid,text,bigint,text)','EXECUTE')
  AND NOT has_function_privilege('saas_m1_project_executor',
     'saas_m1_review.inspect_project_attempt(text,text,uuid,text,bigint,text)','EXECUTE')
  AND NOT has_table_privilege('saas_m1_review_operator',
     'saas_m1_private.project_attempt_bindings','SELECT')
  AND NOT has_table_privilege('saas_m1_review_owner',
     'saas_m1_private.project_attempt_bindings','UPDATE')
  AND NOT has_table_privilege('saas_m1_attempt_owner',
     'saas_rls_private.scope_signers','SELECT')
  AND NOT has_table_privilege('saas_m1_attempt_owner',
     'saas_m1_private.projects','INSERT')
  AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
       WHERE oid='saas_m1_private.project_attempt_bindings'::regclass),
  'M1g NOLOGIN roles remain least-privileged: reviewer reads projected evidence only'
);

-- Re-install SQL024 after successful commits: no TRUNCATE, backfill,
-- deletion or in-place audit trigger replacement is permitted.
SET saas.staging_only='true';
\ir ../../staging/saas-rls/024_m1_attempt_bound_project_audit_pilot.sql
SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*)=4 FROM saas_m1_private.project_attempt_bindings)
  AND (SELECT status='disabled' AND version=3 FROM saas_m1_private.projects
       WHERE tenant_id='demo-north' AND project_id='m1g-first')
  AND (SELECT COUNT(*)=3 FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id='m1g-first')
  AND EXISTS (SELECT 1 FROM pg_trigger
       WHERE tgrelid='saas_m1_private.projects'::regclass
       AND tgname='m1_project_atomic_audit'
       AND tgfoid='saas_m1_private.append_project_write_audit_fenced()'::regprocedure)
  AND EXISTS (SELECT 1 FROM pg_trigger
       WHERE tgrelid='saas_m1_private.projects'::regclass
       AND tgname='m1_project_attempt_binding'
       AND tgfoid='saas_m1_private.bind_project_attempt_to_audit()'::regprocedure),
  'M1g replay preserves all 4 immutable attempt bindings and M1d signed fence'
);
\echo 'PASS M1g: server UUIDv4 is transaction-bound to signed project+audit; unique replay denial, reviewer STOP/absence, no retry or production'