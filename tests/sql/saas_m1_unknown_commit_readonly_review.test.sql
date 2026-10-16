\set ON_ERROR_STOP on
-- M1f: compare actual signed project+audit local evidence, never retry.
-- PostgreSQL16 disposable CI only, replay-safe, no operator write access.
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
     OR current_user <> 'postgres'
     OR to_regprocedure(
        'saas_m1_review.inspect_unknown_project_commit(text,text,text,bigint,text)') IS NULL
     OR to_regclass('saas_m1_private.project_write_audit_outbox') IS NULL
  THEN
    RAISE EXCEPTION 'M1f acceptance is restricted to disposable PostgreSQL16';
  END IF;
END
$guard$;

SELECT saas_rls_test.assert_true(
  (SELECT count(*)=1 FROM saas_m1_private.projects
   WHERE tenant_id='demo-north' AND project_id='m1b-lost-ack')
  AND (SELECT count(*)=1 FROM saas_m1_private.project_write_audit_outbox
   WHERE tenant_id='demo-north' AND project_id='m1b-lost-ack')
  AND NOT EXISTS (SELECT 1 FROM saas_m1_private.projects
    WHERE tenant_id='demo-north' AND project_id='m1e-physical-loss')
  AND NOT EXISTS (SELECT 1 FROM saas_m1_private.project_write_audit_outbox
    WHERE tenant_id='demo-north' AND project_id='m1e-physical-loss'),
  'Real native PG driver injected both committed-lost-ACK and pre-COMMIT physical loss'
);

-- READ COMMITTED READ ONLY and NOLOGIN reviewer role are mandatory;
-- its function owner can only SELECT with explicit FORCE RLS policies.
BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY;
SET LOCAL ROLE saas_m1_review_operator;
SELECT evidence_code AS lost_ack_evidence,
       local_audit_event AS lost_ack_event,
       observed_project_version AS lost_ack_version
  FROM saas_m1_review.inspect_unknown_project_commit(
    'demo-north','m1b-lost-ack','create',1,'actor-north') \gset
SELECT evidence_code AS terminated_evidence
  FROM saas_m1_review.inspect_unknown_project_commit(
    'demo-north','m1e-physical-loss','create',1,'actor-north') \gset
SELECT evidence_code AS cancelled_evidence
  FROM saas_m1_review.inspect_unknown_project_commit(
    'demo-north','m1e-aborted','create',1,'actor-north') \gset
SELECT evidence_code AS spoof_actor_evidence
  FROM saas_m1_review.inspect_unknown_project_commit(
    'demo-north','m1b-lost-ack','create',1,'actor-elsewhere') \gset
SELECT evidence_code AS wrong_operation_evidence
  FROM saas_m1_review.inspect_unknown_project_commit(
    'demo-north','m1b-lost-ack','rename',1,'actor-north') \gset
SELECT evidence_code AS missing_version_evidence
  FROM saas_m1_review.inspect_unknown_project_commit(
    'demo-north','m1b-lost-ack','rename',2,'actor-north') \gset
SELECT evidence_code AS other_tenant_evidence
  FROM saas_m1_review.inspect_unknown_project_commit(
    'demo-orbit','m1b-lost-ack','create',1,'actor-north') \gset
-- The project was renamed and disabled after v1: immutable earlier
-- events still match, provided the complete 1..current-version audit exists.
SELECT evidence_code AS earlier_create_evidence,
       observed_project_version AS earlier_current_version
  FROM saas_m1_review.inspect_unknown_project_commit(
    'demo-north','m1b-first','create',1,'actor-north') \gset
SELECT evidence_code AS earlier_rename_evidence
  FROM saas_m1_review.inspect_unknown_project_commit(
    'demo-north','m1b-first','rename',2,'actor-north') \gset
SELECT evidence_code AS final_disable_evidence
  FROM saas_m1_review.inspect_unknown_project_commit(
    'demo-north','m1b-first','disable',3,'actor-north') \gset
RESET ROLE;
COMMIT;

SELECT saas_rls_test.assert_true(
  :'lost_ack_evidence'='LOCAL_PAIR_OBSERVED'
  AND (:'lost_ack_event')::BIGINT>0
  AND (:'lost_ack_version')::BIGINT=1
  AND :'terminated_evidence'='NO_LOCAL_EVIDENCE'
  AND :'cancelled_evidence'='NO_LOCAL_EVIDENCE'
  AND :'spoof_actor_evidence'='INCONSISTENT_STOP'
  AND :'wrong_operation_evidence'='INCONSISTENT_STOP'
  AND :'missing_version_evidence'='INCONSISTENT_STOP'
  AND :'other_tenant_evidence'='NO_LOCAL_EVIDENCE'
  AND :'earlier_create_evidence'='LOCAL_PAIR_OBSERVED'
  AND (:'earlier_current_version')::BIGINT=3
  AND :'earlier_rename_evidence'='LOCAL_PAIR_OBSERVED'
  AND :'final_disable_evidence'='LOCAL_PAIR_OBSERVED',
  'M1f only local matching pair, inconclusive absence, or inconsistent STOP; no inferred retry'
);

-- A separate ordinary READ WRITE transaction must not masquerade as a
-- supervised review, even when using an otherwise privileged account.
DO $deny_write$
DECLARE denied BOOLEAN:=FALSE;
BEGIN
  BEGIN
    PERFORM * FROM saas_m1_review.inspect_unknown_project_commit(
       'demo-north','m1b-lost-ack','create',1,'actor-north');
  EXCEPTION WHEN raise_exception THEN
    denied:=SQLERRM='M1f inspection requires explicit READ COMMITTED READ ONLY transaction';
  END;
  IF NOT denied THEN
    RAISE EXCEPTION 'M1f review accepted a read-write transaction';
  END IF;
END
$deny_write$;

-- No function, read-table, journal, signing-key or membership grants reach
-- regular M1 writer/CI runner. The reviewer cannot directly SELECT data.
SELECT saas_rls_test.assert_true(
  NOT has_schema_privilege('saas_ci_runner','saas_m1_review','USAGE')
  AND NOT has_schema_privilege('saas_m1_project_executor','saas_m1_review','USAGE')
  AND NOT has_function_privilege('saas_ci_runner',
       'saas_m1_review.inspect_unknown_project_commit(text,text,text,bigint,text)','EXECUTE')
  AND NOT has_function_privilege('saas_m1_project_executor',
       'saas_m1_review.inspect_unknown_project_commit(text,text,text,bigint,text)','EXECUTE')
  AND NOT has_table_privilege('saas_m1_review_operator',
       'saas_m1_private.projects','SELECT')
  AND NOT has_table_privilege('saas_m1_review_operator',
       'saas_m1_private.project_write_audit_outbox','SELECT')
  AND NOT has_table_privilege('saas_m1_review_owner',
       'saas_m1_private.projects','UPDATE')
  AND NOT has_table_privilege('saas_m1_review_owner',
       'saas_m1_private.project_write_audit_outbox','DELETE')
  AND NOT has_table_privilege('saas_m1_review_owner',
       'saas_rls_private.scope_signers','SELECT')
  AND NOT pg_has_role('saas_ci_runner','saas_m1_review_operator','MEMBER'),
  'M1f operator can only invoke read-only projection, no writer/signer/tenant grants'
);

-- Idempotent migration replay must not add/change project/outbox rows.
SET saas.staging_only='true';
\ir ../../staging/saas-rls/023_m1_unknown_commit_readonly_review_pilot.sql
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=1 FROM saas_m1_private.project_write_audit_outbox
   WHERE tenant_id='demo-north' AND project_id='m1b-lost-ack'
     AND operation='create' AND project_version=1)
  AND (SELECT count(*)=3 FROM saas_m1_private.project_write_audit_outbox
   WHERE tenant_id='demo-north' AND project_id='m1b-first')
  AND (SELECT status='disabled' AND version=3
   FROM saas_m1_private.projects
   WHERE tenant_id='demo-north' AND project_id='m1b-first'),
  'M1f idempotent reviewer replay cannot mutate project or audit evidence'
);

\echo 'PASS M1f: NOLOGIN read-only operator inspection; matching committed pair vs absent/inconsistent STOP, no retry or recovery'
