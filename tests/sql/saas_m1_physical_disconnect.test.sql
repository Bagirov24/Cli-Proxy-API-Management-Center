\set ON_ERROR_STOP on
-- M1e: disposable PG16 physical backend termination and abort, while
-- signed M1c project/audit and M1b committed lost-ACK acceptance are intact.
-- This file must never be executed against production or Railway.
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
     OR current_user <> 'postgres'
     OR to_regclass('saas_m1_private.projects') IS NULL
     OR to_regclass('saas_m1_private.project_write_audit_outbox') IS NULL
     OR to_regprocedure('saas_m1_api.create_project(text,text,text)') IS NULL
  THEN
    RAISE EXCEPTION 'M1e physical disconnect test refused outside disposable PostgreSQL16';
  END IF;
END
$guard$;

SELECT saas_rls_test.assert_true(
  NOT EXISTS (
    SELECT 1 FROM saas_m1_private.projects
    WHERE tenant_id='demo-north'
      AND project_id IN ('m1e-physical-loss', 'm1e-aborted',
                         'm1e-reuse-denied', 'm1e-abort-reuse-denied'))
  AND NOT EXISTS (
    SELECT 1 FROM saas_m1_private.project_write_audit_outbox
    WHERE tenant_id='demo-north'
      AND project_id IN ('m1e-physical-loss', 'm1e-aborted',
                         'm1e-reuse-denied', 'm1e-abort-reuse-denied'))
  AND (SELECT COUNT(*) = 1 FROM saas_m1_private.projects
       WHERE tenant_id='demo-north' AND project_id='m1b-lost-ack'
         AND status='active' AND version=1)
  AND (SELECT COUNT(*) = 1 FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id='m1b-lost-ack'
         AND operation='create' AND project_version=1),
  'M1e physical loss/abort => no project, no audit, no retry; committed lost ACK => exactly one of each'
);

SELECT saas_rls_test.assert_true(
  NOT has_table_privilege('saas_ci_runner',
     'saas_m1_private.project_write_audit_outbox','SELECT')
  AND NOT has_table_privilege('saas_ci_runner',
     'saas_m1_private.project_write_audit_outbox','UPDATE')
  AND NOT has_table_privilege('saas_m1_project_executor',
     'saas_m1_private.project_write_audit_outbox','DELETE')
  AND NOT has_table_privilege('saas_ci_runner',
     'saas_rls_private.scope_signers','SELECT')
  AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
       WHERE oid='saas_m1_private.project_write_audit_outbox'::regclass),
  'M1e no privilege escalation to private journal/signer while aborting physical pool'
);

\echo 'PASS M1e: real backend termination/aborted project have 0 rows/0 audits, no retry; lost committed ACK has exactly 1 of each'