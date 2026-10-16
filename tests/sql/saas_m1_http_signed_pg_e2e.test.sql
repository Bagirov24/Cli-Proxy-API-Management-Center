\set ON_ERROR_STOP on
-- M1j independent privileged PG16 evidence after REAL HTTP -> signed
-- Bun.SQL -> M1d signed authorization fence/M1c audit/M1g UUID binding.
-- Separate fsynced M1h intent is verified by a no-PG witness process.
-- This acceptance is restricted to disposable GitHub PostgreSQL16.
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test' OR current_user <> 'postgres'
     OR to_regclass('saas_m1_private.projects') IS NULL
     OR to_regclass('saas_m1_private.project_write_audit_outbox') IS NULL
     OR to_regclass('saas_m1_private.project_attempt_bindings') IS NULL
     OR to_regprocedure('saas_m1_private.append_project_write_audit_fenced()') IS NULL
  THEN
    RAISE EXCEPTION 'M1j HTTP-to-PG acceptance denied outside disposable signed PG16';
  END IF;
END
$guard$;

SELECT saas_rls_test.assert_true(
  (SELECT status='disabled' AND version=3 AND name='M1j synthetic rename'
   FROM saas_m1_private.projects
   WHERE tenant_id='demo-north' AND project_id='m1j-flow')
  AND (SELECT COUNT(*)=3 FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id='m1j-flow')
  AND (SELECT ARRAY_AGG(operation ORDER BY project_version)
       = ARRAY['create','rename','disable']::TEXT[]
       FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id='m1j-flow')
  AND (SELECT ARRAY_AGG(project_version ORDER BY project_version)
       = ARRAY[1,2,3]::BIGINT[]
       FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id='m1j-flow')
  AND (SELECT COUNT(*)=3 AND COUNT(DISTINCT b.attempt_id)=3
       FROM saas_m1_private.project_attempt_bindings b
       JOIN saas_m1_private.project_write_audit_outbox a
         ON a.event_id=b.event_id
       WHERE a.tenant_id='demo-north' AND a.project_id='m1j-flow'
         AND a.actor_id='actor-north'
         AND a.pg_txid ~ '^[0-9]{1,19}$')
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.projects
       WHERE tenant_id='demo-north' AND project_id='m1j-ack-lost'
         AND status='active' AND version=1)
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id='m1j-ack-lost'
         AND operation='create' AND project_version=1 AND actor_id='actor-north')
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.project_attempt_bindings b
       JOIN saas_m1_private.project_write_audit_outbox a
         ON a.event_id=b.event_id
       WHERE a.tenant_id='demo-north' AND a.project_id='m1j-ack-lost'),
  'M1j real loopback HTTP create+rename+disable => signed 3/3/3; HTTP 503 after COMMIT => 1/1/1'
);

SELECT saas_rls_test.assert_true(
  NOT EXISTS (SELECT 1 FROM saas_m1_private.projects
    WHERE project_id IN ('m1j-auth-denied','m1j-db-revoked',
                         'm1j-precommit-loss','m1j-signer-dead'))
  AND NOT EXISTS (SELECT 1 FROM saas_m1_private.project_write_audit_outbox
    WHERE project_id IN ('m1j-auth-denied','m1j-db-revoked',
                         'm1j-precommit-loss','m1j-signer-dead'))
  AND NOT EXISTS (
    SELECT 1 FROM saas_m1_private.project_attempt_bindings b
    JOIN saas_m1_private.project_write_audit_outbox a
      ON a.event_id=b.event_id
    WHERE a.project_id IN ('m1j-auth-denied','m1j-db-revoked',
                           'm1j-precommit-loss','m1j-signer-dead')
  )
  AND (SELECT COUNT(*)=1 FROM saas_rls.memberships
    WHERE actor_id='actor-north' AND tenant_id='demo-north' AND status='active')
  AND (SELECT COUNT(*)=1 FROM pg_trigger
    WHERE tgname='m1_project_atomic_audit'
      AND tgrelid='saas_m1_private.projects'::regclass
      AND tgfoid='saas_m1_private.append_project_write_audit_fenced()'::regprocedure),
  'M1j HTTP forgery, revoked DB membership, pre-COMMIT physical loss and unavailable signer leave no ghost write/audit'
);

SELECT saas_rls_test.assert_true(
  NOT has_table_privilege('saas_ci_runner',
      'saas_m1_private.project_write_audit_outbox','SELECT')
  AND NOT has_table_privilege('saas_ci_runner',
      'saas_m1_private.project_attempt_bindings','SELECT')
  AND NOT has_table_privilege('saas_m1_project_executor',
      'saas_m1_private.projects','INSERT')
  AND NOT has_table_privilege('saas_m1_attempt_owner',
      'saas_rls_private.scope_signers','SELECT')
  AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
       WHERE oid='saas_m1_private.project_write_audit_outbox'::regclass)
  AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
       WHERE oid='saas_m1_private.project_attempt_bindings'::regclass),
  'M1j HTTP transport confers no new database privilege or signer access'
);

\echo 'PASS M1j: real loopback HTTP -> signed PG16 CAS+fence+audit+UUID; 503 committed=1/1/1, precommit disconnected=0/0/0, DB revoked/forgery/signer gone=0, NO retry/deploy'
