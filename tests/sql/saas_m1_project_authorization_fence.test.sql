\set ON_ERROR_STOP on
-- M1d: native pg16 signed transactional write/revocation fencing acceptance.
DO $guard$
BEGIN
  IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
     OR to_regprocedure('saas_m1_private.append_project_write_audit_fenced()') IS NULL
     OR to_regprocedure('saas_rls.acquire_authorized_read_barrier(text,text,text,text)') IS NULL
  THEN RAISE EXCEPTION 'M1d SQL acceptance requires isolated PG16 fixture'; END IF;
END
$guard$;

SELECT saas_rls_test.assert_true(
  EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid='saas_m1_private.projects'::regclass
      AND tgname='m1_project_atomic_audit'
      AND tgfoid='saas_m1_private.append_project_write_audit_fenced()'::regprocedure
      AND NOT tgisinternal)
  AND has_function_privilege('saas_m1_audit_owner',
      'saas_rls.acquire_authorized_read_barrier(text,text,text,text)','EXECUTE')
  AND NOT has_function_privilege('saas_m1_project_executor',
      'saas_m1_private.append_project_write_audit_fenced()','EXECUTE')
  AND NOT has_table_privilege('saas_m1_audit_owner',
      'saas_rls_private.tenant_authorization_revisions','SELECT')
  AND NOT has_table_privilege('saas_m1_audit_owner',
      'saas_m1_private.projects','INSERT')
  AND NOT has_table_privilege('saas_ci_runner',
      'saas_m1_private.project_write_audit_outbox','SELECT')
  AND NOT has_table_privilege('saas_ci_runner',
      'saas_rls_private.scope_signers','SELECT')
  AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
       WHERE oid='saas_m1_private.project_write_audit_outbox'::regclass),
  'M1d fence is installed without direct private table/signer grants');

-- The signed FOR SHARE primitive rejects non-read-committed snapshots.
-- Even if the original precheck passes, the trigger must abort provisional
-- project changes and the required private audit event together.
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120) \gset
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-north','m1d-snapshot',
  'Refuse stale snapshot')::TEXT AS m1d_bad_snapshot \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(:'m1d_bad_snapshot'='false',
  'M1d rejects RR snapshot instead of trusting a stale signed scope');
ROLLBACK;

-- An unsigned executor has fixed-function EXECUTE but cannot create rows,
-- while public reader/CI runner cannot write the private audit directly.
BEGIN;
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-north','m1d-unsigned',
  'No signed scope')::TEXT AS m1d_unsigned \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(:'m1d_unsigned'='false',
  'M1d untrusted direct executor still denied');
ROLLBACK;

-- The concurrent multi-session harness ran before this SQL acceptance:
-- verify one ordered COMMIT + audit and both concurrent DENY outcomes.
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=1 FROM saas_m1_private.projects
    WHERE tenant_id='demo-north' AND project_id='m1d-write-first'
      AND status='active' AND version=1)
  AND (SELECT count(*)=1 FROM saas_m1_private.project_write_audit_outbox
    WHERE tenant_id='demo-north' AND project_id='m1d-write-first'
      AND project_version=1 AND operation='create' AND actor_id='actor-north')
  AND NOT EXISTS (
    SELECT 1 FROM saas_m1_private.projects
    WHERE project_id IN ('m1d-revoke-first','m1d-suspend-first',
                         'm1d-snapshot','m1d-unsigned'))
  AND NOT EXISTS (
    SELECT 1 FROM saas_m1_private.project_write_audit_outbox
    WHERE project_id IN ('m1d-revoke-first','m1d-suspend-first',
                         'm1d-snapshot','m1d-unsigned')),
  'M1d exactly one permitted COMMIT with audit, forbidden writes have none'
);

-- Replaying 022 must keep event IDs and the trigger pointed at the
-- signed barrier. No fixture reset, DELETE, data rewrite, or reissue.
SET saas.staging_only='true';
\ir ../../staging/saas-rls/022_m1_project_authorization_fence_pilot.sql
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=1 FROM saas_m1_private.project_write_audit_outbox
   WHERE tenant_id='demo-north' AND project_id='m1d-write-first'
     AND operation='create')
  AND EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid='saas_m1_private.projects'::regclass
      AND tgname='m1_project_atomic_audit'
      AND tgfoid='saas_m1_private.append_project_write_audit_fenced()'::regprocedure
      AND NOT tgisinternal),
  'M1d 022 replay must preserve project audit and signed fence'
);
\echo 'PASS M1d: signed tenant epoch fence, RR/unsigned deny, ordered writes/audit and replay; NOT PRODUCTION or retry'