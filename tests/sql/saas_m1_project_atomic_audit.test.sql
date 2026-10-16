\set ON_ERROR_STOP on
-- M1c: disposable PostgreSQL16 atomic project write/audit acceptance.
-- Requires M1a+M1b acceptance and M1c 021 installed. No production data.
DO $guard$
BEGIN
  IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
     OR to_regclass('saas_m1_private.project_write_audit_outbox') IS NULL
     OR to_regprocedure('saas_rls_test.issue_scope(text,text,integer)') IS NULL
  THEN RAISE EXCEPTION 'M1c acceptance denied outside disposable PG16'; END IF;
END
$guard$;

-- Confirm exact M1b's real RS256 -> Bun.SQL -> signed project DML emitted
-- atomic rows. Lost ACK has a committed audit row despite caller 503.
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=3 FROM saas_m1_private.project_write_audit_outbox
   WHERE tenant_id='demo-north' AND project_id='m1b-first')
  AND (SELECT array_agg(operation ORDER BY project_version)
      = ARRAY['create','rename','disable']::text[]
       FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id='m1b-first')
  AND (SELECT array_agg(project_version ORDER BY project_version)
      = ARRAY[1,2,3]::bigint[]
       FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id='m1b-first')
  AND (SELECT count(*)=1 FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id='m1b-lost-ack'
         AND operation='create' AND project_version=1)
  AND NOT EXISTS (
       SELECT 1 FROM saas_m1_private.project_write_audit_outbox
       WHERE project_id IN ('m1b-revoked','m1b-bad-aud','m1b-viewer',
                            'm1b-auditor')),
  'M1b actual signed native SQL CRUD and lost ACK must have exact committed private audit rows'
);

-- Outbox has no project NAME or tokens or raw SQL; it is private data and
-- cannot be read or changed by executor, runner, reader or project owner.
SELECT saas_rls_test.assert_true(
  NOT EXISTS (
    SELECT 1 FROM pg_attribute
    WHERE attrelid='saas_m1_private.project_write_audit_outbox'::regclass
      AND attnum>0 AND NOT attisdropped
      AND attname IN ('name','token','jwt','secret','password',
                      'authorization','raw_sql','payload','response_body'))
  AND NOT has_schema_privilege('saas_m1_project_executor','saas_m1_private','USAGE')
  AND NOT has_table_privilege('saas_m1_project_executor',
        'saas_m1_private.project_write_audit_outbox','SELECT')
  AND NOT has_table_privilege('saas_ci_runner',
        'saas_m1_private.project_write_audit_outbox','SELECT')
  AND NOT has_table_privilege('saas_rls_reader',
        'saas_m1_private.project_write_audit_outbox','INSERT')
  AND NOT has_table_privilege('saas_m1_project_owner',
        'saas_m1_private.project_write_audit_outbox','UPDATE')
  AND NOT has_table_privilege('saas_m1_audit_owner',
        'saas_m1_private.projects','INSERT'),
  'M1c private audit row must be redacted and inaccessible to SQL API roles'
);

-- A signed transaction stores project state and one audit entry together.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project(
  'demo-north','m1c-atomic','M1c private name')::TEXT AS m1c_created \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
  :'m1c_created'='true'
  AND EXISTS (SELECT 1 FROM saas_m1_private.projects
              WHERE tenant_id='demo-north' AND project_id='m1c-atomic'
                AND version=1 AND status='active')
  AND EXISTS (SELECT 1 FROM saas_m1_private.project_write_audit_outbox
              WHERE tenant_id='demo-north' AND project_id='m1c-atomic'
                AND operation='create' AND project_version=1
                AND actor_id='actor-north' AND
                    pg_txid=txid_current()::text),
  'Project row and private audit must exist in SAME uncommitted tx');
COMMIT;

-- CAS success, duplicate/stale conflict, disable terminal:
-- only real mutations produce events, one per project version.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-north','m1c-atomic','Duplicate')::TEXT AS m1c_duplicate \gset
SELECT saas_m1_api.rename_project('demo-north','m1c-atomic','New name',1)::TEXT AS m1c_rename \gset
SELECT saas_m1_api.rename_project('demo-north','m1c-atomic','Stale',1)::TEXT AS m1c_stale \gset
SELECT saas_m1_api.disable_project('demo-north','m1c-atomic',2)::TEXT AS m1c_disable \gset
SELECT saas_m1_api.disable_project('demo-north','m1c-atomic',3)::TEXT AS m1c_repeat \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
  :'m1c_duplicate'='false' AND :'m1c_rename'='true'
  AND :'m1c_stale'='false' AND :'m1c_disable'='true'
  AND :'m1c_repeat'='false',
  'Duplicate/stale/terminal conflict denied; no retry or reactivation');
COMMIT;
SELECT saas_rls_test.assert_true(
  (SELECT array_agg(operation ORDER BY project_version)
   = ARRAY['create','rename','disable']::text[]
   FROM saas_m1_private.project_write_audit_outbox
   WHERE tenant_id='demo-north' AND project_id='m1c-atomic')
  AND (SELECT count(*)=3 FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id='m1c-atomic')
  AND (SELECT status='disabled' AND version=3
       FROM saas_m1_private.projects
       WHERE tenant_id='demo-north' AND project_id='m1c-atomic'),
  'Exactly three privately audited committed state changes, no false conflict events'
);

-- Transaction ROLLBACK removes BOTH project and private audit event.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-north','m1c-rollback','Temporary')::TEXT AS provisional \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
  :'provisional'='true' AND
  EXISTS (SELECT 1 FROM saas_m1_private.project_write_audit_outbox
          WHERE tenant_id='demo-north' AND project_id='m1c-rollback'),
  'Audit is written transactionally before rollback');
ROLLBACK;
SELECT saas_rls_test.assert_true(
  NOT EXISTS (SELECT 1 FROM saas_m1_private.projects
              WHERE tenant_id='demo-north' AND project_id='m1c-rollback')
  AND NOT EXISTS (SELECT 1 FROM saas_m1_private.project_write_audit_outbox
                  WHERE tenant_id='demo-north' AND project_id='m1c-rollback'),
  'ROLLBACK must remove project and audit atomically'
);

-- Force an audit UNIQUE collision with a privileged fixture-only row.
-- The public function's EXCEPTION block must undo its provisional INSERT.
-- Fixture preseed itself also rolls back: never permanently forge audit.
BEGIN;
INSERT INTO saas_m1_private.project_write_audit_outbox
  (tenant_id,project_id,project_version,operation,actor_id,
   authorization_revision,pg_txid)
VALUES ('demo-north','m1c-audit-denied',1,'create','actor-north',
        1,txid_current()::text);
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_m1_project_executor;
SELECT saas_m1_api.create_project('demo-north','m1c-audit-denied',
  'MUST NOT COMMIT WITHOUT AUDIT')::TEXT AS audit_blocked \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
  :'audit_blocked'='false'
  AND NOT EXISTS (SELECT 1 FROM saas_m1_private.projects
                  WHERE tenant_id='demo-north' AND project_id='m1c-audit-denied')
  AND (SELECT count(*)=1 FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id='m1c-audit-denied'),
  'Audit uniqueness failure must roll back project without duplicate audit');
ROLLBACK;
SELECT saas_rls_test.assert_true(
  NOT EXISTS (SELECT 1 FROM saas_m1_private.projects
              WHERE tenant_id='demo-north' AND project_id='m1c-audit-denied')
  AND NOT EXISTS (SELECT 1 FROM saas_m1_private.project_write_audit_outbox
                  WHERE tenant_id='demo-north' AND project_id='m1c-audit-denied'),
  'Privileged fault fixture leaves no project/audit after rollback'
);

-- A superuser can change DDL, so this is NOT independent WORM/HSM. But
-- ordinary UPDATE/DELETE SQL DML is rejected even by the test installer.
DO $append_only$
DECLARE
  update_denied BOOLEAN := false;
  delete_denied BOOLEAN := false;
BEGIN
  BEGIN
    UPDATE saas_m1_private.project_write_audit_outbox
       SET operation='rename' WHERE project_id='m1c-atomic';
  EXCEPTION WHEN raise_exception THEN update_denied := true;
  END;
  BEGIN
    DELETE FROM saas_m1_private.project_write_audit_outbox
       WHERE project_id='m1c-atomic';
  EXCEPTION WHEN raise_exception THEN delete_denied := true;
  END;
  IF NOT update_denied OR NOT delete_denied THEN
    RAISE EXCEPTION 'M1c private outbox accepted forbidden UPDATE/DELETE';
  END IF;
END
$append_only$;

-- Replay of CI staging migration must preserve recorded projects, event
-- revisions, log IDs and terminal state: no TRUNCATE, GC or reset.
SET saas.staging_only='true';
\ir ../../staging/saas-rls/021_m1_project_atomic_audit_pilot.sql
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=3 FROM saas_m1_private.project_write_audit_outbox
   WHERE tenant_id='demo-north' AND project_id='m1c-atomic')
  AND (SELECT count(*)=1 FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id='m1b-lost-ack')
  AND (SELECT status='disabled' AND version=3
       FROM saas_m1_private.projects
       WHERE tenant_id='demo-north' AND project_id='m1c-atomic'),
  'M1c replay must not lose signed project audit or reactivate disabled row'
);
\echo 'PASS M1c: real Bun.SQL signed project writes have atomic private audit; COMMIT/ROLLBACK/conflicts/audit-failure/replay fail closed, NO PRODUCTION or auto retry'