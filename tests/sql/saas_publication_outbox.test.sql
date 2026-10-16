\set ON_ERROR_STOP on
-- 2G.4d.6b: append-only signed audit, rollback, spoofing and ACL acceptance.
DO $guard$
BEGIN
  IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
     OR to_regclass('saas_rls_private.local_publication_audit_outbox') IS NULL
  THEN RAISE EXCEPTION 'Refusing outbox tests outside disposable CI'; END IF;
END
$guard$;

BEGIN;
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  NOT saas_rls.record_signed_local_publication(
    'demo-north','actor-north','tenant-admin','projects','ci-outbox-unsigned'),
  'Unsigned reader must not insert outbox event');
RESET ROLE;
ROLLBACK;

-- A signed successful event inside a transaction is NOT durable if rolled back.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.record_signed_local_publication(
    'demo-north','actor-north','tenant-admin','projects','ci-outbox-rollback'),
  'Signed active actor must append private audit event');
RESET ROLE;
SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*)=1 FROM saas_rls_private.local_publication_audit_outbox
   WHERE correlation_id='ci-outbox-rollback'),
  'The staged event must exist inside its signed transaction');
ROLLBACK;
SELECT saas_rls_test.assert_true(
  NOT EXISTS (SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
   WHERE correlation_id='ci-outbox-rollback'),
  'Audit outbox and publication transaction must rollback atomically');

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.record_signed_local_publication(
    'demo-north','actor-north','tenant-admin','projects','ci-outbox-persist')
  AND NOT saas_rls.record_signed_local_publication(
    'demo-orbit','actor-orbit','tenant-viewer','projects','ci-outbox-forged')
  AND NOT saas_rls.record_signed_local_publication(
    'demo-north','actor-north','tenant-owner','projects','ci-outbox-wrong-role')
  AND NOT saas_rls.record_signed_local_publication(
    'demo-north','actor-north','tenant-admin','projects','bad correlation'),
  'Only exact signed role/tenant and safe server correlation may insert');
RESET ROLE;
COMMIT;

SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*)=1 FROM saas_rls_private.local_publication_audit_outbox
   WHERE correlation_id='ci-outbox-persist'
     AND tenant_id='demo-north' AND actor_id='actor-north'
     AND collection='projects' AND authorization_revision>0
     AND result='allow')
  AND NOT EXISTS (SELECT 1 FROM saas_rls_private.local_publication_audit_outbox
                  WHERE correlation_id IN ('ci-outbox-forged','ci-outbox-wrong-role'))
  AND NOT has_table_privilege('saas_rls_reader',
      'saas_rls_private.local_publication_audit_outbox','SELECT')
  AND NOT has_table_privilege('saas_ci_runner',
      'saas_rls_private.local_publication_audit_outbox','INSERT'),
  'Committed audit is redacted/durable, foreign actor cannot insert or inspect');

-- A revoked actor cannot append another event, even with a MAC that
-- previously authenticated the same actor and tenant.
BEGIN;
UPDATE saas_rls_private.actor_session_state
 SET status='revoked',revision=revision+1 WHERE actor_id='actor-north';
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  NOT saas_rls.record_signed_local_publication(
    'demo-north','actor-north','tenant-admin','projects','ci-outbox-revoked'),
  'Revoked actor cannot append authorized Allow audit');
RESET ROLE;
ROLLBACK;

-- Duplicate correlation must raise and NEVER overwrite prior event.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
DO $probe$
DECLARE caught BOOLEAN := FALSE;
BEGIN
  BEGIN
    PERFORM saas_rls.record_signed_local_publication(
      'demo-north','actor-north','tenant-admin','projects','ci-outbox-persist');
  EXCEPTION WHEN unique_violation THEN caught := TRUE;
  END;
  PERFORM saas_rls_test.assert_true(caught,
    'Duplicate local publication receipt must fail closed');
END
$probe$;
RESET ROLE;
ROLLBACK;
\echo 'PASS: signed PG16 durable-on-COMMIT audit, spoofing and ROLLBACK isolation'
