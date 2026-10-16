\set ON_ERROR_STOP on
-- Signed reader may take only its own tenant's shared publication lock.
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test' OR current_user <> 'postgres'
     OR to_regclass('saas_rls_private.tenant_authorization_revisions') IS NULL THEN
    RAISE EXCEPTION 'Refusing publication tests outside disposable PG CI';
  END IF;
END
$guard$;

BEGIN;
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.acquire_authorized_read_barrier(
    'demo-north','actor-north','tenant-admin','projects') IS NULL,
  'unsigned reader cannot hold authorization publication barrier');
RESET ROLE;
ROLLBACK;

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.acquire_authorized_read_barrier(
    'demo-north','actor-north','tenant-admin','projects') ~ '^[1-9][0-9]*$'
  AND saas_rls.acquire_authorized_read_barrier(
    'demo-orbit','actor-orbit','tenant-viewer','projects') IS NULL
  AND saas_rls.acquire_authorized_read_barrier(
    'demo-north','actor-north','tenant-owner','projects') IS NULL,
  'signed barrier cannot cross tenants or accept forged roles');
RESET ROLE;
ROLLBACK;

BEGIN;
SELECT saas_rls_test.issue_scope('actor-auditor','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.acquire_authorized_read_barrier(
    'demo-north','actor-auditor','tenant-auditor','projects') IS NOT NULL
  AND saas_rls.acquire_authorized_read_barrier(
    'demo-north','actor-auditor','tenant-auditor','accounts') IS NULL,
  'barrier must honor exact signed collection capability');
RESET ROLE;
ROLLBACK;

BEGIN;
SELECT saas_rls_test.issue_scope('actor-paused','demo-paused',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.acquire_authorized_read_barrier(
    'demo-paused','actor-paused','tenant-owner','projects') IS NULL,
  'suspended tenant cannot hold publication epoch');
RESET ROLE;
ROLLBACK;

SELECT saas_rls_test.assert_true(
  NOT has_table_privilege('saas_rls_reader',
       'saas_rls_private.tenant_authorization_revisions','SELECT')
  AND NOT has_table_privilege('saas_rls_reader',
       'saas_rls.resource_grants','UPDATE'),
  'reader must not gain private revision access or grant writer authority');
\echo 'PASS: publication barrier refuses unsigned, foreign, suspended or wrong-role reader'
