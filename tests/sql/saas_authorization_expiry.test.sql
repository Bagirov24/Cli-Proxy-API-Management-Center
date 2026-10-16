\set ON_ERROR_STOP on
-- Stage 2G.4d.4b: real expiry WITHOUT a database mutation at deadline.
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test' OR current_user <> 'postgres'
     OR to_regclass('saas_rls_private.tenant_authorization_revisions') IS NULL THEN
    RAISE EXCEPTION 'Refusing grant expiry test outside disposable PG CI';
  END IF;
END
$guard$;

BEGIN;
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  NOT EXISTS (
    SELECT 1 FROM saas_rls.authorized_revision_state(
      'demo-north','actor-north','tenant-admin','projects')
  ), 'unsigned revision/expiry attestation must fail closed');
RESET ROLE;
ROLLBACK;

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  (SELECT revision ~ '^[1-9][0-9]*$' AND not_after_ms IS NULL
   FROM saas_rls.authorized_revision_state(
     'demo-north','actor-north','tenant-admin','projects'))
  AND NOT EXISTS (
    SELECT 1 FROM saas_rls.authorized_revision_state(
      'demo-orbit','actor-orbit','tenant-viewer','projects'))
  AND NOT EXISTS (
    SELECT 1 FROM saas_rls.authorized_revision_state(
      'demo-north','actor-north','tenant-owner','projects')),
  'signed state must return private tenant epoch only, no foreign or wrong role');
RESET ROLE;
ROLLBACK;

-- Trigger fires once for the expiry-field WRITE. The subsequent expiration
-- is a CLOCK transition and must alter the signed deadline even though the
-- raw tenant epoch stays the same.
BEGIN;
UPDATE saas_rls.resource_grants
   SET expires_at=statement_timestamp() + INTERVAL '1300 milliseconds'
 WHERE id='grant-account' AND grantee_tenant_id='demo-north';
SELECT revision::TEXT AS epoch_before
  FROM saas_rls_private.tenant_authorization_revisions
 WHERE tenant_id='demo-north' \gset
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  (SELECT revision=:'epoch_before' AND
          not_after_ms ~ '^[1-9][0-9]+$'
   FROM saas_rls.authorized_revision_state(
     'demo-north','actor-north','tenant-admin','projects')),
  'before expiry the signed state must include the earliest grant deadline');
RESET ROLE;

SELECT pg_sleep(1.7);

SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  (SELECT revision=:'epoch_before' AND not_after_ms IS NULL
   FROM saas_rls.authorized_revision_state(
     'demo-north','actor-north','tenant-admin','projects')),
  'elapsed expiry must invalidate time attestation with UNCHANGED raw epoch');
RESET ROLE;
ROLLBACK;

SELECT saas_rls_test.assert_true(
  (SELECT expires_at IS NULL FROM saas_rls.resource_grants
   WHERE id='grant-account')
  AND NOT has_table_privilege('saas_rls_reader',
      'saas_rls.resource_grants','SELECT'),
  'test rollback must restore real grant and never expose private SQL');

\echo 'PASS: PostgreSQL signed deadline changes when grant expires without SQL write'
