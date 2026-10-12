\set ON_ERROR_STOP on
-- Stage 2G.4d.6a: real PG16 signed actor-wide kill switch/epoch rollback.
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test' OR current_user <> 'postgres'
    OR to_regclass('saas_rls_private.actor_session_state') IS NULL THEN
    RAISE EXCEPTION 'Refusing actor kill switch tests outside disposable CI';
  END IF;
END
$guard$;

SELECT revision::TEXT AS north_before
 FROM saas_rls_private.tenant_authorization_revisions
 WHERE tenant_id='demo-north' \gset
SELECT revision::TEXT AS orbit_before
 FROM saas_rls_private.tenant_authorization_revisions
 WHERE tenant_id='demo-orbit' \gset

-- Active actor+role must be present in BOTH the private registry and DB membership.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',90);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.scope_membership_matches('demo-north','actor-north','tenant-admin')
  AND NOT saas_rls.scope_membership_matches('demo-orbit','actor-north','tenant-admin')
  AND NOT saas_rls.scope_membership_matches('demo-north','actor-north','tenant-owner'),
  'only signed matching actor/role can pass active session DB gate');
RESET ROLE;
ROLLBACK;

BEGIN;
UPDATE saas_rls_private.actor_session_state
   SET status='revoked', revision=revision+1 WHERE actor_id='actor-north';
SELECT saas_rls_test.assert_true(
  (SELECT revision=(:'north_before')::BIGINT+1
   FROM saas_rls_private.tenant_authorization_revisions
   WHERE tenant_id='demo-north')
  AND (SELECT revision::TEXT=:'orbit_before'
   FROM saas_rls_private.tenant_authorization_revisions
   WHERE tenant_id='demo-orbit'),
  'actor revocation must advance North only, not other tenants');
SELECT saas_rls_test.issue_scope('actor-north','demo-north',90);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  NOT saas_rls.scope_membership_matches('demo-north','actor-north','tenant-admin')
  AND saas_rls.authorized_revision('demo-north','actor-north','tenant-admin','projects') IS NULL
  AND NOT EXISTS (
    SELECT 1 FROM saas_rls.authorized_revision_state(
      'demo-north','actor-north','tenant-admin','projects')
  )
  AND saas_rls.acquire_authorized_read_barrier(
    'demo-north','actor-north','tenant-admin','projects') IS NULL,
  'revoked actor must fail signed gate, revision attestation and FOR SHARE');
RESET ROLE;
ROLLBACK;

SELECT saas_rls_test.assert_true(
  (SELECT status='active' FROM saas_rls_private.actor_session_state
   WHERE actor_id='actor-north')
  AND (SELECT revision::TEXT=:'north_before'
       FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'),
  'ROLLBACK restores actor active status and North epoch atomically');

-- A new actor record/DELETE must invalidate all current member tenants,
-- even when one actor has memberships in more than one tenant.
BEGIN;
INSERT INTO saas_rls.memberships(actor_id,tenant_id,role,status)
VALUES ('actor-north','demo-orbit','tenant-viewer','active');
UPDATE saas_rls_private.actor_session_state
   SET status='revoked', revision=revision+1 WHERE actor_id='actor-north';
SELECT saas_rls_test.assert_true(
  (SELECT revision=(:'north_before')::BIGINT+1
   FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north')
  AND (SELECT revision=(:'orbit_before')::BIGINT+2
   FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-orbit'),
  'shared actor kill switch must atomically bump North once and Orbit twice');
ROLLBACK;

-- Identical UPDATEs do not advance the epoch, even if a privileged
-- fixture repeats the same active actor status.
BEGIN;
UPDATE saas_rls_private.actor_session_state
 SET status=status WHERE actor_id='actor-north';
SELECT saas_rls_test.assert_true(
  (SELECT revision=(:'north_before')::BIGINT
   FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'),
  'No-op actor UPDATE must not advance tenant revision');
ROLLBACK;

-- Replay of guarded migration must retain revoked fixture actors; separately
-- tested by repeating 008 in CI after this test.
SELECT saas_rls_test.assert_true(
  NOT has_table_privilege('saas_ci_runner',
      'saas_rls_private.actor_session_state','SELECT')
  AND NOT has_table_privilege('saas_rls_reader',
      'saas_rls_private.actor_session_state','UPDATE'),
  'least-privileged reader must not inspect or mutate actor session registry');
\echo 'PASS: signed PG16 actor kill switch, cross-tenant fanout and ROLLBACK'
