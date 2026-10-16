\set ON_ERROR_STOP on
-- Stage 2G.4d.2: PG16 transactionally versioned authorization pilot.
-- Applied only AFTER 004 and disposable synthetic 2F/2G fixtures.
SET saas.staging_only = 'true';

SELECT saas_rls_test.assert_true(
  (SELECT count(*)=3 FROM saas_rls_private.tenant_authorization_revisions) AND
  (SELECT tenant_active FROM saas_rls_private.tenant_authorization_revisions
   WHERE tenant_id='demo-north') AND
  (SELECT tenant_active FROM saas_rls_private.tenant_authorization_revisions
   WHERE tenant_id='demo-orbit') AND
  NOT (SELECT tenant_active FROM saas_rls_private.tenant_authorization_revisions
       WHERE tenant_id='demo-paused') AND
  NOT has_schema_privilege('saas_rls_reader', 'saas_rls_private', 'USAGE') AND
  NOT has_table_privilege('saas_rls_reader',
    'saas_rls_private.tenant_authorization_revisions','SELECT'),
  'epoch bootstrap and private ACL must remain tenant-scoped'
);

-- Unsigned, cross-tenant, wrong role, auditor capability and paused
-- tenant may not extract revision even if caller guesses resource IDs.
BEGIN;
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.authorized_revision('demo-north','actor-north','tenant-admin','projects')
    IS NULL,
  'missing signed SQL scope must not reveal private epoch'
);
RESET ROLE;
ROLLBACK;

BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.authorized_revision('demo-north','actor-north','tenant-admin','projects')
    ~ '^[1-9][0-9]*$'
  AND saas_rls.authorized_revision('demo-orbit','actor-orbit','tenant-viewer','projects')
    IS NULL
  AND saas_rls.authorized_revision('demo-north','actor-orbit','tenant-admin','projects')
    IS NULL
  AND saas_rls.authorized_revision('demo-north','actor-north','tenant-owner','projects')
    IS NULL,
  'signed North may read only its own actor/role-bound epoch'
);
RESET ROLE;
ROLLBACK;

BEGIN;
SELECT saas_rls_test.issue_scope('actor-auditor','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.authorized_revision('demo-north','actor-auditor','tenant-auditor','projects')
    IS NOT NULL
  AND saas_rls.authorized_revision('demo-north','actor-auditor','tenant-auditor','resources')
    IS NULL,
  'auditor can attest permitted projects but not accounts/egress'
);
RESET ROLE;
ROLLBACK;

BEGIN;
SELECT saas_rls_test.issue_scope('actor-paused','demo-paused',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.authorized_revision('demo-paused','actor-paused','tenant-owner','projects')
    IS NULL,
  'signed but suspended tenant must never obtain usable revision'
);
RESET ROLE;
ROLLBACK;

-- All mutations are part of ONE transaction that is deliberately rolled back.
-- No revision (or membership/grant/catalog change) may survive rollback.
SELECT revision::TEXT AS north_before FROM
  saas_rls_private.tenant_authorization_revisions
  WHERE tenant_id='demo-north' \gset
SELECT revision::TEXT AS orbit_before FROM
  saas_rls_private.tenant_authorization_revisions
  WHERE tenant_id='demo-orbit' \gset

BEGIN;
DO $tests$
DECLARE
  n BIGINT;
  o BIGINT;
BEGIN
  -- psql variables are not expanded inside DO dollar-quoted source.
  SELECT revision INTO STRICT n
    FROM saas_rls_private.tenant_authorization_revisions
    WHERE tenant_id='demo-north';
  SELECT revision INTO STRICT o
    FROM saas_rls_private.tenant_authorization_revisions
    WHERE tenant_id='demo-orbit';
  UPDATE saas_rls.memberships SET role='tenant-owner'
  WHERE actor_id='actor-north' AND tenant_id='demo-north';
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=n+1 FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-north'), 'membership role downgrade/upgrade bumps epoch');

  UPDATE saas_rls.memberships SET status='revoked'
  WHERE actor_id='actor-north' AND tenant_id='demo-north';
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=n+2 FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-north'), 'membership revoke bumps epoch');

  UPDATE saas_rls.resource_grants SET status='disabled' WHERE id='grant-pool';
  UPDATE saas_rls.resource_grants SET status='disabled' WHERE id='grant-account';
  UPDATE saas_rls.resource_grants SET status='active' WHERE id='grant-egress';
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=n+5 FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-north'),
    'Pool/Account/Egress grants must be independent versioned writes');

  UPDATE saas_rls.resource_grants
     SET expires_at='2030-01-01T00:00:00Z' WHERE id='grant-account';
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=n+6 FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-north'), 'grant expiry mutation bumps epoch');

  -- Shared pool is granted independently to North and Orbit.
  UPDATE saas_rls.resource_catalog SET status='blocked'
  WHERE id='shared-pool';
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=n+7 FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-north') AND
    (SELECT revision=o+1 FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-orbit'),
    'shared resource mutation must invalidate EVERY affected grantee');

  UPDATE saas_rls.tenants SET status='suspended' WHERE id='demo-north';
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=n+8 AND NOT tenant_active
     FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'),
    'tenant suspension must invalidate revision and deny state');

  INSERT INTO saas_rls.tenants(id,name,status)
  VALUES ('ci-tenant-reused','Ephemeral', 'active');
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=1 AND tenant_active FROM
     saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='ci-tenant-reused'), 'new tenant epoch initialized');
  DELETE FROM saas_rls.tenants WHERE id='ci-tenant-reused';
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=2 AND NOT tenant_active FROM
     saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='ci-tenant-reused'), 'tenant delete retains a tombstone');
  INSERT INTO saas_rls.tenants(id,name,status)
  VALUES ('ci-tenant-reused','Recreated', 'active');
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=3 AND tenant_active FROM
     saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='ci-tenant-reused'), 'reused tenant ID cannot reset epoch');
END
$tests$;
ROLLBACK;

SELECT saas_rls_test.assert_true(
  (SELECT revision::TEXT=:'north_before'
   FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north')
  AND (SELECT revision::TEXT=:'orbit_before'
   FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-orbit')
  AND NOT EXISTS (SELECT 1 FROM saas_rls_private.tenant_authorization_revisions
                  WHERE tenant_id='ci-tenant-reused')
  AND (SELECT status='active' FROM saas_rls.memberships
       WHERE actor_id='actor-north' AND tenant_id='demo-north')
  AND (SELECT status='active' FROM saas_rls.resource_grants WHERE id='grant-pool'),
  'ROLLBACK must undo BOTH authorization mutation and epoch bump'
);

-- A committed grant change outside a LIMITed projects read is detected
-- by a new signed transaction even though its project rows do not change.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.authorized_revision(
  'demo-north','actor-north','tenant-admin','projects') AS signed_before \gset
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=1 FROM saas_rls.projects),
  'North project row set must remain stable');
RESET ROLE;
ROLLBACK;

UPDATE saas_rls.resource_grants SET status='disabled' WHERE id='grant-pool';
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.authorized_revision(
  'demo-north','actor-north','tenant-admin','projects') AS signed_after \gset
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=1 FROM saas_rls.projects),
  'projects rows unchanged despite unrelated revoked Pool grant');
RESET ROLE;
ROLLBACK;

SELECT saas_rls_test.assert_true(
  (:'signed_after')::BIGINT = (:'signed_before')::BIGINT+1,
  'two signed transactions must observe committed grant revision drift');
UPDATE saas_rls.resource_grants SET status='active' WHERE id='grant-pool';

-- Exact role must still be enforced after a successful signed JWT mapping.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
UPDATE saas_rls.memberships SET role='tenant-viewer'
WHERE actor_id='actor-north' AND tenant_id='demo-north';
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.authorized_revision('demo-north','actor-north','tenant-admin','projects')
    IS NULL,
  'signed scope cannot override a role downgraded in PostgreSQL');
RESET ROLE;
ROLLBACK;

\echo 'PASS: signed PG16 revision isolation, tenant/member/grant/catalog invalidation and rollback'
