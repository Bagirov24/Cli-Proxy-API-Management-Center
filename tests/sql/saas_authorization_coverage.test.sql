\set ON_ERROR_STOP on
-- 2G.4d.4a: actual transactional PostgreSQL epoch coverage, disposable only.
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test' OR current_user <> 'postgres'
     OR to_regclass('saas_rls_private.tenant_authorization_revisions') IS NULL THEN
    RAISE EXCEPTION 'Refusing projection revision tests outside ephemeral CI';
  END IF;
END
$guard$;

SELECT revision::TEXT AS north_before
  FROM saas_rls_private.tenant_authorization_revisions
 WHERE tenant_id='demo-north' \gset
SELECT revision::TEXT AS orbit_before
  FROM saas_rls_private.tenant_authorization_revisions
 WHERE tenant_id='demo-orbit' \gset

BEGIN;
DO $probe$
DECLARE
  north BIGINT;
  orbit BIGINT;
BEGIN
  SELECT revision INTO STRICT north FROM saas_rls_private.tenant_authorization_revisions
  WHERE tenant_id='demo-north';
  SELECT revision INTO STRICT orbit FROM saas_rls_private.tenant_authorization_revisions
  WHERE tenant_id='demo-orbit';

  UPDATE saas_rls.projects SET status='disabled' WHERE id='north-project';
  UPDATE saas_rls.applications SET status='disabled' WHERE id='north-app';
  UPDATE saas_rls.key_bindings SET status='disabled' WHERE id='north-binding';
  UPDATE saas_rls.routing_bindings SET status='disabled' WHERE id='north-route';
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=north+4 FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-north') AND
    (SELECT revision=orbit FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-orbit'),
    'project/application/key/routing changes must version ONLY North');

  -- No-op updates must not spuriously advance version; real changes do.
  UPDATE saas_rls.projects SET status=status WHERE id='north-project';
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=north+4 FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-north'), 'no-op projection UPDATE must not advance revision');

  -- Shared pool is explicitly granted to BOTH North and Orbit, though Orbit
  -- lacks the shared Account grant. Changing this link must invalidate both.
  UPDATE saas_rls.resource_links SET status='disabled' WHERE id='shared-member';
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=north+5 FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-north') AND
    (SELECT revision=orbit+1 FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-orbit'),
    'shared Pool->Account link must invalidate both distinct grantees');

  -- Linking a platform pool to tenant-owned North Account also invalidates
  -- both the previous grantees and the new endpoint owner.
  UPDATE saas_rls.resource_links SET to_id='north-account'
  WHERE id='shared-member';
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=north+6 FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-north') AND
    (SELECT revision=orbit+2 FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-orbit'),
    'link endpoint change must bump affected owner and original grantees');

  INSERT INTO saas_rls.projects(id,tenant_id,name,status)
  VALUES ('ci-transient-projection','demo-north','Synthetic','active');
  DELETE FROM saas_rls.projects WHERE id='ci-transient-projection';
  PERFORM saas_rls_test.assert_true(
    (SELECT revision=north+8 FROM saas_rls_private.tenant_authorization_revisions
     WHERE tenant_id='demo-north'), 'project INSERT and DELETE must each bump');
END
$probe$;
ROLLBACK;

SELECT saas_rls_test.assert_true(
  (SELECT revision::TEXT=:'north_before'
   FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north')
  AND (SELECT revision::TEXT=:'orbit_before'
   FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-orbit')
  AND (SELECT status='active' FROM saas_rls.projects WHERE id='north-project')
  AND (SELECT status='active' FROM saas_rls.applications WHERE id='north-app')
  AND (SELECT status='active' FROM saas_rls.key_bindings WHERE id='north-binding')
  AND (SELECT status='active' FROM saas_rls.routing_bindings WHERE id='north-route')
  AND (SELECT status='active' FROM saas_rls.resource_links WHERE id='shared-member')
  AND NOT EXISTS (SELECT 1 FROM saas_rls.projects WHERE id='ci-transient-projection'),
  'rollback must undo projection/link state and all tenant epoch increments'
);

-- Signed scope never permits a client to obtain another tenant's revision.
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',90);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.authorized_revision('demo-orbit','actor-orbit','tenant-viewer','projects') IS NOT NULL
  AND saas_rls.authorized_revision('demo-north','actor-north','tenant-admin','projects') IS NULL,
  'foreign signed scope must never read North authorization epoch'
);
RESET ROLE;
ROLLBACK;
\echo 'PASS: ephemeral metadata/link revisions, shared fanout and rollback'
