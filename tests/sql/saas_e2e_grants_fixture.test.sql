\set ON_ERROR_STOP on
-- 2G.4a / disposable PG16 GitHub Actions ONLY. Never production migrations.
-- Runs AFTER the existing 2F driver acceptance, so its grant changes cannot
-- invalidate previous staging driver invariants.
SET saas.staging_only = 'true';
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test' OR current_user <> 'postgres'
     OR current_setting('saas.staging_only', true) IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'Refusing SaaS 2G.4 grant fixture outside ephemeral CI';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM saas_rls.resource_grants
                 WHERE id = 'grant-pool' AND status = 'active')
     OR NOT EXISTS (SELECT 1 FROM saas_rls.resource_grants
                    WHERE id = 'grant-account' AND status = 'active')
     OR NOT EXISTS (SELECT 1 FROM saas_rls.resource_grants
                    WHERE id = 'grant-egress' AND status = 'active') THEN
    RAISE EXCEPTION 'Required fresh synthetic 2F fixture grants missing';
  END IF;
END
$guard$;

-- North retains independent platform pool + account grants, but its shared
-- Egress grant is revoked. Account visibility MUST NOT imply Egress access.
UPDATE saas_rls.resource_grants
SET status = 'disabled'
WHERE id = 'grant-egress' AND grantee_tenant_id = 'demo-north';

-- Orbit receives access to a shared POOL only, not to any account or egress
-- inside it. Granting a pool MUST NOT leak its account or routing references.
INSERT INTO saas_rls.resource_grants
  (id, resource_id, resource_kind, grantee_tenant_id,
   owner_kind, owner_tenant_id, status, expires_at)
VALUES
  ('ci-e2e-orbit-pool', 'shared-pool', 'pool', 'demo-orbit',
   'platform', NULL, 'active', NULL),
  ('ci-e2e-orbit-expired-egress', 'shared-egress', 'egress', 'demo-orbit',
   'platform', NULL, 'active', '2000-01-01T00:00:00Z');

SELECT saas_rls_test.assert_true(
  (SELECT status = 'disabled' FROM saas_rls.resource_grants
   WHERE id = 'grant-egress')
  AND (SELECT count(*) = 1 FROM saas_rls.resource_grants
       WHERE id = 'ci-e2e-orbit-pool' AND status = 'active')
  AND (SELECT count(*) = 1 FROM saas_rls.resource_grants
       WHERE id = 'ci-e2e-orbit-expired-egress'
         AND expires_at < statement_timestamp()),
  '2G.4 independent grants fixture must be active and expired as intended'
);
COMMIT;

\echo 'PASS: ephemeral E2E grants differentiate pool/account/egress independently'
