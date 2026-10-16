-- Migration 003: explicit authenticated SQL read gate for EPHEMERAL PG16.
-- Apply ONLY after 001/002 and only to disposable saas_ephemeral_test.
-- No production migration path, new grants, writes by saas_ci_runner or Core.
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
     OR current_setting('saas.staging_only', true) IS DISTINCT FROM 'true'
     OR current_user <> 'postgres' THEN
    RAISE EXCEPTION 'Refusing 2G.4b signed read gate outside ephemeral CI';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles
                 WHERE rolname = 'saas_rls_owner' AND NOT rolbypassrls) THEN
    RAISE EXCEPTION 'Missing least-privilege SaaS RLS owner';
  END IF;
END
$guard$;

-- Even a valid actor/tenant MAC is not enough: the DB's current
-- membership ROLE must match the role the backend authorized before SQL.
-- The signed actor/tenant values are verified by 002; the role parameter
-- is never taken from JWT claims or a client header. Returns BOOLEAN only.
CREATE OR REPLACE FUNCTION saas_rls.scope_membership_matches(
  expected_tenant TEXT, expected_actor TEXT, expected_role TEXT
) RETURNS BOOLEAN
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT saas_rls_private.scope_verified()
    AND expected_tenant =
      NULLIF(current_setting('saas.scope_tenant', true), '')
    AND expected_actor =
      NULLIF(current_setting('saas.scope_actor', true), '')
    AND EXISTS (
      SELECT 1 FROM saas_rls.memberships AS m
      WHERE m.tenant_id = expected_tenant
        AND m.actor_id = expected_actor
        AND m.role = expected_role
        AND m.status = 'active'
    )
$fn$;

ALTER FUNCTION saas_rls.scope_membership_matches(TEXT,TEXT,TEXT)
  OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.scope_membership_matches(TEXT,TEXT,TEXT)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.scope_membership_matches(TEXT,TEXT,TEXT)
  TO saas_rls_reader;

-- Private memberships and signing keys remain unavailable to the reader.
DO $assert$
BEGIN
  IF has_table_privilege('saas_rls_reader', 'saas_rls.memberships', 'SELECT')
    OR has_table_privilege('saas_rls_reader', 'saas_rls.resource_grants', 'SELECT')
    OR has_table_privilege('saas_rls_reader',
                           'saas_rls_private.scope_signers', 'SELECT') THEN
    RAISE EXCEPTION 'Signed gate must not expose private authorization tables';
  END IF;
END
$assert$;
COMMIT;

\echo 'PASS: staging-only signed membership role read gate installed'
