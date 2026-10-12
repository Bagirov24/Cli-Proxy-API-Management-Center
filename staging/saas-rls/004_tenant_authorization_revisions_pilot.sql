-- Stage 2G.4d.2: disposable PG16 authorization epoch pilot ONLY.
-- NEVER deploy this migration to Railway/Core/production.
-- A row-level epoch lock serializes committed changes for one tenant.
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
     OR current_setting('saas.staging_only', true) IS DISTINCT FROM 'true'
     OR current_user <> 'postgres'
     OR NOT EXISTS (SELECT 1 FROM pg_roles
                    WHERE rolname='saas_rls_owner' AND NOT rolsuper AND NOT rolbypassrls) THEN
    RAISE EXCEPTION 'Refusing authorization revision pilot outside ephemeral PG16 CI';
  END IF;
END
$guard$;

-- No FK: retain a tombstone after DELETE, so reusing a tenant ID cannot
-- reset a revision within this disposable database. No real data/keys here.
CREATE TABLE IF NOT EXISTS saas_rls_private.tenant_authorization_revisions (
  tenant_id TEXT PRIMARY KEY,
  revision BIGINT NOT NULL CHECK (revision > 0),
  tenant_active BOOLEAN NOT NULL
);
ALTER TABLE saas_rls_private.tenant_authorization_revisions OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.tenant_authorization_revisions FROM PUBLIC;
REVOKE ALL ON saas_rls_private.tenant_authorization_revisions FROM saas_rls_reader;

-- Replay preserves all existing revision counters and tombstones.
INSERT INTO saas_rls_private.tenant_authorization_revisions
  (tenant_id, revision, tenant_active)
SELECT id, 1, status='active' FROM saas_rls.tenants
ON CONFLICT (tenant_id) DO NOTHING;

CREATE OR REPLACE FUNCTION saas_rls_private.advance_tenant_authorization_revision(
  target_tenant TEXT
) RETURNS VOID
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF target_tenant IS NULL THEN RAISE EXCEPTION 'Missing tenant revision scope'; END IF;
  -- UPDATE locks exactly one epoch row until COMMIT/ROLLBACK. Concurrent
  -- writers for the same tenant cannot silently lose increments.
  UPDATE saas_rls_private.tenant_authorization_revisions
     SET revision = revision + 1 WHERE tenant_id = target_tenant;
  IF NOT FOUND THEN RAISE EXCEPTION 'Missing tenant revision record'; END IF;
END
$fn$;
ALTER FUNCTION saas_rls_private.advance_tenant_authorization_revision(TEXT)
  OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.advance_tenant_authorization_revision(TEXT)
  FROM PUBLIC, saas_rls_reader;

CREATE OR REPLACE FUNCTION saas_rls_private.revise_tenant_status()
RETURNS TRIGGER
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO saas_rls_private.tenant_authorization_revisions AS current_epoch
      (tenant_id, revision, tenant_active)
    VALUES (NEW.id, 1, NEW.status='active')
    ON CONFLICT (tenant_id) DO UPDATE
      SET revision = current_epoch.revision + 1,
          tenant_active = EXCLUDED.tenant_active;
  ELSIF TG_OP = 'DELETE' THEN
    UPDATE saas_rls_private.tenant_authorization_revisions
       SET revision=revision+1, tenant_active=FALSE WHERE tenant_id=OLD.id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Missing deleted tenant revision'; END IF;
  ELSE
    IF NEW.id IS DISTINCT FROM OLD.id THEN
      RAISE EXCEPTION 'Tenant ID change is not supported by revision pilot';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
      UPDATE saas_rls_private.tenant_authorization_revisions
         SET revision=revision+1, tenant_active=(NEW.status='active')
       WHERE tenant_id=NEW.id;
      IF NOT FOUND THEN RAISE EXCEPTION 'Missing changed tenant revision'; END IF;
    END IF;
  END IF;
  RETURN NULL;
END
$fn$;
ALTER FUNCTION saas_rls_private.revise_tenant_status()
  OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.revise_tenant_status()
  FROM PUBLIC, saas_rls_reader;

DROP TRIGGER IF EXISTS saas_tenant_authorization_revision ON saas_rls.tenants;
CREATE TRIGGER saas_tenant_authorization_revision
AFTER INSERT OR UPDATE OR DELETE ON saas_rls.tenants
FOR EACH ROW EXECUTE FUNCTION saas_rls_private.revise_tenant_status();

-- Single implementation for membership and independent Pool/Account/Egress
-- grants. Moves between tenants bump BOTH old and new affected tenants.
CREATE OR REPLACE FUNCTION saas_rls_private.revise_scoped_authorization()
RETURNS TRIGGER
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  previous_tenant TEXT;
  next_tenant TEXT;
  affected_tenant TEXT;
BEGIN
  IF TG_TABLE_NAME = 'memberships' THEN
    IF TG_OP <> 'INSERT' THEN previous_tenant := OLD.tenant_id; END IF;
    IF TG_OP <> 'DELETE' THEN next_tenant := NEW.tenant_id; END IF;
  ELSIF TG_TABLE_NAME = 'resource_grants' THEN
    IF TG_OP <> 'INSERT' THEN previous_tenant := OLD.grantee_tenant_id; END IF;
    IF TG_OP <> 'DELETE' THEN next_tenant := NEW.grantee_tenant_id; END IF;
  ELSE
    RAISE EXCEPTION 'Unexpected authorization revision source';
  END IF;
  -- Deterministic order lowers cross-tenant deadlock risk. Row lock held
  -- to transaction end; failures and rollbacks undo both write and epoch.
  FOR affected_tenant IN
    SELECT DISTINCT t.tenant_id
    FROM (VALUES (previous_tenant), (next_tenant)) AS t(tenant_id)
    WHERE t.tenant_id IS NOT NULL ORDER BY t.tenant_id
  LOOP
    PERFORM saas_rls_private.advance_tenant_authorization_revision(affected_tenant);
  END LOOP;
  RETURN NULL;
END
$fn$;
ALTER FUNCTION saas_rls_private.revise_scoped_authorization()
  OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.revise_scoped_authorization()
  FROM PUBLIC, saas_rls_reader;

DROP TRIGGER IF EXISTS saas_membership_authorization_revision ON saas_rls.memberships;
CREATE TRIGGER saas_membership_authorization_revision
AFTER INSERT OR UPDATE OR DELETE ON saas_rls.memberships
FOR EACH ROW EXECUTE FUNCTION saas_rls_private.revise_scoped_authorization();

DROP TRIGGER IF EXISTS saas_grant_authorization_revision ON saas_rls.resource_grants;
CREATE TRIGGER saas_grant_authorization_revision
AFTER INSERT OR UPDATE OR DELETE ON saas_rls.resource_grants
FOR EACH ROW EXECUTE FUNCTION saas_rls_private.revise_scoped_authorization();

-- A shared resource may affect MULTIPLE grantees without modifying grants.
-- Invalidate its tenant owner (if any) and every explicit grantee.
CREATE OR REPLACE FUNCTION saas_rls_private.revise_catalog_authorization()
RETURNS TRIGGER
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  previous_owner TEXT;
  next_owner TEXT;
  resource_identity TEXT;
  affected_tenant TEXT;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    previous_owner := OLD.owner_tenant_id;
    resource_identity := OLD.id;
  END IF;
  IF TG_OP <> 'DELETE' THEN
    next_owner := NEW.owner_tenant_id;
    IF TG_OP = 'UPDATE' AND NEW.id IS DISTINCT FROM OLD.id THEN
      RAISE EXCEPTION 'Resource ID change is not supported by revision pilot';
    END IF;
    resource_identity := NEW.id;
  END IF;
  IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN
    RETURN NULL;
  END IF;
  FOR affected_tenant IN
    SELECT DISTINCT candidates.tenant_id
    FROM (
      SELECT v.tenant_id FROM (VALUES (previous_owner), (next_owner)) AS v(tenant_id)
      UNION ALL
      SELECT g.grantee_tenant_id
      FROM saas_rls.resource_grants AS g WHERE g.resource_id=resource_identity
    ) AS candidates
    WHERE candidates.tenant_id IS NOT NULL
    ORDER BY candidates.tenant_id
  LOOP
    PERFORM saas_rls_private.advance_tenant_authorization_revision(affected_tenant);
  END LOOP;
  RETURN NULL;
END
$fn$;
ALTER FUNCTION saas_rls_private.revise_catalog_authorization()
  OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.revise_catalog_authorization()
  FROM PUBLIC, saas_rls_reader;

DROP TRIGGER IF EXISTS saas_catalog_authorization_revision ON saas_rls.resource_catalog;
CREATE TRIGGER saas_catalog_authorization_revision
AFTER INSERT OR UPDATE OR DELETE ON saas_rls.resource_catalog
FOR EACH ROW EXECUTE FUNCTION saas_rls_private.revise_catalog_authorization();

-- Only a valid signed actor+tenant+txid, active DB membership, exact role
-- and collection capability can obtain the revision attestation.
-- Do not return raw membership rows or allow direct reader SELECT.
CREATE OR REPLACE FUNCTION saas_rls.authorized_revision(
  expected_tenant TEXT, expected_actor TEXT, expected_role TEXT,
  expected_collection TEXT
) RETURNS TEXT
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT r.revision::TEXT
    FROM saas_rls_private.tenant_authorization_revisions AS r
   WHERE r.tenant_id=expected_tenant AND r.tenant_active
     AND saas_rls.scope_membership_matches(
       expected_tenant, expected_actor, expected_role)
     AND saas_rls.read_allowed(expected_tenant, expected_collection)
$fn$;
ALTER FUNCTION saas_rls.authorized_revision(TEXT,TEXT,TEXT,TEXT)
  OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.authorized_revision(TEXT,TEXT,TEXT,TEXT)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.authorized_revision(TEXT,TEXT,TEXT,TEXT)
  TO saas_rls_reader;

DO $assert$
BEGIN
  IF has_schema_privilege('saas_rls_reader', 'saas_rls_private', 'USAGE')
     OR has_table_privilege('saas_rls_reader',
       'saas_rls_private.tenant_authorization_revisions', 'SELECT')
     OR has_table_privilege('saas_rls_reader',
       'saas_rls_private.tenant_authorization_revisions', 'UPDATE')
     OR NOT has_function_privilege('saas_rls_reader',
       'saas_rls.authorized_revision(text,text,text,text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'Revision isolation ACL is unsafe';
  END IF;
END
$assert$;
COMMIT;
\echo 'PASS: ephemeral transactional tenant authorization revisions installed'
