-- 2G.4d.4a: epoch coverage for all metadata projection dependencies.
-- Disposable PG16 saas_ephemeral_test ONLY. No Railway or production migrations.
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
     OR current_user <> 'postgres'
     OR current_setting('saas.staging_only', TRUE) IS DISTINCT FROM 'true'
     OR NOT EXISTS (SELECT 1 FROM pg_roles
                    WHERE rolname='saas_rls_owner' AND NOT rolsuper AND NOT rolbypassrls)
     OR to_regclass('saas_rls_private.tenant_authorization_revisions') IS NULL THEN
    RAISE EXCEPTION 'Refusing SaaS revision coverage migration outside disposable CI';
  END IF;
END
$guard$;

-- Project/application/key-binding/routing writes can alter safe metadata,
-- visibility via joins, and pool-routing relationships even when the
-- caller's LIMIT masks them. Bump BOTH tenants on tenant-id relocation.
CREATE OR REPLACE FUNCTION saas_rls_private.revise_tenant_projection()
RETURNS TRIGGER
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  old_tenant TEXT;
  new_tenant TEXT;
  affected_tenant TEXT;
BEGIN
  IF TG_TABLE_NAME NOT IN ('projects','applications','key_bindings','routing_bindings') THEN
    RAISE EXCEPTION 'Unexpected tenant projection revision source';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
  IF TG_OP <> 'INSERT' THEN old_tenant := OLD.tenant_id; END IF;
  IF TG_OP <> 'DELETE' THEN new_tenant := NEW.tenant_id; END IF;
  FOR affected_tenant IN
    SELECT DISTINCT v.tenant_id
    FROM (VALUES (old_tenant), (new_tenant)) AS v(tenant_id)
    WHERE v.tenant_id IS NOT NULL ORDER BY v.tenant_id
  LOOP
    PERFORM saas_rls_private.advance_tenant_authorization_revision(affected_tenant);
  END LOOP;
  RETURN NULL;
END
$fn$;
ALTER FUNCTION saas_rls_private.revise_tenant_projection()
  OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.revise_tenant_projection()
  FROM PUBLIC, saas_rls_reader;

DROP TRIGGER IF EXISTS saas_project_epoch ON saas_rls.projects;
CREATE TRIGGER saas_project_epoch
AFTER INSERT OR UPDATE OR DELETE ON saas_rls.projects
FOR EACH ROW EXECUTE FUNCTION saas_rls_private.revise_tenant_projection();

DROP TRIGGER IF EXISTS saas_application_epoch ON saas_rls.applications;
CREATE TRIGGER saas_application_epoch
AFTER INSERT OR UPDATE OR DELETE ON saas_rls.applications
FOR EACH ROW EXECUTE FUNCTION saas_rls_private.revise_tenant_projection();

DROP TRIGGER IF EXISTS saas_key_binding_epoch ON saas_rls.key_bindings;
CREATE TRIGGER saas_key_binding_epoch
AFTER INSERT OR UPDATE OR DELETE ON saas_rls.key_bindings
FOR EACH ROW EXECUTE FUNCTION saas_rls_private.revise_tenant_projection();

DROP TRIGGER IF EXISTS saas_routing_binding_epoch ON saas_rls.routing_bindings;
CREATE TRIGGER saas_routing_binding_epoch
AFTER INSERT OR UPDATE OR DELETE ON saas_rls.routing_bindings
FOR EACH ROW EXECUTE FUNCTION saas_rls_private.revise_tenant_projection();

-- A pool-account / account-egress link can be visible to multiple tenants
-- via independently granted endpoints. Invalidate the union of all
-- endpoint owners and grantees, for BOTH old and new endpoints on UPDATE.
-- This over-invalidates where a grant is expired, which is safely strict.
CREATE OR REPLACE FUNCTION saas_rls_private.revise_resource_link()
RETURNS TRIGGER
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  old_from TEXT;
  old_to TEXT;
  new_from TEXT;
  new_to TEXT;
  affected_tenant TEXT;
BEGIN
  IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
  IF TG_OP <> 'INSERT' THEN
    old_from := OLD.from_id;
    old_to := OLD.to_id;
  END IF;
  IF TG_OP <> 'DELETE' THEN
    new_from := NEW.from_id;
    new_to := NEW.to_id;
  END IF;
  FOR affected_tenant IN
    SELECT DISTINCT affected.tenant_id
    FROM (
      SELECT c.owner_tenant_id AS tenant_id
        FROM saas_rls.resource_catalog AS c
       WHERE c.id IN (old_from, old_to, new_from, new_to)
      UNION ALL
      SELECT g.grantee_tenant_id AS tenant_id
        FROM saas_rls.resource_grants AS g
       WHERE g.resource_id IN (old_from, old_to, new_from, new_to)
    ) AS affected
    WHERE affected.tenant_id IS NOT NULL
    ORDER BY affected.tenant_id
  LOOP
    PERFORM saas_rls_private.advance_tenant_authorization_revision(affected_tenant);
  END LOOP;
  RETURN NULL;
END
$fn$;
ALTER FUNCTION saas_rls_private.revise_resource_link()
  OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.revise_resource_link()
  FROM PUBLIC, saas_rls_reader;

DROP TRIGGER IF EXISTS saas_resource_link_epoch ON saas_rls.resource_links;
CREATE TRIGGER saas_resource_link_epoch
AFTER INSERT OR UPDATE OR DELETE ON saas_rls.resource_links
FOR EACH ROW EXECUTE FUNCTION saas_rls_private.revise_resource_link();

DO $assert$
BEGIN
  IF has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
    OR has_table_privilege('saas_rls_reader',
        'saas_rls_private.tenant_authorization_revisions','SELECT')
    OR has_function_privilege('saas_rls_reader',
        'saas_rls_private.revise_resource_link()', 'EXECUTE') THEN
    RAISE EXCEPTION 'Revision coverage must not expose private writer state';
  END IF;
END
$assert$;
COMMIT;
\echo 'PASS: staging epoch tracks project/app/key/routing and shared resource links'
