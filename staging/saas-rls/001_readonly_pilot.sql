-- Staging-only PostgreSQL 16 RLS proof; NEVER apply to Railway production.
-- Explicit guard (not an access-control substitute) is set by the ephemeral CI SQL test.
BEGIN;
DO $guard$
BEGIN
  IF current_setting('saas.staging_only', true) IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'Refusing SaaS RLS migration outside explicit ephemeral staging test';
  END IF;
END
$guard$;

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_rls_owner') THEN
    CREATE ROLE saas_rls_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_rls_reader') THEN
    CREATE ROLE saas_rls_reader NOLOGIN;
  END IF;
END
$roles$;
ALTER ROLE saas_rls_owner NOLOGIN NOBYPASSRLS;
ALTER ROLE saas_rls_reader NOLOGIN NOBYPASSRLS;

CREATE SCHEMA IF NOT EXISTS saas_rls AUTHORIZATION saas_rls_owner;
REVOKE ALL ON SCHEMA saas_rls FROM PUBLIC;
GRANT USAGE ON SCHEMA saas_rls TO saas_rls_reader;

-- Private authorization state: no SELECT grant to the HTTP/query reader.
CREATE TABLE IF NOT EXISTS saas_rls.tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'disabled'))
);
CREATE TABLE IF NOT EXISTS saas_rls.memberships (
  actor_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES saas_rls.tenants(id),
  role TEXT NOT NULL CHECK (role IN (
    'tenant-owner', 'tenant-admin', 'tenant-viewer', 'tenant-auditor'
  )),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  PRIMARY KEY (actor_id, tenant_id)
);

-- Tenant-scoped resources, no credentials/secret handles or real egress URLs.
CREATE TABLE IF NOT EXISTS saas_rls.projects (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES saas_rls.tenants(id),
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled'))
);
CREATE TABLE IF NOT EXISTS saas_rls.applications (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES saas_rls.tenants(id),
  project_id TEXT NOT NULL REFERENCES saas_rls.projects(id),
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled'))
);
CREATE TABLE IF NOT EXISTS saas_rls.key_bindings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES saas_rls.tenants(id),
  application_id TEXT NOT NULL REFERENCES saas_rls.applications(id),
  key_kind TEXT NOT NULL CHECK (key_kind IN ('cpa', 'core-native')),
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled'))
);

CREATE TABLE IF NOT EXISTS saas_rls.resource_catalog (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('pool', 'account', 'egress')),
  owner_kind TEXT NOT NULL CHECK (owner_kind IN ('tenant', 'platform')),
  owner_tenant_id TEXT REFERENCES saas_rls.tenants(id),
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'blocked')),
  CONSTRAINT owner_consistency CHECK (
    (owner_kind = 'tenant' AND owner_tenant_id IS NOT NULL) OR
    (owner_kind = 'platform' AND owner_tenant_id IS NULL)
  )
);

CREATE TABLE IF NOT EXISTS saas_rls.resource_grants (
  id TEXT PRIMARY KEY,
  resource_id TEXT NOT NULL REFERENCES saas_rls.resource_catalog(id),
  resource_kind TEXT NOT NULL CHECK (resource_kind IN ('pool', 'account', 'egress')),
  grantee_tenant_id TEXT NOT NULL REFERENCES saas_rls.tenants(id),
  owner_kind TEXT NOT NULL CHECK (owner_kind IN ('tenant', 'platform')),
  owner_tenant_id TEXT REFERENCES saas_rls.tenants(id),
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  expires_at TIMESTAMPTZ,
  CONSTRAINT grant_owner_consistency CHECK (
    (owner_kind = 'tenant' AND owner_tenant_id IS NOT NULL) OR
    (owner_kind = 'platform' AND owner_tenant_id IS NULL)
  )
);
CREATE INDEX IF NOT EXISTS idx_saas_rls_active_grants ON saas_rls.resource_grants
  (grantee_tenant_id, resource_kind, resource_id, status);

-- Link rows are visible ONLY when BOTH independently granted resources
-- can be read: pool membership never implies account / egress access.
CREATE TABLE IF NOT EXISTS saas_rls.resource_links (
  id TEXT PRIMARY KEY,
  link_kind TEXT NOT NULL CHECK (link_kind IN ('pool-account', 'account-egress')),
  from_id TEXT NOT NULL REFERENCES saas_rls.resource_catalog(id),
  to_id TEXT NOT NULL REFERENCES saas_rls.resource_catalog(id),
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled'))
);

CREATE TABLE IF NOT EXISTS saas_rls.routing_bindings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES saas_rls.tenants(id),
  application_id TEXT NOT NULL REFERENCES saas_rls.applications(id),
  key_binding_id TEXT NOT NULL REFERENCES saas_rls.key_bindings(id),
  pool_id TEXT NOT NULL REFERENCES saas_rls.resource_catalog(id),
  provider_id TEXT NOT NULL,
  requested_model_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  egress_policy TEXT NOT NULL CHECK (egress_policy IN ('required', 'direct-explicit'))
);

-- Each DB session scope is written ONLY after server session verification.
-- These GUCs are NOT proof of authentication: never expose arbitrary SQL
-- or let a client control the actor/tenant settings.
CREATE OR REPLACE FUNCTION saas_rls.scope_tenant() RETURNS TEXT
LANGUAGE sql STABLE
AS $fn$ SELECT NULLIF(current_setting('saas.tenant_id', true), '') $fn$;

CREATE OR REPLACE FUNCTION saas_rls.read_allowed(
  target_tenant TEXT, resource_collection TEXT
) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, saas_rls
AS $fn$
  SELECT EXISTS (
    SELECT 1 FROM saas_rls.memberships AS m
    WHERE m.actor_id = NULLIF(current_setting('saas.actor_id', true), '')
      AND m.tenant_id = target_tenant
      AND m.tenant_id = NULLIF(current_setting('saas.tenant_id', true), '')
      AND m.status = 'active'
      AND (
        m.role IN ('tenant-owner', 'tenant-admin', 'tenant-viewer')
        OR (m.role = 'tenant-auditor'
            AND resource_collection IN ('tenant', 'projects', 'applications'))
      )
  )
$fn$;

CREATE OR REPLACE FUNCTION saas_rls.resource_granted(
  resource_kind TEXT, resource_id TEXT, owner_kind TEXT, owner_tenant_id TEXT
) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, saas_rls
AS $fn$
  SELECT CASE
    WHEN $3 = 'tenant'
      AND $4 = NULLIF(current_setting('saas.tenant_id', true), '')
      THEN TRUE
    ELSE EXISTS (
      SELECT 1 FROM saas_rls.resource_grants AS g
      WHERE g.resource_id = $2
        AND g.resource_kind = $1
        AND g.grantee_tenant_id = NULLIF(current_setting('saas.tenant_id', true), '')
        AND g.owner_kind = $3
        AND g.owner_tenant_id IS NOT DISTINCT FROM $4
        AND g.status = 'active'
        AND (g.expires_at IS NULL OR g.expires_at > statement_timestamp())
    )
  END
$fn$;

-- Never run private definer functions as the postgres superuser.
ALTER TABLE saas_rls.tenants OWNER TO saas_rls_owner;
ALTER TABLE saas_rls.memberships OWNER TO saas_rls_owner;
ALTER TABLE saas_rls.projects OWNER TO saas_rls_owner;
ALTER TABLE saas_rls.applications OWNER TO saas_rls_owner;
ALTER TABLE saas_rls.key_bindings OWNER TO saas_rls_owner;
ALTER TABLE saas_rls.resource_catalog OWNER TO saas_rls_owner;
ALTER TABLE saas_rls.resource_grants OWNER TO saas_rls_owner;
ALTER TABLE saas_rls.resource_links OWNER TO saas_rls_owner;
ALTER TABLE saas_rls.routing_bindings OWNER TO saas_rls_owner;
ALTER FUNCTION saas_rls.scope_tenant() OWNER TO saas_rls_owner;
ALTER FUNCTION saas_rls.read_allowed(TEXT, TEXT) OWNER TO saas_rls_owner;
ALTER FUNCTION saas_rls.resource_granted(TEXT, TEXT, TEXT, TEXT) OWNER TO saas_rls_owner;

REVOKE ALL ON ALL TABLES IN SCHEMA saas_rls FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA saas_rls FROM saas_rls_reader;
REVOKE ALL ON FUNCTION saas_rls.scope_tenant() FROM PUBLIC;
REVOKE ALL ON FUNCTION saas_rls.read_allowed(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION saas_rls.resource_granted(TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.scope_tenant() TO saas_rls_reader;
GRANT EXECUTE ON FUNCTION saas_rls.read_allowed(TEXT, TEXT) TO saas_rls_reader;
GRANT EXECUTE ON FUNCTION saas_rls.resource_granted(TEXT, TEXT, TEXT, TEXT) TO saas_rls_reader;

-- Reader has no write, memberships or raw grants privilege.
GRANT SELECT ON saas_rls.tenants, saas_rls.projects,
  saas_rls.applications, saas_rls.key_bindings,
  saas_rls.resource_catalog, saas_rls.resource_links,
  saas_rls.routing_bindings TO saas_rls_reader;

-- FORCE blocks table-owner RLS bypass; owner only creates fixtures in CI
-- via postgres superuser, never through the read role.
ALTER TABLE saas_rls.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_rls.tenants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS read_tenants ON saas_rls.tenants;
CREATE POLICY read_tenants ON saas_rls.tenants FOR SELECT TO saas_rls_reader
USING (
  id = saas_rls.scope_tenant() AND status = 'active'
  AND saas_rls.read_allowed(id, 'tenant')
);

ALTER TABLE saas_rls.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_rls.projects FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS read_projects ON saas_rls.projects;
CREATE POLICY read_projects ON saas_rls.projects FOR SELECT TO saas_rls_reader
USING (
  tenant_id = saas_rls.scope_tenant()
  AND saas_rls.read_allowed(tenant_id, 'projects')
  AND EXISTS (SELECT 1 FROM saas_rls.tenants AS t WHERE t.id = tenant_id)
);

ALTER TABLE saas_rls.applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_rls.applications FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS read_applications ON saas_rls.applications;
CREATE POLICY read_applications ON saas_rls.applications FOR SELECT TO saas_rls_reader
USING (
  tenant_id = saas_rls.scope_tenant()
  AND saas_rls.read_allowed(tenant_id, 'applications')
  AND EXISTS (
    SELECT 1 FROM saas_rls.projects AS p
    WHERE p.id = project_id AND p.tenant_id = tenant_id
  )
);

ALTER TABLE saas_rls.key_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_rls.key_bindings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS read_cpa_keys ON saas_rls.key_bindings;
CREATE POLICY read_cpa_keys ON saas_rls.key_bindings FOR SELECT TO saas_rls_reader
USING (
  key_kind = 'cpa'
  AND tenant_id = saas_rls.scope_tenant()
  AND saas_rls.read_allowed(tenant_id, 'client-keys')
  AND EXISTS (
    SELECT 1 FROM saas_rls.applications AS a
    WHERE a.id = application_id AND a.tenant_id = tenant_id
  )
);

ALTER TABLE saas_rls.resource_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_rls.resource_catalog FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS read_resources ON saas_rls.resource_catalog;
CREATE POLICY read_resources ON saas_rls.resource_catalog FOR SELECT TO saas_rls_reader
USING (
  saas_rls.read_allowed(saas_rls.scope_tenant(), 'resources')
  AND EXISTS (SELECT 1 FROM saas_rls.tenants AS t WHERE t.id = saas_rls.scope_tenant())
  AND saas_rls.resource_granted(kind, id, owner_kind, owner_tenant_id)
);

ALTER TABLE saas_rls.resource_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_rls.resource_links FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS read_links ON saas_rls.resource_links;
CREATE POLICY read_links ON saas_rls.resource_links FOR SELECT TO saas_rls_reader
USING (
  status = 'active'
  AND saas_rls.read_allowed(saas_rls.scope_tenant(), 'resources')
  AND EXISTS (SELECT 1 FROM saas_rls.resource_catalog AS a
              WHERE a.id = from_id AND
                ((link_kind = 'pool-account' AND a.kind = 'pool') OR
                 (link_kind = 'account-egress' AND a.kind = 'account')))
  AND EXISTS (SELECT 1 FROM saas_rls.resource_catalog AS b
              WHERE b.id = to_id AND
                ((link_kind = 'pool-account' AND b.kind = 'account') OR
                 (link_kind = 'account-egress' AND b.kind = 'egress')))
);

ALTER TABLE saas_rls.routing_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_rls.routing_bindings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS read_routing ON saas_rls.routing_bindings;
CREATE POLICY read_routing ON saas_rls.routing_bindings FOR SELECT TO saas_rls_reader
USING (
  tenant_id = saas_rls.scope_tenant()
  AND saas_rls.read_allowed(tenant_id, 'routing')
  AND EXISTS (SELECT 1 FROM saas_rls.applications AS a
              WHERE a.id = application_id AND a.tenant_id = tenant_id)
  AND EXISTS (SELECT 1 FROM saas_rls.key_bindings AS k
              WHERE k.id = key_binding_id AND k.tenant_id = tenant_id)
  AND EXISTS (SELECT 1 FROM saas_rls.resource_catalog AS p
              WHERE p.id = pool_id AND p.kind = 'pool')
);

COMMIT;
