-- Backend10: persistent SaaS tenant/project BASELINE, default DENY ALL.
-- Isolated PostgreSQL16 staging only. Not pilot SQL001-027, not SQL019.
-- No runtime table privileges, RLS policies, credentials, audit bypass or data.
-- One-shot operator-owned MIGRATOR ONLY, after 0000 and 0001.
-- Operator must approve the reviewed exact file SHA256 and source commit;
-- after an UNKNOWN COMMIT, reconcile catalog + ledger: NEVER auto-retry.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL statement_timeout = '20s';
SET LOCAL lock_timeout = '3s';
SET LOCAL search_path = pg_catalog, pg_temp;
-- Reviewed public digests only. Psql variables cannot expand inside DO bodies.
SELECT pg_catalog.set_config('saas.baseline_expected_0001', :'expected_0001_sha256', true);
SELECT pg_catalog.set_config('saas.baseline_source_sha256', :'migration_sha256', true);
SELECT pg_catalog.set_config('saas.baseline_source_commit', :'source_commit', true);

DO $guard$
DECLARE
  prior_count bigint;
  prior_hash text;
  migrator record;
BEGIN
  IF current_setting('server_version_num')::integer < 160000 OR
     current_setting('server_version_num')::integer >= 170000 OR
     current_database() NOT IN ('saas_staging', 'saas_staging_ci') OR
     current_setting('saas.staging_only', true) IS DISTINCT FROM 'true' OR
     pg_is_in_recovery() OR current_setting('transaction_read_only') <> 'off' OR
     session_user <> 'saas_schema_migrator' THEN
    RAISE EXCEPTION 'Backend10 refused non-isolated/non-migrator PostgreSQL16 context';
  END IF;
  SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb
    INTO migrator FROM pg_catalog.pg_roles WHERE rolname = session_user;
  IF NOT FOUND OR migrator.rolsuper OR migrator.rolbypassrls OR
     migrator.rolcreaterole OR migrator.rolcreatedb THEN
    RAISE EXCEPTION 'Backend10 refused privileged migration login';
  END IF;
  IF to_regnamespace('saas_bootstrap') IS NULL OR
     to_regclass('saas_bootstrap.schema_migrations') IS NULL OR
     to_regnamespace('saas_data') IS NOT NULL OR
     to_regnamespace('saas_rls') IS NOT NULL OR
     to_regnamespace('saas_rls_private') IS NOT NULL OR
     to_regnamespace('saas_m1_private') IS NOT NULL OR
     to_regnamespace('saas_m1_api') IS NOT NULL THEN
    RAISE EXCEPTION 'Backend10 refused absent ledger or preexisting/pilot schema';
  END IF;
  SELECT COUNT(*), MIN(source_sha256)
    INTO prior_count, prior_hash
    FROM saas_bootstrap.schema_migrations;
  IF prior_count <> 1 OR NOT EXISTS (
       SELECT 1 FROM saas_bootstrap.schema_migrations
       WHERE migration_id = '0001_ledger_only'
     ) OR
     prior_hash IS DISTINCT FROM current_setting('saas.baseline_expected_0001', true) OR
     current_setting('saas.baseline_expected_0001', true) !~ '^[a-f0-9]{64}$' THEN
    RAISE EXCEPTION 'Backend10 refused untrusted migration history';
  END IF;
  IF current_setting('saas.baseline_source_sha256', true) !~ '^[a-f0-9]{64}$' OR
     current_setting('saas.baseline_source_commit', true) !~ '^[a-f0-9]{40}$' THEN
    RAISE EXCEPTION 'Backend10 refused invalid source attestation';
  END IF;
END
$guard$;

-- A separate schema, never public and never the CI-only saas_rls pilot.
CREATE SCHEMA saas_data AUTHORIZATION saas_schema_migrator;
REVOKE ALL ON SCHEMA saas_data FROM PUBLIC;

CREATE TABLE saas_data.tenants (
  tenant_id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  tenant_key text NOT NULL UNIQUE
    CHECK (tenant_key ~ '^[a-z][a-z0-9_-]{2,62}$'),
  display_name text NOT NULL
    CHECK (pg_catalog.char_length(pg_catalog.btrim(display_name)) BETWEEN 1 AND 160),
  lifecycle text NOT NULL DEFAULT 'active'
    CHECK (lifecycle IN ('active', 'suspended')),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE saas_data.projects (
  project_id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES saas_data.tenants(tenant_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  project_key text NOT NULL
    CHECK (project_key ~ '^[a-z][a-z0-9_-]{2,62}$'),
  display_name text NOT NULL
    CHECK (pg_catalog.char_length(pg_catalog.btrim(display_name)) BETWEEN 1 AND 160),
  lifecycle text NOT NULL DEFAULT 'active'
    CHECK (lifecycle IN ('active', 'suspended')),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT projects_tenant_key_unique UNIQUE (tenant_id, project_key),
  CONSTRAINT projects_tenant_id_unique UNIQUE (tenant_id, project_id)
);

-- NO policies deliberately: even the table OWNER is denied SELECT/WRITE
-- by FORCE RLS. A future separate migration must introduce a signed scope
-- verifier and narrowly granted security-definer functions only after review.
ALTER TABLE saas_data.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_data.tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE saas_data.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_data.projects FORCE ROW LEVEL SECURITY;

REVOKE ALL ON ALL TABLES IN SCHEMA saas_data FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE saas_schema_migrator
  IN SCHEMA saas_data REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE saas_schema_migrator
  IN SCHEMA saas_data REVOKE ALL ON FUNCTIONS FROM PUBLIC;

COMMENT ON SCHEMA saas_data IS
  'SaaS staging-only tenant/project catalog; no runtime grants or RLS policies';
COMMENT ON TABLE saas_data.tenants IS
  'Baseline only. FORCE RLS with zero policies: no application reads/writes';
COMMENT ON TABLE saas_data.projects IS
  'Baseline only. Tenant FK, optimistic revision; RLS denies all until signed policy';

-- Atomic with CREATE TABLE. Unknown COMMIT is manually reconciled, not replayed.
INSERT INTO saas_bootstrap.schema_migrations
  (migration_id, source_sha256, source_commit)
VALUES ('0002_tenant_projects_baseline', :'migration_sha256', :'source_commit');

COMMIT;
