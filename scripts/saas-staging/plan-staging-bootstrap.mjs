/**
 * Backend 08: read-only plan/preflight for an operator-owned SaaS staging DB.
 *
 * NO psql, network access, SQL execution, migrations, Railway writes, or
 * secret retrieval. The caller must obtain an independent Railway project /
 * backup / credentials review before manually executing a migration.
 */
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

const TARGET = Object.freeze({
  projectId: 'a9703851-6eb1-406c-bb15-7d3a89359fb7',
  environmentId: 'b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b',
  database: 'saas_staging',
  role: 'saas_schema_migrator',
  migration: '0001_ledger_only',
});
const SQL = new URL('../../staging/saas-bootstrap/0001_ledger_only.sql', import.meta.url);
const ROLE_SQL = new URL('../../staging/saas-bootstrap/0000_operator_migrator_role.sql', import.meta.url);
const TENANT_SQL = new URL('../../staging/saas-bootstrap/0002_tenant_projects_baseline.sql', import.meta.url);
const FAIL = 'Backend08 isolated staging migration preflight refused';

function refuse() {
  // No env/URL/credential/error interpolation: logs are safe to share.
  throw new Error(FAIL);
}

function migrationPlan() {
  const bytes = readFileSync(SQL);
  const source = bytes.toString('utf8');
  const roleBytes = readFileSync(ROLE_SQL);
  const roleSource = roleBytes.toString('utf8');
  const tenantBytes = readFileSync(TENANT_SQL);
  const tenantSource = tenantBytes.toString('utf8');
  // Narrow source-shape check, not a general-purpose SQL sanitizer.
  // Only this reviewed file is eligible. No wildcard or pilot directory.
  if (bytes.byteLength < 900 || bytes.byteLength > 12_000 ||
      !source.includes('CREATE SCHEMA saas_bootstrap;') ||
      !source.includes("VALUES ('0001_ledger_only'") ||
      !source.includes('REVOKE ALL ON SCHEMA saas_bootstrap FROM PUBLIC;') ||
      !source.includes('CREATE TRIGGER deny_ledger_change') ||
      /\\(?:i\b|ir\b|include\b)/i.test(source) ||
      roleBytes.byteLength < 1000 || roleBytes.byteLength > 9000 ||
      !roleSource.includes('CREATE ROLE saas_schema_migrator') ||
      !roleSource.includes('NOBYPASSRLS NOCREATEDB NOCREATEROLE') ||
      !roleSource.includes("current_database() NOT IN ('saas_staging', 'saas_staging_ci')") ||
      /\\(?:i\b|ir\b|include\b)/i.test(roleSource) ||
      tenantBytes.byteLength < 2000 || tenantBytes.byteLength > 12000 ||
      !tenantSource.includes('CREATE SCHEMA saas_data AUTHORIZATION saas_schema_migrator;') ||
      !tenantSource.includes('ALTER TABLE saas_data.projects FORCE ROW LEVEL SECURITY;') ||
      !tenantSource.includes('ALTER TABLE saas_data.tenants FORCE ROW LEVEL SECURITY;') ||
      !tenantSource.includes("VALUES ('0002_tenant_projects_baseline'") ||
      /\\(?:i\b|ir\b|include\b)/i.test(tenantSource)) refuse();
  return Object.freeze({
    operation: 'plan-only',
    executionAuthorized: false,
    projectId: TARGET.projectId,
    environmentId: TARGET.environmentId,
    database: TARGET.database,
    requiredPostgresMajor: 16,
    migration: TARGET.migration,
    path: 'staging/saas-bootstrap/0001_ledger_only.sql',
    sha256: createHash('sha256').update(bytes).digest('hex'),
    operatorRoleBootstrap: Object.freeze({
      path: 'staging/saas-bootstrap/0000_operator_migrator_role.sql',
      sha256: createHash('sha256').update(roleBytes).digest('hex'),
      executionAuthorized: false,
      mode: 'manual-operator-only-after-verified-backup',
      login: TARGET.role,
    }),
    creates: ['saas_bootstrap.schema_migrations'],
    tenantProjectsBaseline: Object.freeze({
      path: 'staging/saas-bootstrap/0002_tenant_projects_baseline.sql',
      sha256: createHash('sha256').update(tenantBytes).digest('hex'),
      migration: '0002_tenant_projects_baseline',
      priorRequiredSha256: createHash('sha256').update(bytes).digest('hex'),
      executionAuthorized: false,
      creates: ['saas_data.tenants', 'saas_data.projects'],
      rls: 'force-enabled-with-zero-policies-deny-all',
    }),
    forbidden: ['staging/saas-rls/001-027', 'SQL019', 'Core/Gateway databases'],
    approval: 'independent-security-ops-and-backup-restore-required',
  });
}

function checkStagingContext(env) {
  // Configuration checks are necessary but NOT an identity attestation.
  // The operator must separately inspect Railway resource IDs and roles.
  if (!env || env.GITHUB_ACTIONS === 'true' ||
      env.SAAS_MIGRATION_PLAN_ONLY !== 'true' ||
      env.SAAS_MIGRATION_TARGET_PROFILE !== 'isolated-staging' ||
      env.RAILWAY_PROJECT_ID !== TARGET.projectId ||
      env.RAILWAY_ENVIRONMENT_ID !== TARGET.environmentId ||
      env.RAILWAY_ENVIRONMENT_NAME !== 'staging' ||
      env.PGDATABASE !== TARGET.database ||
      env.PGUSER !== TARGET.role ||
      env.PGPORT !== '5432' ||
      typeof env.PGHOST !== 'string' ||
      env.PGHOST.length > 180 ||
      !/^[a-z0-9-]+\.railway\.internal$/.test(env.PGHOST) ||
      env.PGHOST.includes('cliproxyapi-core') ||
      env.PGHOST.includes('api-gateway')) refuse();
  return Object.freeze({
    targetMatchesPinnedStaging: true,
    executionAuthorized: false,
    confirmation: 'environment-strings-only-not-Railway-identity-proof',
  });
}

function main(args, env) {
  if (args.length !== 1) refuse();
  if (args[0] === '--plan') return migrationPlan();
  if (args[0] === '--check-staging-context') {
    return {...migrationPlan(), ...checkStagingContext(env)};
  }
  return refuse();
}

try {
  process.stdout.write(JSON.stringify(main(process.argv.slice(2), process.env)) + '\n');
} catch {
  process.stderr.write(FAIL + '\n');
  process.exitCode = 1;
}
