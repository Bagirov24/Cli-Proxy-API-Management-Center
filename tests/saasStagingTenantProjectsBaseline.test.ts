import {describe, expect, test} from 'bun:test';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const SQL = new URL('../staging/saas-bootstrap/0002_tenant_projects_baseline.sql', import.meta.url);
const PRIOR = new URL('../staging/saas-bootstrap/0001_ledger_only.sql', import.meta.url);
const PLAN = new URL('../scripts/saas-staging/plan-staging-bootstrap.mjs', import.meta.url);
const SECRET = 'UNIT_TEST_FAKE_DB_PASSWORD_NO_LOG';

function plan(arg: string) {
  const r = spawnSync('node', [fileURLToPath(PLAN), arg], {
    encoding: 'utf8',
    env: {...process.env, DATABASE_URL: SECRET, PGPASSWORD: SECRET},
    timeout: 8000,
  });
  return {status: r.status, stdout: r.stdout, stderr: r.stderr};
}

describe('Backend10 permanent SaaS tenant/project baseline remains deny-all', () => {
  test('read-only offline plan pins exact migration bytes without apply capability', () => {
    const r = plan('--plan');
    expect(r.status).toBe(0);
    const p = JSON.parse(r.stdout);
    expect(p.executionAuthorized).toBe(false);
    expect(p.tenantProjectsBaseline).toEqual({
      path: 'staging/saas-bootstrap/0002_tenant_projects_baseline.sql',
      sha256: createHash('sha256').update(readFileSync(SQL)).digest('hex'),
      migration: '0002_tenant_projects_baseline',
      priorRequiredSha256: createHash('sha256').update(readFileSync(PRIOR)).digest('hex'),
      executionAuthorized: false,
      creates: ['saas_data.tenants', 'saas_data.projects'],
      rls: 'force-enabled-with-zero-policies-deny-all',
    });
    expect(r.stdout + r.stderr).not.toContain(SECRET);
  });

  test('exact staging PG16 migrator and previous checksum are required', () => {
    const sql = readFileSync(SQL, 'utf8');
    expect(sql).toContain("current_database() NOT IN ('saas_staging', 'saas_staging_ci')");
    expect(sql).toContain("session_user <> 'saas_schema_migrator'");
    expect(sql).toContain("current_setting('saas.staging_only', true)");
    expect(sql).toContain('saas_bootstrap.schema_migrations');
    expect(sql).toContain(":'expected_0001_sha256'");
    expect(sql).toContain(":'migration_sha256'");
    expect(sql).toContain(":'source_commit'");
    expect(sql).toContain('CREATE SCHEMA saas_data AUTHORIZATION saas_schema_migrator');
  });

  test('no runtime grants, no policies, no pilot imports, no auth defaults', () => {
    const sql = readFileSync(SQL, 'utf8');
    expect(sql).toContain('ALTER TABLE saas_data.tenants FORCE ROW LEVEL SECURITY');
    expect(sql).toContain('ALTER TABLE saas_data.projects FORCE ROW LEVEL SECURITY');
    expect(sql).toContain('REVOKE ALL ON ALL TABLES IN SCHEMA saas_data FROM PUBLIC');
    expect(sql).toContain('REFERENCES saas_data.tenants(tenant_id)');
    expect(sql).toContain('ON DELETE RESTRICT');
    expect(sql).not.toMatch(/\bCREATE\s+POLICY\b/i);
    expect(sql).not.toMatch(/\bGRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|USAGE|EXECUTE)\b/i);
    expect(sql).not.toMatch(/\bCREATE\s+ROLE\b/i);
    expect(sql).not.toMatch(/\bSECURITY\s+DEFINER\b/i);
    expect(sql).not.toMatch(/\\(?:i|ir|include)\s+.*saas-rls/i);
    expect(sql).not.toMatch(/\bsaas_core\b|\bapi_gateway\b/i);
  });

  test('planner refuses any live execution verb', () => {
    for (const arg of ['--apply', '--execute', '--deploy', '--write']) {
      const r = plan(arg);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain('preflight refused');
      expect(r.stdout + r.stderr).not.toContain(SECRET);
    }
  });
});
