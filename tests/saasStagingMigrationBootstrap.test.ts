import {describe, expect, test} from 'bun:test';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const PROGRAM = new URL('../scripts/saas-staging/plan-staging-bootstrap.mjs', import.meta.url);
const SQL = new URL('../staging/saas-bootstrap/0001_ledger_only.sql', import.meta.url);
const SECRET = 'SENSITIVE_DB_PASSWORD_NOT_FOR_LOGS';

function run(command: string, changes: Record<string, string | undefined> = {}) {
  const env = {...process.env, DATABASE_URL: SECRET, PGPASSWORD: SECRET, ...changes};
  const result = spawnSync('node', [fileURLToPath(PROGRAM), command], {
    encoding: 'utf8', env, timeout: 8000,
  });
  return {status: result.status, stdout: result.stdout, stderr: result.stderr};
}

const context = {
  GITHUB_ACTIONS: 'false',
  SAAS_MIGRATION_PLAN_ONLY: 'true',
  SAAS_MIGRATION_TARGET_PROFILE: 'isolated-staging',
  RAILWAY_PROJECT_ID: 'a9703851-6eb1-406c-bb15-7d3a89359fb7',
  RAILWAY_ENVIRONMENT_ID: 'b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b',
  RAILWAY_ENVIRONMENT_NAME: 'staging',
  PGDATABASE: 'saas_staging',
  PGUSER: 'saas_schema_migrator',
  PGPORT: '5432',
  PGHOST: 'saas-postgres.railway.internal',
};

describe('Backend08 isolated staging bootstrap: plan and closed-by-default', () => {
  test('read-only plan returns exact source SHA256 with no execute capability', () => {
    const out = run('--plan');
    expect(out.status).toBe(0);
    const result = JSON.parse(out.stdout);
    expect(result.operation).toBe('plan-only');
    expect(result.executionAuthorized).toBe(false);
    expect(result.requiredPostgresMajor).toBe(16);
    expect(result.path).toBe('staging/saas-bootstrap/0001_ledger_only.sql');
    expect(result.sha256).toBe(
      createHash('sha256').update(readFileSync(SQL)).digest('hex')
    );
    expect(result.forbidden).toContain('SQL019');
    expect(out.stdout + out.stderr).not.toContain(SECRET);
  });

  test('refuses malformed argument and every unrelated deployment context', () => {
    const badArgs = run('--apply', context);
    expect(badArgs.status).not.toBe(0);
    expect(badArgs.stderr).toContain('preflight refused');
    expect(badArgs.stderr).not.toContain(SECRET);

    for (const [field, value] of Object.entries({
      GITHUB_ACTIONS: 'true',
      SAAS_MIGRATION_PLAN_ONLY: 'false',
      SAAS_MIGRATION_TARGET_PROFILE: 'production',
      RAILWAY_PROJECT_ID: 'bd565370-7321-4dba-908a-412186b1b986',
      RAILWAY_ENVIRONMENT_ID: '1ae8fb62-814e-4a37-bdde-383b9f8a8740',
      RAILWAY_ENVIRONMENT_NAME: 'production',
      PGDATABASE: 'railway',
      PGUSER: 'postgres',
      PGPORT: '6432',
      PGHOST: 'cliproxyapi-core.railway.internal',
    })) {
      const out = run('--check-staging-context', {...context, [field]: value});
      expect(out.status).not.toBe(0);
      expect(out.stderr).toContain('preflight refused');
      expect(out.stdout + out.stderr).not.toContain(SECRET);
    }
  });

  test('even pinned staging identity returns a plan, never an execution', () => {
    const out = run('--check-staging-context', context);
    expect(out.status).toBe(0);
    const result = JSON.parse(out.stdout);
    expect(result.targetMatchesPinnedStaging).toBe(true);
    expect(result.executionAuthorized).toBe(false);
    expect(result.confirmation).toContain('not-Railway-identity-proof');
    expect(out.stdout + out.stderr).not.toContain(SECRET);
  });

  test('bootstrap SQL cannot import old pilot schemas or issue app credentials', () => {
    const text = readFileSync(SQL, 'utf8');
    expect(text).toContain("current_database() NOT IN ('saas_staging', 'saas_staging_ci')");
    expect(text).toContain('session_user');
    expect(text).toContain('REVOKE ALL ON SCHEMA saas_bootstrap FROM PUBLIC');
    expect(text).toContain('BEFORE UPDATE OR DELETE');
    expect(text).not.toMatch(/\\(?:i|ir)\s+staging\/saas-rls/);
    expect(text).not.toMatch(/CREATE\s+ROLE|ALTER\s+ROLE|GRANT\s+saas_m1_/i);
  });
});
