import {describe, expect, test} from 'bun:test';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const OPERATOR = new URL('../staging/saas-bootstrap/0000_operator_migrator_role.sql', import.meta.url);
const PLANNER = new URL('../scripts/saas-staging/plan-staging-bootstrap.mjs', import.meta.url);
const forbiddenSecret = 'FAKE_TEST_PASSWORD_DO_NOT_LOG';

function plan(arg: string) {
  const result = spawnSync('node', [fileURLToPath(PLANNER), arg], {
    encoding: 'utf8',
    timeout: 7000,
    env: {...process.env, PGPASSWORD: forbiddenSecret, DATABASE_URL: forbiddenSecret},
  });
  return {code: result.status, stdout: result.stdout, stderr: result.stderr};
}

describe('Backend09 operator-only PostgreSQL16 migrator role prebootstrap', () => {
  test('offline plan pins 0000 role SQL by exact SHA256 without an execution path', () => {
    const result = plan('--plan');
    expect(result.code).toBe(0);
    const body = JSON.parse(result.stdout);
    expect(body.executionAuthorized).toBe(false);
    expect(body.operatorRoleBootstrap).toEqual({
      path: 'staging/saas-bootstrap/0000_operator_migrator_role.sql',
      sha256: createHash('sha256').update(readFileSync(OPERATOR)).digest('hex'),
      executionAuthorized: false,
      mode: 'manual-operator-only-after-verified-backup',
      login: 'saas_schema_migrator',
    });
    expect(result.stdout + result.stderr).not.toContain(forbiddenSecret);
  });

  test('operator migration SQL denies production, pilot schemas, replay and weak roles', () => {
    const body = readFileSync(OPERATOR, 'utf8');
    expect(body).toContain("current_database() NOT IN ('saas_staging', 'saas_staging_ci')");
    expect(body).toContain("current_setting('saas.staging_only', true)");
    expect(body).toContain("session_user <> 'postgres'");
    expect(body).toContain("rolname = 'saas_schema_migrator'");
    expect(body).toContain('CREATE ROLE saas_schema_migrator');
    expect(body).toContain('NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE');
    expect(body).toContain('REVOKE ALL ON DATABASE');
    expect(body).toContain('REVOKE ALL ON SCHEMA public FROM PUBLIC');
    expect(body).toContain(":'migration_password'");
    expect(body).not.toMatch(/\\(?:i|ir)\s+.*saas-rls/i);
    expect(body).not.toMatch(/GRANT\s+(?:postgres|saas_m1_)/i);
    expect(body).not.toMatch(/DELETE\s+FROM|DROP\s+DATABASE|DROP\s+ROLE/i);
    expect(body).not.toMatch(/https?:\/\//i);
  });

  test('plan has no apply, provision or write subcommand', () => {
    for (const option of ['--apply', '--migrate', '--create-role', '--commit']) {
      const r = plan(option);
      expect(r.code).not.toBe(0);
      expect(r.stderr).toContain('preflight refused');
      expect(r.stdout + r.stderr).not.toContain(forbiddenSecret);
    }
  });
});
