import {describe,expect,test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

const SQL=readFileSync(
  new URL('../scripts/saas-staging/backend16-0008-readonly-reconcile.sql',import.meta.url),
  'utf8',
);
const E2E=readFileSync(
  new URL('../scripts/saas-staging/verify-backend16-exact-session-pg16.sh',import.meta.url),
  'utf8',
);
const SQL7=readFileSync(
  new URL('../staging/saas-bootstrap/0007_operator_subject_binding_fence.sql',import.meta.url),
);
const SQL8=readFileSync(
  new URL('../staging/saas-bootstrap/0008_exact_subject_session_gate.sql',import.meta.url),
);

describe('Backend16.8 independent SQL0008 READ ONLY reconciler',()=>{
  test('read-only repeatable snapshot; never contains executable migration or role mutation',()=>{
    expect(SQL).toContain('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;');
    expect(SQL).toContain("current_setting('transaction_read_only') <> 'on'");
    expect(SQL).toContain("current_setting('saas.staging_only',true)");
    expect(SQL).toContain("current_database() NOT IN ('saas_staging','saas_staging_ci')");
    expect(SQL).toContain("session_user <> 'postgres'");
    expect(SQL).toContain("pg_catalog.pg_is_in_recovery()");
    expect(SQL).toContain('SET LOCAL statement_timeout');
    expect(SQL).toContain('SET LOCAL lock_timeout');
    expect(SQL.trimEnd()).toMatch(/END AS verified_state;$/);
    const live=SQL.split('\n')
      .filter(line=>!line.trimStart().startsWith('--'))
      .join('\n');
    expect(live).not.toMatch(/^\s*(?:CREATE|ALTER|DROP|GRANT|REVOKE|INSERT|UPDATE|DELETE|TRUNCATE)\b/im);
    expect(live).not.toMatch(/SET\s+(?:LOCAL\s+)?ROLE\b/i);
    expect(live).not.toContain('pg_terminate_backend');
    expect(live).not.toContain('Bun.serve');
    expect(SQL).not.toMatch(/railway\s+(?:up|redeploy|run)/i);
  });

  test('absent and installed markers require explicit operator expectation',()=>{
    expect(SQL).toContain('\\if :{?b16_expected_state}');
    expect(SQL).toContain('SELECT 1 / 0;');
    expect(SQL).toContain("wanted NOT IN ('absent','installed')");
    expect(SQL).toContain("CASE wanted WHEN 'absent' THEN 7 ELSE 8 END");
    expect(SQL).toContain("'PASS_BACKEND16_SQL0008_READONLY_ABSENT_SEALED_NEVER_AUTO_INSTALL'");
    expect(SQL).toContain("'PASS_BACKEND16_SQL0008_READONLY_INSTALLED_SEALED'");
    expect(SQL).toContain('B16_READONLY_STOP_PARTIAL_SQL0008');
    expect(SQL).toContain("WHERE p.oid=to_regprocedure(");
    expect(SQL).toContain('BACKEND16_READONLY_RECONCILE_STOP_MISSING_EXPECTATION');
  });

  test('all original migration hashes and pinned production SQL0007/0008 provenance',()=>{
    expect(createHash('sha256').update(SQL7).digest('hex')).toBe(
      '1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0',
    );
    expect(createHash('sha256').update(SQL8).digest('hex')).toBe(
      'ef4858975fea0842ae16d1b572457641c0359fa9630f02a1d52ea972007c632b',
    );
    for(const receipt of [
      '0001_ledger_only','0002_tenant_projects_baseline',
      '0003_operator_runtime_roles','0004_principal_bound_read_rls',
      '0005_principal_lifecycle_revocation_fence',
      '0006_principal_session_fence',
      '0007_operator_subject_binding_fence',
      '0008_exact_subject_session_gate',
    ])expect(SQL).toContain(receipt);
    expect(SQL).toContain('314f0962f2d955241fb5ee7a29175bddb648c130');
    expect(SQL).toContain('6cc4a76a0b3144380ccc95f0ca1c275ae312cae3');
    expect(SQL).toContain("m.applied_by IS DISTINCT FROM e.author");
    expect(SQL).toContain("source_commit ~ '^[a-f0-9]{40}$'");
    expect(SQL).toContain("WHERE migration_id='0008_exact_subject_session_gate'");
  });

  test('enforces sealed migrator, RLS, identity table privacy and definer grants',()=>{
    for(const marker of [
      'B16_READONLY_STOP_MIGRATOR_NOT_SEALED',
      "c.no_password IS DISTINCT FROM true",
      "c.login IS DISTINCT FROM false",
      'B16_READONLY_STOP_CONCURRENT_STAGING_CLIENT',
      "NOT rolcanlogin AND NOT rolinherit",
      'B16_READONLY_STOP_PREVIOUS_RECEIPTS',
      'B16_READONLY_STOP_FORCE_RLS',
      'B16_READONLY_STOP_B14_TRIGGERS',
      'B16_READONLY_STOP_B15_TRIGGERS',
      'B16_READONLY_STOP_UNEXPECTED_TABLE_GRANTS',
      'B16_READONLY_STOP_NONEMPTY_OR_ROLE_DRIFT',
      "pg_catalog.has_schema_privilege(rolname,'saas_identity','USAGE')",
      'B16_READONLY_STOP_SQL0008_FUNCTION_DRIFT',
      "f.provolatile IS DISTINCT FROM 'v'",
      "f.owner_name IS DISTINCT FROM 'saas_schema_migrator'",
      "f.prorettype IS DISTINCT FROM 'boolean'::regtype",
      "f.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']",
      'f.foreign_grants<>0',
      "f.definition NOT LIKE '%s.session_id=p_session%'",
      "f.definition NOT LIKE '%b.subject_fingerprint=p_subject_sha256%'",
    ])expect(SQL).toContain(marker);
  });

  test('real disposable PG16 runs both snapshots with sealed migrator',()=>{
    for(const marker of [
      "-v b16_expected_state=absent",
      "-v b16_expected_state=installed",
      "ALTER ROLE saas_schema_migrator NOLOGIN PASSWORD NULL",
      "ALTER ROLE saas_schema_migrator LOGIN PASSWORD :'ci_migrator_pwd'",
      'PASS_BACKEND16_SQL0008_READONLY_ABSENT_SEALED_NEVER_AUTO_INSTALL',
      'PASS_BACKEND16_SQL0008_READONLY_INSTALLED_SEALED',
    ])expect(E2E).toContain(marker);
    expect(E2E.split('backend16-0008-readonly-reconcile.sql').length-1).toBe(2);
    const pre=E2E.indexOf('-v b16_expected_state=absent');
    const install=E2E.indexOf('-f staging/saas-bootstrap/0008_exact_subject_session_gate.sql');
    const post=E2E.indexOf('-v b16_expected_state=installed');
    expect(pre).toBeGreaterThan(0);
    expect(install).toBeGreaterThan(pre);
    expect(post).toBeGreaterThan(install);
    expect(E2E).not.toContain('postgres.railway.internal');
  });
});
