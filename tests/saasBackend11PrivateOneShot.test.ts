import {describe, expect, test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

const BASE = new URL('../staging/saas-bootstrap/', import.meta.url);
const SRC = new URL('../scripts/saas-staging/backend11-private-one-shot.ts', import.meta.url);
const sha = (buf: Buffer) => createHash('sha256').update(buf).digest('hex');

describe('Backend11 private one-shot staging bootstrap', () => {
  const source = readFileSync(SRC, 'utf8');

  test('Railway Bun TypeScript single-file function has valid syntax', () => {
    const transpiler = new Bun.Transpiler({loader:'ts', target:'bun'});
    const js = transpiler.transformSync(source);
    expect(js).toContain('BACKEND11_STOP_UNKNOWN_STATE_RECONCILE_NO_RETRY');
    expect(js).toContain('PASS_BACKEND11_STAGING_PG16_0000_0001_0002_FORCE_RLS_NOLOGIN');
  });

  test('all three immutable migration bytes match the audited SHA256', () => {
    const files = [
      ['0000_operator_migrator_role.sql',
       '08047267af4750206d6963b058d2766b4f4f2ea16bb60e90209070aa65a4aab3'],
      ['0001_ledger_only.sql',
       '7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279'],
      ['0002_tenant_projects_baseline.sql',
       '80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f'],
    ];
    for (const [name, digest] of files) {
      expect(sha(readFileSync(new URL(name, BASE)))).toBe(digest);
      expect(source).toContain(name);
      expect(source).toContain(digest);
    }
    expect(source).toContain('7b2158009b742b47e12fd738c34ae430662803cf');
    expect(source).toContain("await crypto.subtle.digest('SHA-256',bytes)");
  });

  test('environment pinned to staging with no public DB proxy or production fallback', () => {
    expect(source).toContain('a9703851-6eb1-406c-bb15-7d3a89359fb7');
    expect(source).toContain('b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b');
    expect(source).toContain("url.hostname !== 'postgres.railway.internal'");
    expect(source).toContain("url.pathname !== '/saas_staging'");
    expect(source).toContain("e.RAILWAY_SERVICE_NAME !== 'saas-bootstrap-once'");
    expect(source).toContain("e.SAAS_BOOTSTRAP_EXPLICIT_ENABLE !== 'true'");
    expect(source).toContain("e.SAAS_BOOTSTRAP_OPERATOR_ACCEPT_LOSS !== 'true'");
    expect(source).toContain('STAGING_POSTGRES_PRIVATE_URL');
    expect(source).not.toContain('bd565370-7321-4dba-908a-412186b1b986');
    expect(source).not.toMatch(/DATABASE_PUBLIC_URL|Bun\.serve|\.listen\(|createServer|setInterval/);
  });

  test('no automatic migration retry and no logging of secrets or diagnostics', () => {
    expect(source).toContain("redirect:'error'");
    expect(source).toContain("res.url !== url");
    expect(source).toContain("console.error(FAIL)");
    expect(source).toContain("process.exitCode=1");
    expect(source).toContain('ALTER ROLE saas_schema_migrator NOLOGIN');
    expect(source).not.toContain('await validateEnvironment'); // validation is synchronous
    expect(source).toContain('const url = validateEnvironment()');
    expect(source).toContain('await blank(admin)');
    expect(source).toContain('await verify(admin)');
    expect(source).not.toMatch(/\bretry\s*\(|\bwhile\s*\(|\bsetTimeout\s*\(|console\.log\(\s*error/);
    expect(source).not.toMatch(/\bprocess\.env\.DATABASE_URL\b/);
    expect(source).not.toMatch(/\bDROP\s+DATABASE\b|\bDROP\s+ROLE\b/);
  });
});
