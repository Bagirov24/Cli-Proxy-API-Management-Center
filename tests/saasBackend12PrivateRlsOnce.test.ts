import {describe,expect,test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

const SRC=new URL('../scripts/saas-staging/backend12-private-rls-once.ts',import.meta.url);
const SQL_DIR=new URL('../staging/saas-bootstrap/',import.meta.url);
const source=readFileSync(SRC,'utf8');

describe('Backend12 one-shot private Railway staging policy installer',()=>{
  test('Bun Function source is syntactically valid, no HTTP entrypoint',()=>{
    const code=new Bun.Transpiler({loader:'ts',target:'bun'}).transformSync(source);
    expect(code).toContain('PASS_BACKEND12_STAGING_READ_ONLY_ROLE_RLS_0003_0004_NOLOGIN');
    expect(source).not.toMatch(/Bun\.serve|\.listen\(|createServer|setInterval|DATABASE_PUBLIC_URL/);
  });
  test('immutable reviewed SQL commits and hashes match bytes',()=>{
    const files=[
      ['0003_operator_runtime_roles.sql','8bd26bb1e798e1196f64546a0bfd554cfe46c6a5cd9d4414d369bc1cbf98124e'],
      ['0004_principal_bound_read_rls.sql','4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980'],
    ];
    for(const [path,hash] of files){
      const real=createHash('sha256').update(readFileSync(new URL(path,SQL_DIR))).digest('hex');
      expect(real).toBe(hash);
      expect(source).toContain(hash);
      expect(source).toContain(path);
    }
    expect(source).toContain('8b06c308d2fe52abb17b44fa09451db0994d3850');
    expect(source).toContain("await crypto.subtle.digest('SHA-256',bytes)");
    expect(source).toContain("redirect:'error'");
    expect(source).toContain('r.url!==url');
  });
  test('pins exact staging identity and private Postgres URL; no fallback',()=>{
    expect(source).toContain('a9703851-6eb1-406c-bb15-7d3a89359fb7');
    expect(source).toContain('b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b');
    expect(source).toContain("e.RAILWAY_SERVICE_NAME!=='saas-b12-rls-once'");
    expect(source).toContain("e.SAAS_B12_APPLY_EXPLICIT_ENABLE!=='true'");
    expect(source).toContain("e.SAAS_B12_ACCEPT_NO_BACKUP!=='true'");
    expect(source).toContain("url.hostname!=='postgres.railway.internal'");
    expect(source).toContain("url.pathname!=='/saas_staging'");
    expect(source).toContain("decodeURIComponent(url.username)!=='postgres'");
    expect(source).toContain("options:'-c saas.staging_only=true'");
    expect(source).not.toContain('cliproxyapi-personal');
    expect(source).not.toContain('custom-no-apikey-fun');
  });
  test('fail-closed preflight, distinct roles, readback and expiring operator handoff',()=>{
    expect(source).toContain('await preflight(admin)');
    expect(source).toContain('await admin.query(bind(roleSql,');
    expect(source).toContain('await migrator.query(bind(policySql,');
    expect(source).toContain("userUrl.username='saas_schema_migrator'");
    expect(source).toContain('Date.now()+5*60*1000');
    expect(source).toContain("ALTER ROLE saas_schema_migrator LOGIN PASSWORD");
    expect(source).toContain('await verify(admin)');
    expect(source).toContain('ALTER ROLE saas_schema_migrator NOLOGIN PASSWORD NULL');
    expect(source).toContain("q.rows[0].rolpassword!==null");
    expect(source).toContain('console.error(STOP)');
    expect(source).not.toMatch(/\bretry\s*\(|\bwhile\s*\(|\bDROP\s+(?:ROLE|SCHEMA|DATABASE)\b/);
    expect(source).toContain('BACKEND12_STOP_UNKNOWN_COMMIT_RECONCILE_NO_RETRY');
  });
});
