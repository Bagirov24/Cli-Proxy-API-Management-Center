import {describe,expect,test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

const ROOT=new URL('../scripts/saas-staging/backend13-private-lifecycle-once.ts',import.meta.url);
const SQL=new URL('../staging/saas-bootstrap/0005_principal_lifecycle_revocation_fence.sql',import.meta.url);
const OLD=new URL('../staging/saas-bootstrap/0004_principal_bound_read_rls.sql',import.meta.url);
const source=readFileSync(ROOT,'utf8');
const sha=(buf:Buffer)=>createHash('sha256').update(buf).digest('hex');

describe('Backend13 private one-shot lifecycle Railway installer — default DENY',()=>{
  test('Bun function compiles, no API/listener, immutable reviewed source',()=>{
    const javascript=new Bun.Transpiler({loader:'ts',target:'bun'}).transformSync(source);
    expect(javascript).toContain('PASS_BACKEND13_STAGING_PG16_0005_CAS_AUDIT_FENCE_NOLOGIN');
    expect(source).not.toMatch(/Bun\.serve|createServer|\.listen\(|setInterval|DATABASE_PUBLIC_URL/);
    expect(source).toContain('d9a5a151cd86ff458882032ed2c62fd947a92f07');
    expect(source).toContain('0005_principal_lifecycle_revocation_fence.sql');
    expect(sha(readFileSync(SQL))).toBe('b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556');
    expect(sha(readFileSync(OLD))).toBe('4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980');
    expect(source).toContain('b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556');
    expect(source).toContain("await crypto.subtle.digest('SHA-256',bytes)");
    expect(source).toContain("redirect:'error'");
    expect(source).toContain('r.url!==url');
  });
  test('isolated Railway project and private Postgres only',()=>{
    expect(source).toContain('a9703851-6eb1-406c-bb15-7d3a89359fb7');
    expect(source).toContain('b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b');
    expect(source).toContain("e.RAILWAY_SERVICE_NAME!=='saas-b13-lifecycle-once'");
    expect(source).toContain("e.SAAS_B13_APPLY_EXPLICIT_ENABLE!=='true'");
    expect(source).toContain("e.SAAS_B13_ACCEPT_STAGING_LOSS!=='true'");
    expect(source).toContain("url.hostname!=='postgres.railway.internal'");
    expect(source).toContain("url.pathname!=='/saas_staging'");
    expect(source).toContain("decodeURIComponent(url.username)!=='postgres'");
    expect(source).toContain("options:'-c saas.staging_only=true'");
    expect(source).not.toContain('cliproxyapi-personal');
    expect(source).not.toContain('custom-no-apikey-fun');
  });
  test('requires exactly four prior receipts, force RLS and zero principals',()=>{
    expect(source).toContain('await before(admin)');
    expect(source).toContain('receipt.rows.length!==4');
    expect(source).toContain('z.tenants!==0');
    expect(source).toContain('z.projects!==0');
    expect(source).toContain('z.grants!==0');
    expect(source).toContain('x.mig_password!==null');
    expect(source).toContain('x.mig_login!==false');
    expect(source).toContain("previousFunc.rows[0].provolatile!=='s'");
    expect(source).toContain('extras.rows[0].audit_exists');
    expect(source).toContain('extras.rows[0].fn_exists');
  });
  test('no uncertain COMMIT retry; short-lived in-memory migrator and sealed credential',()=>{
    expect(source).toContain('Date.now()+5*60*1000');
    expect(source).toContain("ALTER ROLE saas_schema_migrator LOGIN PASSWORD");
    expect(source).toContain("migUrl.username='saas_schema_migrator'");
    expect(source).toContain('await migrator.query(bind(sql');
    expect(source).toContain('await after(admin)');
    expect(source).toContain('ALTER ROLE saas_schema_migrator NOLOGIN PASSWORD NULL');
    expect(source).toContain('PASS_BACKEND13_STAGING_PG16_0005_CAS_AUDIT_FENCE_NOLOGIN');
    expect(source).toContain('BACKEND13_STOP_UNKNOWN_COMMIT_MANUALLY_RECONCILE_NO_RETRY');
    expect(source).toContain('console.error(STOP)');
    expect(source).not.toMatch(/\bretry\s*\(|\bwhile\s*\(|\bDROP\s+(?:ROLE|DATABASE|SCHEMA)\b/i);
  });
  test('readback proves policies, atomic audit, no runtime executor or data',()=>{
    expect(source).toContain('receipts.rows.length!==5');
    expect(source).toContain('s.map_triggers!==2');
    expect(source).toContain('s.audit_triggers!==2');
    expect(source).toContain('s.read_policies!==2');
    expect(source).toContain('s.all_policies!==2');
    expect(source).toContain('s.reader_operator!==false');
    expect(source).toContain('s.writer_operator!==false');
    expect(source).toContain('s.audit_read!==false');
    expect(source).toContain('s.memberships!==0');
  });
});
