import {describe,expect,test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

const FILE=new URL('../scripts/saas-staging/backend14-private-session-once.ts',import.meta.url);
const SQL=new URL('../staging/saas-bootstrap/0006_principal_session_fence.sql',import.meta.url);
const source=readFileSync(FILE,'utf8');

describe('Backend14 immutable staging-only no-retry private migration runner',()=>{
 test('TypeScript source compiles without an HTTP or scheduled listener',()=>{
   const compiled=new Bun.Transpiler({loader:'ts',target:'bun'}).transformSync(source);
   expect(compiled).toContain('PASS_BACKEND14_STAGING_PG16_0006_PRIVATE_SESSIONS_FORCE_RLS_NOLOGIN');
   expect(source).not.toMatch(/Bun\.serve|createServer|\.listen\(|setInterval|cronSchedule|DATABASE_PUBLIC_URL/);
 });
 test('exact immutable reviewed SQL and Git commit pins match bytes',()=>{
   const expected='b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505';
   const digest=createHash('sha256').update(readFileSync(SQL)).digest('hex');
   expect(digest).toBe(expected);
   expect(source).toContain(expected);
   expect(source).toContain('0006_principal_session_fence.sql');
   expect(source).toContain('e040f3994106a467e4bf42c1f21b18ca70ed4da2');
   expect(source).toContain('b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556');
   expect(source).toContain("await crypto.subtle.digest('SHA-256',bytes)");
   expect(source).toContain("redirect:'error'");
   expect(source).toContain('r.url!==url');
 });
 test('staging service, explicit consent and private DB ONLY',()=>{
   expect(source).toContain('a9703851-6eb1-406c-bb15-7d3a89359fb7');
   expect(source).toContain('b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b');
   expect(source).toContain("e.RAILWAY_SERVICE_NAME!=='saas-b14-session-once'");
   expect(source).toContain("e.SAAS_B14_APPLY_EXPLICIT_ENABLE!=='true'");
   expect(source).toContain("e.SAAS_B14_ACCEPT_STAGING_LOSS!=='true'");
   expect(source).toContain("u.hostname!=='postgres.railway.internal'");
   expect(source).toContain("u.port!=='5432'");
   expect(source).toContain("u.pathname!=='/saas_staging'");
   expect(source).toContain("decodeURIComponent(u.username)!=='postgres'");
   expect(source).toContain("options:'-c saas.staging_only=true'");
   expect(source).not.toContain('cliproxyapi-personal');
   expect(source).not.toContain('custom-no-apikey-fun');
 });
 test('preflight existing five receipts, zero data, DB read-back before NOLOGIN',()=>{
   expect(source).toContain('await preflight(admin)');
   expect(source).toContain('await migrator.query(bind(approved,');
   expect(source).toContain('await readBack(admin)');
   expect(source).toContain('await seal(admin);sealed=true');
   expect(source).toContain('ALTER ROLE saas_schema_migrator NOLOGIN PASSWORD NULL');
   expect(source).toContain("loginMayExist&&!sealed");
   expect(source).toContain('BACKEND14_STOP_UNKNOWN_COMMIT_RECONCILE_NEVER_RETRY');
   expect(source).not.toMatch(/\bretry\s*\(|\bwhile\s*\(|\bDROP\s+(?:SCHEMA|ROLE|DATABASE)\b/);
   expect(source).not.toMatch(/console\.(?:error|log)\(\s*(?:err|error|exception)/i);
 });
});
