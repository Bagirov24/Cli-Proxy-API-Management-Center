import {describe,expect,test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

const FILE=new URL('../scripts/saas-staging/backend15-subject-binding-once.ts',import.meta.url);
const SQL=new URL('../staging/saas-bootstrap/0007_operator_subject_binding_fence.sql',import.meta.url);
const source=readFileSync(FILE,'utf8');
const pin='1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0';

describe('Backend15 private immutable 0007 one-shot staging installer',()=>{
 test('compiles and has no HTTP listener, cron or retry',()=>{
   const compiled=new Bun.Transpiler({loader:'ts',target:'bun'}).transformSync(source);
   expect(compiled).toContain('PASS_BACKEND15_STAGING_PG16_0007_SUBJECT_BINDING_FORCE_RLS_NOLOGIN');
   expect(source).not.toMatch(/Bun\.serve|createServer|\.listen\(|setInterval|cronSchedule|DATABASE_PUBLIC_URL/);
   expect(source).not.toMatch(/\bretry\s*\(|\bwhile\s*\(|\bDROP\s+(?:SCHEMA|ROLE|DATABASE)\b/);
 });
 test('reviewed exact SQL bytes and immutable merged commit',()=>{
   expect(createHash('sha256').update(readFileSync(SQL)).digest('hex')).toBe(pin);
   expect(source).toContain(pin);
   expect(source).toContain("COMMIT='6cc4a76a0b3144380ccc95f0ca1c275ae312cae3'");
   expect(source).toContain("SQL_FILE='0007_operator_subject_binding_fence.sql'");
   expect(source).toContain("expected_0006_sha256:PREVIOUS[5][1]");
   expect(source).toContain('b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505');
   expect(source).toContain("redirect:'error'");
   expect(source).toContain('r.url!==url');
   expect(source).toContain("await crypto.subtle.digest('SHA-256',bytes)");
 });
 test('locks isolated Railway staging and private database URL only',()=>{
   for(const id of ['a9703851-6eb1-406c-bb15-7d3a89359fb7',
     'b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b',
     '37f8f166-75a6-4617-b243-8e681181c16d'])expect(source).toContain(id);
   expect(source).toContain("RUNNER='saas-b15-binding-once'");
   expect(source).toContain("e.SAAS_B15_APPLY_EXPLICIT_ENABLE!=='true'");
   expect(source).toContain("e.SAAS_B15_ACCEPT_DISPOSABLE_STAGING!=='true'");
   expect(source).toContain("u.hostname!=='postgres.railway.internal'");
   expect(source).toContain("u.port!=='5432'");
   expect(source).toContain("u.pathname!=='/saas_staging'");
   expect(source).toContain("decodeURIComponent(u.username)!=='postgres'");
   expect(source).toContain("options:'-c saas.staging_only=true'");
   expect(source).not.toMatch(/cliproxyapi-personal|custom-no-apikey-fun|api-gateway/);
 });
 test('strict preflight, atomic single execution, read-back, seal, unknown commit refusal',()=>{
   const steps=['const approved=await source()','await admin.connect()',
     'await preflight(admin)','await migrator.query(bind(approved,',
     'await readBack(admin)','await seal(admin);sealed=true'];
   for(let i=1;i<steps.length;i++)expect(source.indexOf(steps[i])).toBeGreaterThan(source.indexOf(steps[i-1]));
   for(const required of ['PREVIOUS.length','migrator_no_password','other_connections',
     'migrator_privileged','new_roles','memberships','b14_triggers',
     'reader_identity','writer_identity','unexpected_grants',
     'binding_unique_indexes','b15_triggers','binding_fence',
     'ALTER ROLE saas_schema_migrator NOLOGIN PASSWORD NULL',
     'rolpassword IS NULL','loginMayExist&&!sealed',
     'BACKEND15_STOP_UNKNOWN_COMMIT_RECONCILE_NEVER_RETRY'])
       expect(source).toContain(required);
   expect(source.split("v.applied_by===(i===2?'postgres':'saas_schema_migrator')").length-1).toBe(2);
   expect(source).not.toMatch(/console\.(?:error|log)\(\s*(?:err|error|exception)/i);
 });
});
