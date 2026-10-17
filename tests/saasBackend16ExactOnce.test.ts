import {describe,expect,test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

const RUNNER=readFileSync(
  new URL('../scripts/saas-staging/backend16-exact-session-once.ts',import.meta.url),'utf8');
const MIGRATION=readFileSync(
  new URL('../staging/saas-bootstrap/0008_exact_subject_session_gate.sql',import.meta.url));
const SQL7=readFileSync(
  new URL('../staging/saas-bootstrap/0007_operator_subject_binding_fence.sql',import.meta.url));
const SHA8='ef4858975fea0842ae16d1b572457641c0359fa9630f02a1d52ea972007c632b';
const SHA7='1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0';

describe('Backend16.5 staging-only exact SQL0008 one-shot installer contract',()=>{
  test('source compiles for Bun and has NO HTTP, scheduler, or retry',()=>{
    const transpiled=new Bun.Transpiler({loader:'ts',target:'bun'})
      .transformSync(RUNNER);
    expect(transpiled).toContain('PASS_BACKEND16_STAGING_PG16_0008_EXACT_SESSION_NOLOGIN');
    expect(RUNNER).not.toMatch(/Bun\.serve|createServer|\.listen\(|setInterval|cronSchedule|DATABASE_PUBLIC_URL/);
    expect(RUNNER).not.toMatch(/\bretry\s*\(|\bwhile\s*\(|\bDROP\s+(?:SCHEMA|ROLE|DATABASE)\b/i);
    expect(RUNNER).not.toMatch(/\brailway\s+(?:up|run|redeploy|deploy)\b/i);
    expect(RUNNER).toContain("pg@8.16.3");
  });
  test('exact SQL0008 bytes and immutable source commit are pinned',()=>{
    expect(MIGRATION.length).toBe(9818);
    expect(createHash('sha256').update(MIGRATION).digest('hex')).toBe(SHA8);
    expect(createHash('sha256').update(SQL7).digest('hex')).toBe(SHA7);
    for(const fragment of [
      "COMMIT='314f0962f2d955241fb5ee7a29175bddb648c130'",
      "SQL_FILE='0008_exact_subject_session_gate.sql'",
      "SQL_SHA='"+SHA8+"'",
      "'0007_operator_subject_binding_fence','"+SHA7+"'",
      'expected_0007_sha256:PREVIOUS[6][1]',
      "source_commit:COMMIT",
      "redirect:'error'","response.url!==url",
      "await crypto.subtle.digest('SHA-256',bytes)",
      "bytes.byteLength!==9818",
    ])expect(RUNNER).toContain(fragment);
    expect(RUNNER).not.toContain('file://');
  });
  test('requires exact Railway project/env/service with private-only PG URL',()=>{
    for(const id of [
      'a9703851-6eb1-406c-bb15-7d3a89359fb7',
      'b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b',
      '37f8f166-75a6-4617-b243-8e681181c16d',
      '302e9762-7451-4999-a657-f5b3624dab63',
    ])expect(RUNNER).toContain(id);
    expect(RUNNER).toContain("RUNNER='saas-b16-0008-once'");
    expect(RUNNER).toContain('e.RAILWAY_SERVICE_ID!==RUNNER_SERVICE_ID');
    expect(RUNNER).toContain("e.SAAS_B16_APPLY_EXPLICIT_ENABLE!=='true'");
    expect(RUNNER).toContain("e.SAAS_B16_ACCEPT_DISPOSABLE_STAGING!=='true'");
    expect(RUNNER).toContain("e.RAILWAY_ENVIRONMENT_NAME!=='staging'");
    expect(RUNNER).toContain("url.hostname!=='postgres.railway.internal'");
    expect(RUNNER).toContain("url.port!=='5432'");
    expect(RUNNER).toContain("url.pathname!=='/saas_staging'");
    expect(RUNNER).toContain("decodeURIComponent(url.username)!=='postgres'");
    expect(RUNNER).toContain("options:'-c saas.staging_only=true'");
    expect(RUNNER).not.toMatch(/cliproxyapi-personal|custom-no-apikey-fun|api-gateway|\/data/);
  });
  test('all seven prior receipt SHAs/author roles must match before SQL',()=>{
    expect(RUNNER).toContain('PREVIOUS=[');
    expect(RUNNER).toContain('r.rows.length!==(post?8:7)');
    expect(RUNNER).toContain("x.applied_by===(i===2?'postgres':'saas_schema_migrator')");
    expect(RUNNER).toContain("x.migration_id!=='0008_exact_subject_session_gate'");
    expect(RUNNER).toContain("x.source_sha256!==SQL_SHA");
    expect(RUNNER).toContain("x.source_commit!==COMMIT");
    expect(RUNNER).toContain("await receipts(admin,false)");
    expect(RUNNER).toContain("await receipts(admin,true)");
    expect(RUNNER).toContain('other_connections');
    expect(RUNNER).toContain('migrator_no_password');
    expect(RUNNER).toContain('migrator_privileged');
    expect(RUNNER).toContain('pg_catalog.pg_authid');
  });
  test('denies data grants and verifies exact definer FOR SHARE privileges',()=>{
    for(const fragment of [
      'b14_triggers','b15_triggers',
      'binding_unique_indexes','revoke_constraint',
      'original_definers','original_binding_fence','operator_functions',
      'new_roles','memberships','forced','all_policies',
      'reader_private_schema','writer_private_schema',
      'reader_sessions','writer_bindings','reader_events',
      'writer_events','reader_write','writer_write',
      'saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)',
      "y.prosecdef!==true","y.provolatile!=='v'",
      "y.owner!=='saas_schema_migrator'",
      'search_path=pg_catalog, pg_temp',
      "pg_catalog.aclexplode(p.proacl)",
      'public_execute','unexpected_grantees','share_locks',
      'exact_session','exact_subject',
    ])expect(RUNNER).toContain(fragment);
    expect(RUNNER).toContain('await catalog(admin,false)');
    expect(RUNNER).toContain('await catalog(admin,true)');
    expect(RUNNER).toContain("'%s.session_id=p_session%'");
    expect(RUNNER).toContain("'%b.subject_fingerprint=p_subject_sha256%'");
  });
  test('source check and preflight always precede ONE SQL submission/readback/seal',()=>{
    const checkpoints=[
      'const sql=await source()',
      'await admin.connect()',
      'await preflight(admin)',
      'loginMayExist=true',
      "await admin.query(\"ALTER ROLE saas_schema_migrator LOGIN",
      'await migrator.connect()',
      'await migrator.query(bind(sql,{',
      'await readBack(admin)',
      'await seal(admin);sealed=true',
      'console.info(SUCCESS)',
    ];
    for(let i=1;i<checkpoints.length;i++)
      expect(RUNNER.indexOf(checkpoints[i])).toBeGreaterThan(RUNNER.indexOf(checkpoints[i-1]));
    expect(RUNNER.split('await migrator.query(bind(sql,{').length-1).toBe(1);
    expect(RUNNER).toContain('BACKEND16_STOP_UNKNOWN_COMMIT_RECONCILE_NEVER_RETRY');
    expect(RUNNER).toContain('if(adminReady&&loginMayExist&&!sealed){');
    expect(RUNNER).toContain('ALTER ROLE saas_schema_migrator NOLOGIN PASSWORD NULL');
    expect(RUNNER).toContain('rolpassword IS NULL AS password_is_null');
    expect(RUNNER).not.toMatch(/console\.(?:error|log)\(\s*(?:err|error|exception|secret|sql)/i);
  });
});
