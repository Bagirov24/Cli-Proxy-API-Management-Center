#!/usr/bin/env node
// Stage 2G.4d.7m: fail-closed, disposable PG16 UNKNOWN-COMMIT settlement.
// This is a local CI surrogate for an external witness, NOT a remote
// independent durable witness or a production exactly-once protocol.
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {mkdtempSync,chmodSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {projectionFromSql,envelopeDigest,canonicalProjection} from './archive-witness-protocol.mjs';

const expected=process.env.GITHUB_ACTIONS==='true' &&
  process.env.SAAS_EPHEMERAL_SETTLEMENT_CI==='true' &&
  process.env.PGHOST==='127.0.0.1' &&
  process.env.PGPORT==='5432' &&
  process.env.PGUSER==='postgres' &&
  process.env.PGDATABASE==='saas_ephemeral_test' &&
  !process.env.RAILWAY_ENVIRONMENT && !process.env.RAILWAY_PROJECT_ID &&
  !process.env.SAAS_PRODUCTION_DATABASE_URL;
if(!expected)throw new Error('Refusing UNKNOWN-COMMIT settlement outside disposable PG16 CI');

const work=mkdtempSync(join(tmpdir(),'saas-unknown-commit-'));
chmodSync(work,0o700);
const offlineEnv={
  GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
  PATH:process.env.PATH||'/usr/bin:/bin',LANG:'C',HOME:work,
};
const sqlEnv={...process.env,PGCONNECT_TIMEOUT:'5'};
const signer=fileURLToPath(new URL('./archive-witness-protocol.mjs',import.meta.url));
const store=fileURLToPath(new URL('./archive-witness-head-store.mjs',import.meta.url));
const highwater=fileURLToPath(new URL('./archive-witness-highwater-gate.mjs',import.meta.url));
const settlement=fileURLToPath(new URL('./archive-witness-settlement.mjs',import.meta.url));
const pub=join(work,'public.pem'),priv=join(work,'private.pem');
const a=join(work,'witness-a'), b=join(work,'witness-b');
const ha=join(work,'head-a.json'),hb=join(work,'head-b.json');
const journal=join(work,'separate-highwater');
const cp1=join(work,'checkpoint-1.json'),cp2=join(work,'checkpoint-2.json');
const ISSUE_UUID='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7a01';
const ROLLBACK_UUID='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7a02';
const PROTOCOL='saas-synthetic-uuid-unknown-commit-v1';
function run(program,args,env,deny=false) {
  const p=spawnSync(program,args,{cwd:work,env,encoding:'utf8',
    timeout:20000,maxBuffer:256000});
  if(deny) {
    assert.notEqual(p.status,0,'Expected DENY: '+program);
    assert.match(p.stderr||'',/SETTLEMENT DENIED:/);
  } else assert.equal(p.status,0,'Unexpected failure: '+program+
    '\n'+(p.stderr||''));
  return p.stdout;
}
const offline=(script,args,deny=false)=>run(process.execPath,[script,...args],
  offlineEnv,deny);
function query(sql) {
  return run('psql',['-X','-q','-t','-A','-v','ON_ERROR_STOP=1','-F','|',
    '-c',sql],sqlEnv).trim();
}
const projectionSQL="SELECT kind,operation FROM ("+
  "SELECT 'issued'::text AS kind,operation_id::text AS operation "+
  "FROM saas_rls_private.synthetic_operation_issues UNION ALL "+
  "SELECT 'producer'::text AS kind,operation_id::text AS operation "+
  "FROM saas_rls_private.synthetic_producer_operations) AS ids ORDER BY kind,operation";
const projection=()=>projectionFromSql(query(projectionSQL));
function save(name,json) {
  const path=join(work,name);
  writeFileSync(path,JSON.stringify(json)+'\n',{flag:'wx',mode:0o600});
  return path;
}
const read=path=>JSON.parse(readFileSync(path,'utf8'));
function candidate(uuid,checkpointFile,kind='issued') {
  const commitment=projectionFromSql(kind+'|'+uuid)[kind][0];
  return {
    protocol:PROTOCOL,kind,commitment,
    baselineHead:{
      sequence:read(checkpointFile).payload.sequence,
      digest:envelopeDigest(read(checkpointFile)),
    },
  };
}
function issueSql(uuid) {
  assert.match(uuid,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  return "INSERT INTO saas_rls_private.synthetic_operation_issues "+
    "(operation_id,tenant_id,actor_id,membership_role,collection,"+
    "requested_limit,issued_at,issue_expires_at,recovery_expires_at) VALUES ("+
    "'"+uuid+"'::uuid,'ci-settlement-tenant','ci-settlement-actor',"+
    "'tenant-viewer','projects',1,clock_timestamp(),"+
    "clock_timestamp()+interval '2 minutes',"+
    "clock_timestamp()+interval '2 hours');";
}
async function unknownCommit(uuid,afterCommit) {
  const name=afterCommit?'ci_settlement_after_commit':'ci_settlement_before_commit';
  const sql=afterCommit
    ? 'BEGIN;\n'+issueSql(uuid)+'\nCOMMIT;\nSELECT pg_sleep(12);\n'
    : 'BEGIN;\n'+issueSql(uuid)+'\nSELECT pg_sleep(12);\nCOMMIT;\n';
  const child=spawn('psql',['-X','-q','-v','ON_ERROR_STOP=1'],{
    env:{...sqlEnv,PGAPPNAME:name},stdio:['pipe','pipe','pipe'],
  });
  // Discard stdout by design; the caller sees only a dropped connection
  // and cannot assume a COMMIT ACK reached the application layer.
  child.stdout.resume();
  let stderr='';
  child.stderr.on('data',data=>{stderr+=String(data);});
  const finished=once(child,'exit');
  child.stdin.end(sql);
  let ready=false;
  for(let i=0;i<130;i++){
    const state=query("SELECT COUNT(*) FROM pg_stat_activity WHERE "+
      "application_name='"+name+"' AND wait_event='PgSleep'");
    if(state==='1'){ready=true;break;}
    await new Promise(resolve=>setTimeout(resolve,35));
  }
  assert.ok(ready,'Physical PostgreSQL session not staged for lost-response test');
  const killed=query("SELECT COUNT(*) FROM (SELECT pg_terminate_backend(pid) "+
    "AS terminated FROM pg_stat_activity WHERE application_name='"+name+
    "') q WHERE terminated");
  assert.equal(killed,'1','Failed to sever PostgreSQL connection');
  const [code]=await finished;
  assert.notEqual(code,0,'Expected physical dropped connection / UNKNOWN outcome');
  assert.ok(stderr.length>0,'Expected PostgreSQL connection termination');
}
function witnessArgs(observedFile) {
  return [pub,a,ha,b,hb,journal,observedFile];
}
function settleArgs(baselineSigned,baselineFile,observedFile,candidateFile) {
  return [pub,a,ha,b,hb,journal,baselineSigned,baselineFile,
    observedFile,candidateFile,'--no-gc'];
}
try {
  assert.equal(query('SELECT current_database()'),'saas_ephemeral_test');
  assert.equal(query("SELECT gc_permitted::text FROM "+
    "saas_rls_private.synthetic_operation_retention_health('demo-north')"),
    'false','Production GC remains prohibited');
  const auditBefore=query('SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox');
  const initial=projection();
  assert.ok(initial.issuedCount>0&&initial.producerCount>0,
    'Expected immutable 015/016 baseline fixture records');
  const initialFile=save('baseline.json',initial);
  assert.equal(query("SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
    "WHERE operation_id='"+ISSUE_UUID+"'::uuid"),'0');
  offline(signer,['keygen',priv,pub]);
  offline(signer,['sign',priv,pub,initialFile,'-',cp1]);
  offline(store,['init',pub,a,ha,cp1]);
  offline(store,['init',pub,b,hb,cp1]);
  offline(highwater,['init',...witnessArgs(initialFile)]);
  const attempt=save('prepare-expected-uuid.json',candidate(ISSUE_UUID,cp1));
  offline(settlement,settleArgs(cp1,initialFile,initialFile,attempt),true);
  console.info('PASS: prepared candidate alone is UNKNOWN; no issue or archive authorization');

  // Real transaction dies BEFORE COMMIT: the source has no new row.
  await unknownCommit(ROLLBACK_UUID,false);
  assert.equal(query("SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
    "WHERE operation_id='"+ROLLBACK_UUID+"'::uuid"),'0');
  const rolled=projection();
  assert.deepEqual(rolled,initial);
  const rollbackFile=save('rolled-back-actual-pg.json',rolled);
  const rollbackAttempt=save('prepare-rolled-back.json',
    candidate(ROLLBACK_UUID,cp1));
  offline(settlement,settleArgs(cp1,initialFile,rollbackFile,rollbackAttempt),true);
  console.info('PASS: real physical connection killed before COMMIT leaves UNKNOWN/ROLLBACK, not retry approval');

  // Real COMMIT occurs, then we deliberately drop the application session
  // before the post-COMMIT sleep can return: its caller sees UNKNOWN.
  await unknownCommit(ISSUE_UUID,true);
  assert.equal(query("SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
    "WHERE operation_id='"+ISSUE_UUID+"'::uuid"),'1');
  const committed=projection();
  assert.equal(committed.issuedCount,initial.issuedCount+1);
  assert.equal(committed.producerCount,initial.producerCount);
  const committedFile=save('committed-no-ack.json',committed);
  offline(settlement,settleArgs(cp1,initialFile,committedFile,attempt),true);
  console.info('PASS: PostgreSQL COMMIT with lost caller response remains DENY until witness successor');

  // Signed settlement sequence: partial publication is NOT enough.
  offline(signer,['sign',priv,pub,committedFile,cp1,cp2]);
  offline(store,['advance',pub,a,ha,cp2]);
  offline(settlement,settleArgs(cp1,initialFile,committedFile,attempt),true);
  offline(store,['advance',pub,b,hb,cp2]);
  offline(settlement,settleArgs(cp1,initialFile,committedFile,attempt),true);
  offline(highwater,['append',...witnessArgs(committedFile)]);
  const output=offline(settlement,settleArgs(cp1,initialFile,committedFile,attempt));
  assert.match(output,/local UNKNOWN-COMMIT identity reconciled/);
  console.info('PASS: independent offline signed successor and dual-replica high-water reconcile one UUID, NO ACK/GC');

  // Wrong prepared key (including cross-kind), forged baseline, old
  // restore, and an extra unanticipated UUID all fail closed.
  const wrong=save('wrong-commitment.json',{
    ...read(attempt),commitment:'0'.repeat(64)});
  offline(settlement,settleArgs(cp1,initialFile,committedFile,wrong),true);
  const forgedBase=save('forged-previous-head.json',{
    ...read(attempt),baselineHead:{sequence:1,digest:'f'.repeat(64)}});
  offline(settlement,settleArgs(cp1,initialFile,committedFile,forgedBase),true);
  const foreignKind=save('producer-kind-forged.json',candidate(ISSUE_UUID,cp1,'producer'));
  offline(settlement,settleArgs(cp1,initialFile,committedFile,foreignKind),true);
  offline(settlement,settleArgs(cp1,initialFile,initialFile,attempt),true);
  const unrelated=structuredClone(committed);
  unrelated.issued.push('f'.repeat(64));
  unrelated.issued.sort();
  unrelated.issuedCount++;
  const extra=save('unrelated-writer.json',unrelated);
  offline(settlement,settleArgs(cp1,initialFile,extra,attempt),true);
  const malformed=save('unknown-fields.json',{...read(attempt),allowGC:true});
  offline(settlement,settleArgs(cp1,initialFile,committedFile,malformed),true);
  assert.deepEqual(canonicalProjection(committed),committed);
  assert.equal(query('SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox'),
    auditBefore,'Witness experiment must never create 009/013 intent');
  assert.equal(query("SELECT gc_permitted::text FROM "+
    "saas_rls_private.synthetic_operation_retention_health('demo-north')"),
    'false');
  const signedBundle=JSON.stringify(read(cp2));
  assert.ok(!signedBundle.includes(ISSUE_UUID)&&
    !signedBundle.includes('ci-settlement-tenant'),
    'Raw UUID or principal disclosed to offline witness');
  console.info('PASS: forged prepare, wrong kind, extra UUID, stale projection and missing baseline are DENIED');
  console.info('PASS: local witness settlement never permits GC, duplicate issuance or remote delivery');
}finally {
  rmSync(work,{recursive:true,force:true});
}
