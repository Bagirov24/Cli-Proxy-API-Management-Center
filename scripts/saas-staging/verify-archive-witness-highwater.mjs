#!/usr/bin/env node
// Stage 2G.4d.7l: physical ephemeral PG16 commit-vs-witness gap,
// two offline witness replicas + separate fsynced high-water journal.
// All three are on ONE job-local runner: NEVER claim durable third-party
// attestation or authorize tombstone GC/archival/deletion/reuse.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync, chmodSync, readFileSync, writeFileSync, existsSync,
  cpSync, copyFileSync, rmSync, mkdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  projectionFromSql,canonicalProjection,
} from './archive-witness-protocol.mjs';

const allowed=process.env.GITHUB_ACTIONS==='true' &&
 process.env.SAAS_EPHEMERAL_HIGHWATER_CI==='true' &&
 process.env.PGHOST==='127.0.0.1' &&
 process.env.PGPORT==='5432' &&
 process.env.PGUSER==='postgres' &&
 process.env.PGDATABASE==='saas_ephemeral_test' &&
 !process.env.RAILWAY_PROJECT_ID&&!process.env.RAILWAY_ENVIRONMENT &&
 !process.env.SAAS_PRODUCTION_DATABASE_URL;
if(!allowed)throw new Error('Refusing tri-compartment witness proof outside disposable PG16');
const work=mkdtempSync(join(tmpdir(),'saas-witness-highwater-'));
chmodSync(work,0o700);
const currentSqlEnv={...process.env,PGCONNECT_TIMEOUT:'5'};
const offlineEnv={
 GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
 PATH:process.env.PATH||'/usr/bin:/bin',LANG:'C',HOME:work,
};
const signer=fileURLToPath(new URL('./archive-witness-protocol.mjs',import.meta.url));
const store=fileURLToPath(new URL('./archive-witness-head-store.mjs',import.meta.url));
const highwater=fileURLToPath(new URL('./archive-witness-highwater-gate.mjs',import.meta.url));
const privateKey=join(work,'private-ed25519.pem');
const publicKey=join(work,'public-ed25519.pem');
const a=join(work,'replica-a'), b=join(work,'replica-b');
const anchorA=join(work,'anchor-a.json'), anchorB=join(work,'anchor-b.json');
const journal=join(work,'separate-highwater');
const cp1=join(work,'checkpoint-1.json'),cp2=join(work,'checkpoint-2.json'),
      cp3=join(work,'checkpoint-3.json');
const args=(aDir=a,aHead=anchorA,bDir=b,bHead=anchorB,jDir=journal,projection)=>
  [publicKey,aDir,aHead,bDir,bHead,jDir,projection];
function run(program,argv,env,denied=false,crash=false){
  const proc=spawnSync(program,argv,{
    cwd:work,env,encoding:'utf8',timeout:14000,maxBuffer:256*1024,
  });
  if(crash)assert.equal(proc.signal,'SIGKILL','Expected simulated fsync/append crash');
  else if(denied){
    assert.notEqual(proc.status,0,'Required security denial was accepted');
    assert.match(proc.stderr||'',/HIGH-WATER DENIED:|HEAD DENIED:/);
  }else assert.equal(proc.status,0,program+' rejected valid fixture: '+(proc.stderr||''));
  return proc.stdout;
}
function offline(script,argv,denied=false,crash=false) {
 return run(process.execPath,[script,...argv],
   crash?{...offlineEnv,SAAS_WITNESS_TEST_KILL_JOURNAL_AFTER_FSYNC:'true'}:
     offlineEnv,denied,crash);
}
function query(sql) {
  return run('psql',['-X','-q','-A','-t','-F','|',
    '-v','ON_ERROR_STOP=1','-c',sql],currentSqlEnv).trim();
}
const projectionSql="SELECT kind,operation FROM ("+
  "SELECT 'issued'::text AS kind,operation_id::text AS operation "+
  "FROM saas_rls_private.synthetic_operation_issues UNION ALL "+
  "SELECT 'producer'::text AS kind,operation_id::text AS operation "+
  "FROM saas_rls_private.synthetic_producer_operations) AS x ORDER BY kind,operation";
function sample(){return projectionFromSql(query(projectionSql));}
function save(name,obj){
 const file=join(work,name);
 writeFileSync(file,JSON.stringify(obj)+'\n',{flag:'wx',mode:0o600});
 return file;
}
function copyTrust(sourceDir,sourceHead,label){
 const outDir=join(work,label+'-replica');
 const outHead=join(work,label+'-head.json');
 cpSync(sourceDir,outDir,{recursive:true});
 copyFileSync(sourceHead,outHead);
 return [outDir,outHead];
}
function idInsert(id,actor){
 assert.match(id,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
 assert.match(actor,/^[a-z0-9-]{1,50}$/);
 assert.equal(query("SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
   "WHERE operation_id='"+id+"'::uuid"),'0');
 query("BEGIN; INSERT INTO saas_rls_private.synthetic_operation_issues "+
  "(operation_id,tenant_id,actor_id,membership_role,collection,"+
  "requested_limit,issued_at,issue_expires_at,recovery_expires_at) VALUES ("+
  "'"+id+"'::uuid,'ci-highwater-tenant','"+actor+"','tenant-viewer',"+
  "'projects',1,clock_timestamp(),clock_timestamp()+interval '2 minutes',"+
  "clock_timestamp()+interval '2 hours'); COMMIT;");
 assert.equal(query("SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
   "WHERE operation_id='"+id+"'::uuid"),'1');
}
try {
 assert.equal(query('SELECT current_database()'),'saas_ephemeral_test');
 assert.equal(query("SELECT gc_permitted::text FROM "+
  "saas_rls_private.synthetic_operation_retention_health('demo-north')"),'false');
 const baseline=sample();
 assert.ok(baseline.issuedCount>0 && baseline.producerCount>0);
 const baselineFile=save('baseline.json',baseline);
 offline(signer,['keygen',privateKey,publicKey]);
 offline(signer,['sign',privateKey,publicKey,baselineFile,'-',cp1]);
 offline(store,['init',publicKey,a,anchorA,cp1]);
 offline(store,['init',publicKey,b,anchorB,cp1]);
 offline(highwater,['init',...args(a,anchorA,b,anchorB,journal,baselineFile)]);
 offline(highwater,['verify',...args(a,anchorA,b,anchorB,journal,baselineFile)]);
 const [oldA,oldAnchorA]=copyTrust(a,anchorA,'old-a');
 const [oldB,oldAnchorB]=copyTrust(b,anchorB,'old-b');
 const oldJournal=join(work,'old-highwater');
 cpSync(journal,oldJournal,{recursive:true});
 console.info('PASS: two offline verifier processes and independent fsynced high-water journal bootstrap');

 // Actual committed PostgreSQL INSERT while both detached witness stores
 // and the journal still pin old signed seq=1: fail closed.
 idInsert('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaacf01','ci-highwater-actor-1');
 const next=sample();
 assert.equal(next.issuedCount,baseline.issuedCount+1);
 const nextFile=save('after-real-PG-commit.json',next);
 offline(highwater,['verify',...args(a,anchorA,b,anchorB,journal,nextFile)],true);
 console.info('PASS: real PG COMMIT before witness publication produces strict unsigned gap DENY');

 offline(signer,['sign',privateKey,publicKey,nextFile,cp1,cp2]);
 offline(store,['advance',publicKey,a,anchorA,cp2]);
 offline(highwater,['verify',...args(a,anchorA,b,anchorB,journal,nextFile)],true);
 offline(store,['advance',publicKey,b,anchorB,cp2]);
 offline(highwater,['verify',...args(a,anchorA,b,anchorB,journal,nextFile)],true);
 offline(highwater,['append',...args(a,anchorA,b,anchorB,journal,nextFile)]);
 offline(highwater,['verify',...args(a,anchorA,b,anchorB,journal,nextFile)]);
 console.info('PASS: incomplete first/second witness ACK and missing high-water pin DENY; complete seq=2 PASS');

 // Restore BOTH independently stored witness histories/anchors to
 // an old signed seq=1. The 3rd compartment at seq=2 refuses rollback.
 offline(highwater,['verify',...args(
   oldA,oldAnchorA,oldB,oldAnchorB,journal,baselineFile)],true);
 offline(highwater,['verify',...args(
   oldA,oldAnchorA,oldB,oldAnchorB,journal,nextFile)],true);
 const lostJournal=join(work,'lost-highwater');
 offline(highwater,['verify',...args(a,anchorA,b,anchorB,lostJournal,nextFile)],true);
 const corruptedJournal=join(work,'corrupt-highwater');
 cpSync(journal,corruptedJournal,{recursive:true});
 writeFileSync(join(corruptedJournal,'highwater.log'),
   '{"sequence":2,"digest":"bad"}\n');
 offline(highwater,['verify',...args(a,anchorA,b,anchorB,corruptedJournal,nextFile)],true);
 console.info('PASS: rollback of BOTH replicas, missing journal and torn journal all DENY');

 // Explicit limitation proof: rollback of ALL 3 job-local compartments
 // can reproduce a prior internally-consistent snapshot. This is NOT
 // an independently persistent external root, never a GC authorization.
 offline(highwater,['verify',...args(
   oldA,oldAnchorA,oldB,oldAnchorB,oldJournal,baselineFile)]);
 console.info('LIMITATION: simultaneous rollback of ALL job-local copies is undetectable (production gate OPEN)');

 // Another real PG COMMIT is invisible to the attestor until signed
 // checkpoint 3 is complete. Test power-loss at journal fsync on CLONES,
 // leaving an orphan lock and a reader that must fail closed.
 idInsert('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaacf02','ci-highwater-actor-2');
 const third=sample();
 assert.equal(third.issuedCount,baseline.issuedCount+2);
 const thirdFile=save('latest-real-PG-set.json',third);
 offline(highwater,['verify',...args(a,anchorA,b,anchorB,journal,thirdFile)],true);
 offline(signer,['sign',privateKey,publicKey,thirdFile,cp2,cp3]);
 const [cloneA,cloneAnchorA]=copyTrust(a,anchorA,'crash-a');
 const [cloneB,cloneAnchorB]=copyTrust(b,anchorB,'crash-b');
 const cloneJournal=join(work,'crash-journal');
 cpSync(journal,cloneJournal,{recursive:true});
 offline(store,['advance',publicKey,cloneA,cloneAnchorA,cp3]);
 offline(store,['advance',publicKey,cloneB,cloneAnchorB,cp3]);
 offline(highwater,['append',...args(cloneA,cloneAnchorA,cloneB,
   cloneAnchorB,cloneJournal,thirdFile)],false,true);
 offline(highwater,['verify',...args(cloneA,cloneAnchorA,cloneB,
   cloneAnchorB,cloneJournal,thirdFile)],true);
 offline(highwater,['verify',...args(a,anchorA,b,anchorB,journal,thirdFile)],true);
 console.info('PASS: SIGKILL after journal fsync leaves pending lock; independent verifier DENIES');

 // A normal publication of both distinct copies + journal can verify
 // the entire signed seq=3 set after the crash test. Replay/skip denied.
 offline(store,['advance',publicKey,a,anchorA,cp3]);
 offline(store,['advance',publicKey,b,anchorB,cp3]);
 offline(highwater,['append',...args(a,anchorA,b,anchorB,journal,thirdFile)]);
 offline(highwater,['verify',...args(a,anchorA,b,anchorB,journal,thirdFile)]);
 offline(highwater,['append',...args(a,anchorA,b,anchorB,journal,thirdFile)],true);
 assert.deepEqual(canonicalProjection(third),third);
 assert.equal(query("SELECT gc_permitted::text FROM "+
  "saas_rls_private.synthetic_operation_retention_health('demo-north')"),'false');
 assert.ok(!JSON.stringify(JSON.parse(readFileSync(cp3,'utf8'))).includes(
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaacf02'),
  'Raw UUID leaked to hashed witness bundle');
 console.info('PASS: signed local tri-compartment seq=3 restored without deleting UUID or authorizing GC');
}finally {
 rmSync(work,{recursive:true,force:true});
}
