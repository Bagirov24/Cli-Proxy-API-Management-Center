#!/usr/bin/env node
// Stage 2G.4d.7k: real disposable PostgreSQL16 pg_dump/pg_restore
// into TWO scratch databases. Witness sidecar has NO DB credentials.
// NEVER touch production, DELETE UUIDs, reset caps, perform archive GC.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync, chmodSync, readFileSync, writeFileSync, existsSync,
  copyFileSync, cpSync, rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { projectionFromSql, canonicalProjection } from './archive-witness-protocol.mjs';

const SOURCE='saas_ephemeral_test';
const OLD='saas_ephemeral_witness_old_7k';
const FRESH='saas_ephemeral_witness_fresh_7k';
const guarded=process.env.GITHUB_ACTIONS==='true' &&
  process.env.SAAS_EPHEMERAL_RESTORE_CI==='true' &&
  process.env.PGHOST==='127.0.0.1' &&
  process.env.PGPORT==='5432' &&
  process.env.PGUSER==='postgres' &&
  process.env.PGDATABASE===SOURCE &&
  !process.env.RAILWAY_ENVIRONMENT &&
  !process.env.RAILWAY_PROJECT_ID &&
  !process.env.SAAS_PRODUCTION_DATABASE_URL;
if(!guarded) throw new Error('Refusing physical restore test outside disposable PostgreSQL16');
const work=mkdtempSync(join(tmpdir(),'saas-7k-restore-'));
chmodSync(work,0o700);
const sourceEnv={...process.env,PGCONNECT_TIMEOUT:'5'};
const offlineEnv={
  GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
  PATH:process.env.PATH||'/usr/bin:/bin',
  HOME:work,LANG:'C',
};
const witness=fileURLToPath(new URL('./archive-witness-protocol.mjs',import.meta.url));
const headCli=fileURLToPath(new URL('./archive-witness-head-store.mjs',import.meta.url));
const projectionSql="SELECT kind,operation FROM ("+
  "SELECT 'issued'::text AS kind,operation_id::text AS operation "+
  "FROM saas_rls_private.synthetic_operation_issues UNION ALL "+
  "SELECT 'producer'::text AS kind,operation_id::text AS operation "+
  "FROM saas_rls_private.synthetic_producer_operations) x ORDER BY kind,operation";
const stateDir=join(work,'private-witness-state');
const anchor=join(work,'separate-pinned-head.json');
const publicKey=join(work,'pinned-public.pem');
const privateKey=join(work,'ephemeral-private.pem');
const oldDump=join(work,'old-full-pg16.dump');
const freshDump=join(work,'fresh-full-pg16.dump');
const firstCheckpoint=join(work,'checkpoint-1.json');
const secondCheckpoint=join(work,'checkpoint-2.json');
const created=new Set();
function run(command,args,{env=sourceEnv,timeout=60000,allowFailure=false}={}) {
  const result=spawnSync(command,args,{
    env,cwd:work,encoding:'utf8',timeout,maxBuffer:2*1024*1024,
  });
  if(allowFailure) {
    assert.notEqual(result.status,0,'Expected failure but succeeded: '+command);
  } else {
    assert.equal(result.status,0,'Command failed: '+command+
      ' '+args.map(x=>x.startsWith(work)?'[private-path]':x).join(' ')+
      '\n'+(result.stderr||''));
  }
  return result;
}
function offline(script,args,{deny=false,kill=false}={}) {
  const env=kill?{...offlineEnv,
    SAAS_WITNESS_TEST_KILL_BEFORE_HEAD_RENAME:'true'}:offlineEnv;
  const r=run(process.execPath,[script,...args],{
    env,timeout:15000,allowFailure:deny||kill,
  });
  if(deny) assert.match(r.stderr||'',/HEAD DENIED:|WITNESS DENIED:/);
  if(kill) assert.equal(r.signal,'SIGKILL','Expected crash after durable staging file');
  return r.stdout;
}
function psql(sql,db=SOURCE) {
  return run('psql',['-X','-q','-A','-t','-F','|',
    '-v','ON_ERROR_STOP=1','--dbname',db,'--command',sql],
    {timeout:20000}).stdout.trim();
}
function sample(db=SOURCE) {
  return projectionFromSql(psql(projectionSql,db));
}
function save(name,obj) {
  const file=join(work,name);
  writeFileSync(file,JSON.stringify(obj)+'\n',{flag:'wx',mode:0o600});
  return file;
}
function read(path) {return JSON.parse(readFileSync(path,'utf8'));}
function verifyFile(projectionPath,{trust=stateDir,pinned=anchor,deny=false}={}) {
  offline(headCli,['verify',publicKey,trust,pinned,projectionPath],{deny});
}
function dump(target) {
  assert.ok(!existsSync(target));
  run('pg_dump',['--format=custom','--no-owner','--no-acl',
    '--dbname',SOURCE,'--file',target],{timeout:75000});
}
function restoredDb(db,file) {
  assert.ok([OLD,FRESH].includes(db),'Illegal restoration destination');
  assert.equal(psql("SELECT COUNT(*) FROM pg_database WHERE datname='"+db+"'"),
    '0','Scratch database already exists — refuse to overwrite');
  run('createdb',['--template','template0',db]);
  created.add(db);
  run('pg_restore',['--exit-on-error','--no-owner','--no-acl',
    '--dbname',db,file],{timeout:75000});
  assert.equal(psql('SELECT current_database()',db),db);
}
function fixtureCommit() {
  const id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaace71';
  assert.equal(psql("SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
    "WHERE operation_id='"+id+"'::uuid"),'0','Fixture UUID collision');
  psql("BEGIN; INSERT INTO saas_rls_private.synthetic_operation_issues "+
    "(operation_id,tenant_id,actor_id,membership_role,collection,"+
    "requested_limit,issued_at,issue_expires_at,recovery_expires_at) VALUES "+
    "('"+id+"'::uuid,'ci-restore-proof','ci-restore-proof-actor',"+
    "'tenant-viewer','projects',1,clock_timestamp(),"+
    "clock_timestamp()+interval '2 minutes',"+
    "clock_timestamp()+interval '2 hours'); COMMIT;");
  assert.equal(psql("SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
    "WHERE operation_id='"+id+"'::uuid"),'1');
  return id;
}
try {
  assert.equal(psql('SELECT current_database()'),SOURCE);
  assert.equal(psql("SELECT gc_permitted::text FROM "+
    "saas_rls_private.synthetic_operation_retention_health('demo-north')"),
    'false','GC is forbidden regardless of signed witness evidence');
  const baseline=sample();
  assert.ok(baseline.issuedCount>0&&baseline.producerCount>0);
  const baselineFile=save('baseline-projection.json',baseline);
  // Full pg_dump is BEFORE new PostgreSQL COMMIT. It never reaches offline
  // witness and stays private in this one ephemeral job.
  dump(oldDump);
  offline(witness,['keygen',privateKey,publicKey]);
  offline(witness,['sign',privateKey,publicKey,
    baselineFile,'-',firstCheckpoint]);
  offline(headCli,['init',publicKey,stateDir,anchor,firstCheckpoint]);
  verifyFile(baselineFile);
  const oldState=join(work,'old-trust-copy');
  const oldAnchor=join(work,'old-anchor-copy.json');
  cpSync(stateDir,oldState,{recursive:true});
  copyFileSync(anchor,oldAnchor);
  console.info('PASS: fsynced detached head and signed history survive fresh verifier process');

  fixtureCommit();
  const observed=sample();
  assert.equal(observed.issuedCount,baseline.issuedCount+1);
  const observedFile=save('observed-after-commit.json',observed);
  // Uncheckpointed COMMIT is DENIED even though older head is signed.
  verifyFile(observedFile,{deny:true});
  offline(witness,['sign',privateKey,publicKey,observedFile,
    firstCheckpoint,secondCheckpoint]);
  offline(headCli,['advance',publicKey,stateDir,anchor,secondCheckpoint]);
  verifyFile(observedFile);
  dump(freshDump);
  console.info('PASS: missing checkpoint after PG COMMIT blocks strict restore; persisted second head unblocks');

  // Actual full SQL restore of an older pg_dump into isolated, disposable
  // PostgreSQL database. The SOURCE is never overwritten or deleted.
  restoredDb(OLD,oldDump);
  const restoredOld=sample(OLD);
  assert.deepEqual(restoredOld,baseline,
    'Old PostgreSQL restore did not reproduce the original UUID set');
  const oldRestoreFile=save('real-old-restore-projection.json',restoredOld);
  verifyFile(oldRestoreFile,{deny:true});
  console.info('PASS: REAL PostgreSQL16 pg_dump/pg_restore of stale backup misses committed UUID and DENIES');

  // Independent new full pg_dump after COMMIT, restored into another
  // scratch DB and verified by a NEW process loading disk-pinned state.
  restoredDb(FRESH,freshDump);
  const restoredFresh=sample(FRESH);
  assert.deepEqual(restoredFresh,observed);
  const freshRestoreFile=save('real-current-restore-projection.json',restoredFresh);
  verifyFile(freshRestoreFile);
  console.info('PASS: REAL PostgreSQL16 current backup restore passes restarted signed witness verifier');

  // Crash before atomic head rename: only cloned witness-state is touched,
  // never the live pinned head or any PostgreSQL database. The killed
  // process leaves a lock/orphan history and MUST fail closed on restart.
  const crashedState=join(work,'crashed-trust-copy');
  const crashedAnchor=join(work,'crashed-anchor-copy.json');
  cpSync(stateDir,crashedState,{recursive:true});
  copyFileSync(anchor,crashedAnchor);
  const thirdCheckpoint=join(work,'checkpoint-3.json');
  offline(witness,['sign',privateKey,publicKey,observedFile,
    secondCheckpoint,thirdCheckpoint]);
  offline(headCli,['advance',publicKey,crashedState,
    crashedAnchor,thirdCheckpoint],{kill:true});
  verifyFile(freshRestoreFile,{trust:crashedState,pinned:crashedAnchor,deny:true});
  verifyFile(freshRestoreFile);
  console.info('PASS: SIGKILL between fsync and rename fails closed on restarted verifier');

  // Old signed history AND head cannot replace current history if an
  // independent-to-state pinned anchor remains at sequence 2.
  verifyFile(oldRestoreFile,{trust:oldState,pinned:anchor,deny:true});
  // If BOTH trust history and anchor roll back, this one-runner CI cannot
  // prove the lost history existed. Explicitly leave durable external
  // witness / trusted-head rollback resistance as SPEC, not VERIFIED.
  const tamperedHead=join(work,'tampered-anchor.json');
  writeFileSync(tamperedHead,'{"sequence":',{flag:'wx',mode:0o600});
  verifyFile(freshRestoreFile,{pinned:tamperedHead,deny:true});
  assert.deepEqual(canonicalProjection(restoredFresh),observed);
  assert.equal(psql("SELECT gc_permitted::text FROM "+
    "saas_rls_private.synthetic_operation_retention_health('demo-north')"),
    'false');
  console.info('PASS: stale trust state and torn pinned head fail; physical GC/reuse stays FORBIDDEN');
} finally {
  // Scratch database deletion is solely to dispose of synthetic restored
  // databases in isolated CI. Never drop SOURCE or any UUID rows within it.
  for(const database of [...created].reverse()) {
    try {run('dropdb',['--if-exists',database],{timeout:20000});}
    catch(err) {process.stderr.write('Scratch cleanup warning: '+err.message+'\n');}
  }
  rmSync(work,{recursive:true,force:true});
}
