#!/usr/bin/env node
// Stage 2G.4d.7j: disposable PG16 proof-only witness/restore adversarial test.
// It NEVER deletes or archives an identifier and NEVER authorizes GC.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import {
  mkdtempSync, chmodSync, readFileSync, writeFileSync, rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  projectionFromSql, envelopeDigest, canonicalProjection,
} from './archive-witness-protocol.mjs';

const ciOnly =
  process.env.GITHUB_ACTIONS === 'true' &&
  process.env.SAAS_EPHEMERAL_ARCHIVE_CI === 'true' &&
  process.env.PGHOST === '127.0.0.1' &&
  process.env.PGPORT === '5432' &&
  process.env.PGUSER === 'postgres' &&
  process.env.PGDATABASE === 'saas_ephemeral_test' &&
  !process.env.RAILWAY_ENVIRONMENT && !process.env.RAILWAY_PROJECT_ID;
if (!ciOnly) throw new Error('Refusing witness test outside disposable PostgreSQL16 CI');
const work = mkdtempSync(join(tmpdir(), 'saas-archive-witness-'));
chmodSync(work, 0o700);
const here = fileURLToPath(new URL('./archive-witness-protocol.mjs', import.meta.url));
const publicPath = join(work,'witness-public.pem');
const privatePath = join(work,'witness-private.pem');
const offlineEnv = {
  GITHUB_ACTIONS:'true', SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
  PATH:process.env.PATH || '/usr/bin:/bin',
  HOME:work, LANG:'C',
};
const sqlEnv = { ...process.env };
function callWitness(args, deny=false) {
  const proc = spawnSync(process.execPath, [here, ...args], {
    env:offlineEnv, cwd:work, encoding:'utf8', timeout:12000,
    maxBuffer:256*1024,
  });
  if (deny) {
    assert.notEqual(proc.status,0,'Expected offline witness DENY but it succeeded');
    assert.match(proc.stderr || '',/WITNESS DENIED:/);
  } else {
    assert.equal(proc.status,0,'Offline witness failed: ' + (proc.stderr||''));
  }
  return proc.stdout;
}
function psql(sql) {
  const proc = spawnSync('psql',
    ['-X','-q','-A','-t','-F','|','-v','ON_ERROR_STOP=1','-c',sql],
    {env:sqlEnv,encoding:'utf8',timeout:12000,maxBuffer:1024*1024});
  assert.equal(proc.status,0,'Disposable PostgreSQL query failed: '+(proc.stderr||''));
  return proc.stdout.trim();
}
const PROJECTION_SQL = "SELECT kind,operation FROM (" +
 "SELECT 'issued'::text AS kind, operation_id::text AS operation " +
 "FROM saas_rls_private.synthetic_operation_issues UNION ALL " +
 "SELECT 'producer'::text AS kind,operation_id::text AS operation " +
 "FROM saas_rls_private.synthetic_producer_operations) AS candidate " +
 "ORDER BY kind,operation";
function sample() { return projectionFromSql(psql(PROJECTION_SQL)); }
function put(name,obj) {
  const path=join(work,name);
  writeFileSync(path,JSON.stringify(obj)+'\n',{flag:'wx',mode:0o600});
  return path;
}
function read(path) {return JSON.parse(readFileSync(path,'utf8'));}
function head(checkpointPath) {
  const doc=read(checkpointPath);
  return {sequence:doc.payload.sequence,digest:envelopeDigest(doc)};
}
function fixtureInsert(id) {
  assert.match(id,/^[0-9a-f-]{36}$/);
  return "INSERT INTO saas_rls_private.synthetic_operation_issues " +
   "(operation_id,tenant_id,actor_id,membership_role,collection," +
   "requested_limit,issued_at,issue_expires_at,recovery_expires_at) VALUES " +
   "('" + id + "'::uuid,'ci-proof-tenant','ci-proof-actor','tenant-viewer'," +
   "'projects',1,clock_timestamp(),clock_timestamp()+interval '2 minutes'," +
   "clock_timestamp()+interval '2 hours');";
}
async function stagedSql(appName,id,terminate) {
  const sql = "BEGIN;\n" + fixtureInsert(id) +
    "\nSELECT pg_sleep(4);\nCOMMIT;\n";
  const child = spawn('psql',['-X','-q','-v','ON_ERROR_STOP=1'],{
    env:{...sqlEnv,PGAPPNAME:appName},stdio:['pipe','pipe','pipe'],
  });
  let stderr='';
  child.stderr.on('data',(chunk)=>{stderr+=String(chunk);});
  const exited=once(child,'exit');
  child.stdin.end(sql);
  let ready=false;
  for(let n=0;n<65;n++){
    const status=psql("SELECT COUNT(*) FROM pg_stat_activity WHERE " +
      "application_name='" + appName + "' AND wait_event='PgSleep'");
    if(status==='1'){ready=true;break;}
    await new Promise(resolve=>setTimeout(resolve,45));
  }
  assert.ok(ready,'Staged PG transaction did not reach pre-COMMIT sleep');
  if (terminate) {
    const terminated=psql("SELECT COUNT(*) FROM (SELECT pg_terminate_backend(pid) " +
      "AS stopped FROM pg_stat_activity WHERE application_name='" +
      appName + "') AS killed WHERE stopped");
    // A terminated transaction must not commit; a crash before COMMIT
    // leaves no new operation ID or audit/intent after connection loss.
    assert.equal(terminated,'1','Unable to terminate staged PG session');
    const [code] = await exited;
    assert.notEqual(code,0,'Killed PostgreSQL session unexpectedly committed');
    assert.ok(stderr.length>0,'Expected psql connection interruption');
  }
  return {child,exited,stderr:()=>stderr};
}
const save = (name,body) => put(name,body);
try {
  assert.equal(psql('SELECT current_database()'),'saas_ephemeral_test');
  assert.equal(psql("SELECT COALESCE((SELECT gc_permitted::text FROM " +
    "saas_rls_private.synthetic_operation_retention_health('demo-north')),'NULL')"),
    'false','Database still must deny GC');
  const first=sample();
  assert.ok(first.issuedCount>0 && first.producerCount>0,
    'Missing signed 015/016 immutable test identities');
  const firstFile=save('projection-1.json',first);
  callWitness(['keygen',privatePath,publicPath]);
  callWitness(['sign',privatePath,publicPath,firstFile,'-',join(work,'checkpoint-1.json')]);
  const firstCheckpoint=join(work,'checkpoint-1.json');
  const trust1=save('pinned-head-1.json',head(firstCheckpoint));
  callWitness(['verify',publicPath,firstCheckpoint,'-',trust1,firstFile]);
  console.info('PASS: distinct offline Ed25519 witness signs only hashed immutable UUID commitments');

  const committedId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaace01';
  const staged=await stagedSql('ci_witness_staged_commit',committedId,false);
  const whileUncommitted=sample();
  assert.deepEqual(whileUncommitted,first,
    'Independent SQL connection observed uncommitted identifier');
  const currentBeforeCommit=save('projection-uncommitted.json',whileUncommitted);
  callWitness(['verify',publicPath,firstCheckpoint,'-',trust1,currentBeforeCommit]);
  const [exitCode]=await staged.exited;
  assert.equal(exitCode,0,'Producer fixture failed COMMIT: '+staged.stderr());
  const second=sample();
  assert.equal(second.issuedCount,first.issuedCount+1);
  assert.equal(second.producerCount,first.producerCount);
  const secondFile=save('projection-2.json',second);
  callWitness(['sign',privatePath,publicPath,secondFile,firstCheckpoint,
    join(work,'checkpoint-2.json')]);
  const secondCheckpoint=join(work,'checkpoint-2.json');
  const trust2=save('pinned-head-2.json',head(secondCheckpoint));
  callWitness(['verify',publicPath,secondCheckpoint,firstCheckpoint,trust2,secondFile]);
  console.info('PASS: committed UUID appears only after COMMIT; monotonic signed witness chain v1 -> v2');

  // A truly killed physical PG16 backend ROLLBACKS its pending INSERT;
  // there is no test-only DELETE or tombstone GC anywhere in this test.
  await stagedSql('ci_witness_precommit_crash',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaace02',true);
  assert.deepEqual(sample(),second,
    'Killed pre-COMMIT PG session changed immutable projection');
  const afterCrash=save('projection-after-crash.json',sample());
  callWitness(['verify',publicPath,secondCheckpoint,firstCheckpoint,trust2,afterCrash]);
  console.info('PASS: killed PG16 transaction rolls back; pinned witness still verifies committed set');

  // Simulated old DB restore: use the earlier non-deleted PROJECTION,
  // not destructive database deletion. v2 signed witness rejects missing UUID.
  callWitness(['verify',publicPath,secondCheckpoint,firstCheckpoint,trust2,firstFile],true);
  // A valid older signed checkpoint cannot replace a pinned new head.
  callWitness(['verify',publicPath,firstCheckpoint,'-',trust2,secondFile],true);
  // A v2 attestation without its signed v1 predecessor is incomplete.
  callWitness(['verify',publicPath,secondCheckpoint,'-',trust2,secondFile],true);

  const forged=structuredClone(read(secondFile));
  forged.issued.splice(0,1);
  forged.issuedCount-=1;
  const forgedFile=save('tampered-projection.json',forged);
  callWitness(['verify',publicPath,secondCheckpoint,firstCheckpoint,trust2,forgedFile],true);
  const modified=structuredClone(read(secondCheckpoint));
  modified.payload.projection.issued.pop();
  modified.payload.projection.issuedCount--;
  const modifiedFile=save('tampered-attestation.json',modified);
  callWitness(['verify',publicPath,modifiedFile,firstCheckpoint,trust2,secondFile],true);

  const competing=structuredClone(read(secondFile));
  const extraCommitment='f'.repeat(64);
  if(!competing.issued.includes(extraCommitment)) {
    competing.issued.push(extraCommitment);
    competing.issued.sort();
    competing.issuedCount++;
  }
  const competingFile=save('competing-projection.json',competing);
  const forkFile=join(work,'fork-checkpoint.json');
  callWitness(['sign',privatePath,publicPath,competingFile,firstCheckpoint,forkFile]);
  callWitness(['verify',publicPath,forkFile,firstCheckpoint,trust2,secondFile],true);
  const alternatePrivate=join(work,'wrong-private.pem');
  const alternatePublic=join(work,'wrong-public.pem');
  callWitness(['keygen',alternatePrivate,alternatePublic]);
  callWitness(['verify',alternatePublic,secondCheckpoint,firstCheckpoint,trust2,secondFile],true);
  const tornFile=join(work,'torn-checkpoint.json');
  writeFileSync(tornFile,'{"payload":',{flag:'wx',mode:0o600});
  callWitness(['verify',publicPath,tornFile,firstCheckpoint,trust2,secondFile],true);
  const visibleBundle=JSON.stringify(read(secondCheckpoint));
  for(const sensitive of [committedId,'ci-proof-tenant','ci-proof-actor',
    'actor_id','event_id','client_secret','access_token']) {
    assert.ok(!visibleBundle.includes(sensitive),
      'Witness bundle leaked private SQL identifier/metadata');
  }
  assert.deepEqual(canonicalProjection(second),second);
  assert.throws(()=>canonicalProjection({...second,issuedCount:second.issuedCount+1}));
  assert.equal(psql("SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
     "WHERE operation_id='"+committedId+"'::uuid"),'1');
  assert.equal(psql("SELECT gc_permitted::text FROM "+
    "saas_rls_private.synthetic_operation_retention_health('demo-north')"),'false');
  console.info('PASS: forged signature, wrong key, fork, stale head, missing predecessor, missing UUID and torn file DENY');
  console.info('PASS: proof-only witness never permits archive deletion, GC or UUID reuse');
} finally {
  // Ephemeral witness private key and all manifests are never published.
  rmSync(work,{recursive:true,force:true});
}
