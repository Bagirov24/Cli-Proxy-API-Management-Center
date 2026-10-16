#!/usr/bin/env node
// Stage 2G.4d.7n: separate Unix-socket witness process and physical
// disposable PG16 writer. ONE CI RUNNER ONLY; NO production witness.
// Tests durable ACK-loss recovery, partition, concurrent stale writers,
// pending-record crash, and fail-closed uncheckpointed PostgreSQL UUID.
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {connect} from 'node:net';
import {
  mkdtempSync,chmodSync,readFileSync,existsSync,unlinkSync,
  cpSync,rmSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  createHash,randomBytes,verify as edVerify,
} from 'node:crypto';
import {
  projectionFromSql,verifyEnvelope,envelopeDigest,canonicalProjection,
} from './archive-witness-protocol.mjs';

const ciOnly=process.env.GITHUB_ACTIONS==='true'&&
  process.env.SAAS_EPHEMERAL_IPC_WITNESS_CI==='true'&&
  process.env.PGHOST==='127.0.0.1'&&process.env.PGPORT==='5432'&&
  process.env.PGUSER==='postgres'&&
  process.env.PGDATABASE==='saas_ephemeral_test'&&
  !process.env.RAILWAY_ENVIRONMENT&&!process.env.RAILWAY_PROJECT_ID&&
  !process.env.SAAS_PRODUCTION_DATABASE_URL;
if(!ciOnly)throw Error('Refusing remote-like witness outside disposable PG16 CI');

const work=mkdtempSync(join(tmpdir(),'saas-ipc-witness-'));
chmodSync(work,0o700);
const serverFile=fileURLToPath(new URL('./archive-witness-ipc-server.mjs',import.meta.url));
const state=join(work,'witness-state'),sock=join(work,'witness.sock');
const offlineEnv={
  GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_IPC_WITNESS_CI:'true',
  SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
  PATH:process.env.PATH||'/usr/bin:/bin',HOME:work,LANG:'C',
};
const sqlEnv={...process.env,PGCONNECT_TIMEOUT:'5'};
const hash=s=>createHash('sha256').update(s).digest('hex');
const freshId=()=>randomBytes(16).toString('hex');
const ISSUE1='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7b01';
const ISSUE2='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7b02';
const ISSUE3='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7b03';
const PROTOCOL='saas-synthetic-ipc-witness-receipt-v1';
const PG_PROJECTION="SELECT kind,operation FROM ("+
  "SELECT 'issued'::text AS kind,operation_id::text AS operation "+
  "FROM saas_rls_private.synthetic_operation_issues UNION ALL "+
  "SELECT 'producer'::text AS kind,operation_id::text AS operation "+
  "FROM saas_rls_private.synthetic_producer_operations) x ORDER BY kind,operation";
function sql(query) {
  const r=spawnSync('psql',['-X','-q','-A','-t','-F','|',
    '-v','ON_ERROR_STOP=1','-c',query],{
    env:sqlEnv,encoding:'utf8',timeout:12000,maxBuffer:2000000,
  });
  assert.equal(r.status,0,'Disposable postgres SQL failure: '+(r.stderr||''));
  return r.stdout.trim();
}
function observed() {return projectionFromSql(sql(PG_PROJECTION));}
function issue(uuid) {
  assert.match(uuid,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  const select="SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
    "WHERE operation_id='"+uuid+"'::uuid";
  assert.equal(sql(select),'0','Disposable UUID fixture collision');
  sql("BEGIN; INSERT INTO saas_rls_private.synthetic_operation_issues "+
    "(operation_id,tenant_id,actor_id,membership_role,collection,"+
    "requested_limit,issued_at,issue_expires_at,recovery_expires_at) VALUES "+
    "('"+uuid+"'::uuid,'ci-ipc-witness','ci-ipc-actor','tenant-viewer',"+
    "'projects',1,clock_timestamp(),clock_timestamp()+interval '2 minutes',"+
    "clock_timestamp()+interval '2 hours'); COMMIT;");
  assert.equal(sql(select),'1','Physical PG16 COMMIT not visible independently');
}
function createDaemon(where=state,path=sock,extra={}) {
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,[serverFile,where,path],{
      env:{...offlineEnv,...extra},stdio:['ignore','pipe','pipe'],
    });
    let complete=false,error='',stdout='';
    const deadline=setTimeout(()=>{
      if(complete)return;
      complete=true;
      child.kill('SIGKILL');
      reject(Error('Witness IPC process readiness deadline: '+error));
    },7000);
    child.stderr.on('data',part=>{error+=String(part);});
    child.stdout.on('data',part=>{
      stdout+=String(part);
      if(stdout.includes('READY:')&&!complete) {
        complete=true;
        clearTimeout(deadline);
        resolve(child);
      }
    });
    child.on('error',err=>{
      if(complete)return;
      complete=true;
      clearTimeout(deadline);
      reject(err);
    });
    child.on('exit',(code,signal)=>{
      if(complete)return;
      complete=true;
      clearTimeout(deadline);
      reject(Error('Witness refused startup: '+code+' '+signal+' '+error));
    });
  });
}
function exchange(path,payload) {
  return new Promise((resolve,reject)=>{
    const connection=connect({path});
    let complete=false,buffer='';
    const expire=setTimeout(()=>{
      if(complete)return;
      complete=true;
      connection.destroy();
      reject(Error('Witness IPC request timed out: DENY'));
    },5000);
    function done(error,result) {
      if(complete)return;
      complete=true;
      clearTimeout(expire);
      connection.destroy();
      if(error)reject(error);
      else resolve(result);
    }
    connection.setEncoding('utf8');
    connection.on('connect',()=>connection.write(JSON.stringify(payload)+'\n'));
    connection.on('data',part=>{
      buffer+=String(part);
      if(buffer.length>1000000)return done(Error('Oversized witness reply'));
      if(buffer.includes('\n')){
        try {
          const [line,...rest]=buffer.split('\n');
          assert.equal(rest.join('').trim(),'','Malformed witness reply framing');
          done(null,JSON.parse(line));
        }catch(error){done(error);}
      }
    });
    connection.on('end',()=>{
      if(!complete)done(Error('Witness disconnected without signed receipt: DENY'));
    });
    connection.on('error',error=>done(error));
  });
}
async function denied(path,payload) {
  const response=await exchange(path,payload);
  assert.deepEqual(response,{ok:false,error:'DENIED'},
    'Required fail-closed IPC denial not returned');
}
async function unavailable(path,payload) {
  await assert.rejects(exchange(path,payload),
    'A lost socket must never count as an authoritative ACK');
}
function pin(reply,pub,requestId,projection,expected) {
  assert.equal(reply?.ok,true);
  assert.equal(reply.state,'SEALED');
  assert.equal(reply.gcPermitted,false);
  const payload=verifyEnvelope(reply.envelope,pub);
  assert.deepEqual(payload.projection,canonicalProjection(projection));
  assert.deepEqual(reply.head,{
    sequence:payload.sequence,digest:envelopeDigest(reply.envelope)});
  assert.equal(payload.sequence,(expected?.sequence??0)+1);
  assert.equal(payload.previous,expected?.digest??null);
  const receipt=reply.receipt;
  assert.deepEqual(receipt.data,{
    protocol:PROTOCOL,requestId,
    sequence:reply.head.sequence,digest:reply.head.digest,
  });
  const signed=Buffer.from(receipt.signature,'base64url');
  assert.equal(signed.length,64);
  assert.equal(edVerify(null,Buffer.from(PROTOCOL+'\n'+
    JSON.stringify(receipt.data)),pub,signed),true,
    'Invalid witness receipt signature');
  return reply.head;
}
function record(requestId,expected,projection) {
  return {op:'append',requestId,expected,projection};
}
async function terminate(child,kill=false) {
  if(child.exitCode!==null||child.signalCode!==null)return;
  const exit=once(child,'exit');
  child.kill(kill?'SIGKILL':'SIGTERM');
  await exit;
}
async function failedStart(where,path,extra={}) {
  await assert.rejects(createDaemon(where,path,extra),
    /Witness refused startup|readiness deadline/,
    'Corrupt witness journal unexpectedly served requests');
}
function clone(from,to) {cpSync(from,to,{recursive:true});}
let server=null;
try {
  assert.equal(sql('SELECT current_database()'),'saas_ephemeral_test');
  assert.equal(sql("SELECT gc_permitted::text FROM "+
    "saas_rls_private.synthetic_operation_retention_health('demo-north')"),'false');
  const auditCount=sql('SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox');
  const initial=observed();
  assert.ok(initial.issuedCount>0&&initial.producerCount>0);
  server=await createDaemon();
  assert.ok(existsSync(join(state,'public.pem')));
  const pub=readFileSync(join(state,'public.pem'),'utf8');
  const request1=freshId();
  const first=await exchange(sock,record(request1,null,initial));
  const head1=pin(first,pub,request1,initial,null);
  const oldReply=await exchange(sock,{op:'check',projection:initial});
  assert.equal(oldReply.head.digest,head1.digest);
  const firstState=join(work,'saved-genesis-state');
  clone(state,firstState);
  console.info('PASS: test-only Unix socket witness daemon owns Ed25519 key and fsynced genesis; client verifies signed receipt');

  // Real PostgreSQL16 COMMIT happens before any separate witness append.
  // The old signed head cannot claim this new immutable UUID is covered.
  issue(ISSUE1);
  const newSet=observed();
  assert.equal(newSet.issuedCount,initial.issuedCount+1);
  await denied(sock,{op:'check',projection:newSet});
  await terminate(server);
  server=null;
  await unavailable(sock,{op:'check',projection:newSet});
  server=await createDaemon();
  assert.equal(readFileSync(join(state,'public.pem'),'utf8'),pub,
    'Restart must retain originally pinned witness key');
  await denied(sock,{op:'check',projection:newSet});
  console.info('PASS: PG COMMIT while IPC witness unavailable is UNSIGNED; socket partition and daemon restart deny');

  // Simulate losing the ACK after fsync of BOTH signed checkpoint and head.
  // The caller gets disconnect, NOT any success signal. On restart the
  // SAME request id + same predecessor + same projection replays receipt.
  await terminate(server);
  server=null;
  server=await createDaemon(state,sock,{SAAS_WITNESS_TEST_LOSE_ACK:'2'});
  const request2=freshId();
  const proposal2=record(request2,head1,newSet);
  await unavailable(sock,proposal2);
  await terminate(server,true);
  server=null;
  assert.ok(existsSync(join(state,'head.json')),
    'Ack loss must happen after fsynced checkpoint/head publication');
  if(existsSync(sock))unlinkSync(sock); // stale test-only socket after SIGKILL
  server=await createDaemon();
  const replay=await exchange(sock,proposal2);
  const head2=pin(replay,pub,request2,newSet,head1);
  const replayAgain=await exchange(sock,proposal2);
  assert.deepEqual(replayAgain,replay,
    'UNKNOWN witness ACK must replay exact durable receipt without new head');
  const current=await exchange(sock,{op:'head'});
  assert.equal(current.head.sequence,2,'No duplicate signed witness checkpoint');
  await denied(sock,record(request2,head1,initial));
  await denied(sock,record(freshId(),head1,newSet));
  await denied(sock,record(freshId(),head2,newSet));
  console.info('PASS: fsynced witness append lost ACK; after fresh process restart same signed receipt replays once');

  // A second independently committed UUID has two concurrent append
  // requests with the SAME old expected head. Single-process event loop
  // serializes them. Exactly one receives an authentic signed receipt.
  issue(ISSUE2);
  const next=observed();
  await denied(sock,{op:'check',projection:next});
  const request3a=freshId(),request3b=freshId();
  const [ra,rb]=await Promise.all([
    exchange(sock,record(request3a,head2,next)),
    exchange(sock,record(request3b,head2,next)),
  ]);
  const admitted=[ra,rb].filter(x=>x?.ok===true);
  assert.equal(admitted.length,1,'Two competing IPC writers both acquired same head');
  const rejected=[ra,rb].filter(x=>x?.ok===false);
  assert.equal(rejected.length,1);
  assert.deepEqual(rejected[0],{ok:false,error:'DENIED'});
  const chosen=ra.ok?request3a:request3b;
  const head3=pin(admitted[0],pub,chosen,next,head2);
  const idempotent=await exchange(sock,record(chosen,head2,next));
  assert.deepEqual(idempotent,admitted[0]);
  const checkNext=await exchange(sock,{op:'check',projection:next});
  assert.deepEqual(checkNext.head,head3);
  const checkpoint3=join(state,'checkpoints','00000003.json');
  assert.ok(existsSync(checkpoint3),'At least one fsynced record must survive');
  console.info('PASS: two concurrent stale IPC publishers serialize; one durable signed head, other DENY');

  // A crash between checkpoint fsync and head fsync must NOT result in a
  // silent self-healing restore, even if the source PG COMMIT succeeded.
  const damaged=join(work,'crashed-witness-state');
  const damagedSock=join(work,'damaged.sock');
  clone(state,damaged);
  issue(ISSUE3);
  const newest=observed();
  await denied(sock,{op:'check',projection:newest});
  const crashed=await createDaemon(damaged,damagedSock,{
    SAAS_WITNESS_TEST_KILL_BEFORE_HEAD:'4'});
  await unavailable(damagedSock,record(freshId(),head3,newest));
  await terminate(crashed,true);
  if(existsSync(damagedSock))unlinkSync(damagedSock);
  assert.ok(existsSync(join(damaged,'checkpoints','00000004.json')));
  await failedStart(damaged,damagedSock);
  await denied(sock,{op:'check',projection:newest});
  // Only the intact original publisher may sign the later committed UUID.
  const request4=freshId();
  const sealed4=await exchange(sock,record(request4,head3,newest));
  pin(sealed4,pub,request4,newest,head3);
  const verifyLatest=await exchange(sock,{op:'check',projection:newest});
  assert.equal(verifyLatest.head.sequence,4);
  console.info('PASS: kill after checkpoint fsync before head leaves orphan; restarted witness refuses damaged state');

  // One runner remains one trust domain: if the signing state AND a
  // caller-held trusted head are jointly rolled back, stale history can
  // appear consistent. Explicit proof of unresolved production gate.
  const historicalSock=join(work,'stale.sock');
  const historical=await createDaemon(firstState,historicalSock);
  const stale=await exchange(historicalSock,{op:'head'});
  assert.equal(stale.head.sequence,1);
  assert.notDeepEqual(stale.head,verifyLatest.head);
  await terminate(historical);
  console.info('LIMITATION: all-local witness state plus lost client pin can roll back; off-host durable root still SPEC');

  // Daemon must NOT launch with SQL credentials, never reading PG directly.
  const forbidden=spawnSync(process.execPath,[serverFile,state,join(work,'forbidden.sock')],{
    env:{...offlineEnv,PGHOST:'127.0.0.1'},
    encoding:'utf8',timeout:3000,
  });
  assert.notEqual(forbidden.status,0,'Witness daemon unexpectedly accepted PGHOST');
  assert.match(forbidden.stderr||'',/Refusing witness daemon/);
  assert.equal(sql('SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox'),
    auditCount,'Witness never created audit or 013 event');
  assert.equal(sql("SELECT gc_permitted::text FROM "+
    "saas_rls_private.synthetic_operation_retention_health('demo-north')"),
    'false');
  const serialized=JSON.stringify(sealed4);
  assert.ok(!serialized.includes(ISSUE3)&&
    !serialized.includes('ci-ipc-actor'),'Raw operation/tenant data leaked');
  assert.deepEqual(canonicalProjection(newest),newest);
  console.info('PASS: read-only Unix witness has no PG credentials, payload, issue authority or GC permission');
}finally {
  if(server)await terminate(server).catch(()=>{});
  rmSync(work,{recursive:true,force:true});
}
