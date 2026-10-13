#!/usr/bin/env node
// Stages 2G.4d.7q/7r/7s: physical disposable PostgreSQL16,
// attested local witness + high-water; optional offline UNKNOWN observer.
// ONE CI RUNNER, NOT WORM, atomic issuer settlement or GC.
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {connect} from 'node:net';
import {
  mkdtempSync,mkdirSync,chmodSync,readFileSync,writeFileSync,cpSync,rmSync,
  existsSync,unlinkSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  generateKeyPairSync,randomBytes,createHash,createPublicKey,
  verify as edVerify,
} from 'node:crypto';
import {envelopeDigest,verifyEnvelope,verifyCheckpoint,projectionFromSql}
  from './archive-witness-protocol.mjs';

const ROLE='saas_witness_projection_7o',DB='saas_ephemeral_test';
const JPROTOCOL='saas-synthetic-ipc-highwater-receipt-v1';
const RPROTOCOL='saas-synthetic-ipc-witness-receipt-v1';
const extended=process.env.SAAS_EPHEMERAL_UNKNOWN_OBSERVATION_CI==='true';
const reviewStage=process.env.SAAS_EPHEMERAL_MANUAL_REVIEW_CI==='true';
if(reviewStage&&!extended)throw Error('7s requires 7r observation proof');
const ci=process.env.GITHUB_ACTIONS==='true'&&
  process.env.SAAS_EPHEMERAL_HIGHWATER_TEST_CI==='true'&&
  process.env.PGHOST==='127.0.0.1'&&process.env.PGPORT==='5432'&&
  process.env.PGUSER==='postgres'&&process.env.PGDATABASE===DB&&
  !process.env.RAILWAY_ENVIRONMENT&&!process.env.RAILWAY_PROJECT_ID&&
  !process.env.SAAS_PRODUCTION_DATABASE_URL;
if(!ci)throw Error('High-water E2E refused outside disposable PG16 CI');
const work=mkdtempSync(join(tmpdir(),'saas-ipc-witness-'));
chmodSync(work,0o700);
const witnessFile=fileURLToPath(new URL('./archive-witness-ipc-server.mjs',import.meta.url));
const journalFile=fileURLToPath(new URL('./archive-witness-highwater-ipc.mjs',import.meta.url));
const projectorFile=fileURLToPath(new URL('./archive-witness-pg-projection-proof.mjs',import.meta.url));
const observerFile=fileURLToPath(new URL('./archive-witness-unknown-observer.mjs',import.meta.url));
const reviewerFile=fileURLToPath(new URL('./archive-witness-manual-review-pin.mjs',import.meta.url));
const state=join(work,'witness-state'),socket=join(work,'witness.sock');
const journalState=join(work,'highwater-state'),journalSocket=join(work,'highwater.sock');
const attPriv=join(work,'projector-private.pem'),attPub=join(work,'projector-public.pem');
const reviewDir=join(work,'reviewer-custody');
const reviewPriv=join(reviewDir,'private.pem'),reviewPub=join(reviewDir,'public.pem');
const reviewerWitPub=join(state,'public.pem'),reviewerHiPub=join(journalState,'public.pem');
const password=randomBytes(24).toString('hex');
const sqlEnv={...process.env,PGCONNECT_TIMEOUT:'5'};
const restrictedEnv={
  GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_PROJECTOR_PROOF_CI:'true',
  PGHOST:'127.0.0.1',PGPORT:'5432',PGUSER:ROLE,
  PGDATABASE:DB,PGPASSWORD:password,PGCONNECT_TIMEOUT:'5',
  PATH:process.env.PATH||'/usr/bin:/bin',HOME:work,LANG:'C',
};
const ipcEnv={
  GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_IPC_WITNESS_CI:'true',
  SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
  SAAS_EPHEMERAL_PG_WITNESS_PROOF_CI:'true',
  SAAS_EPHEMERAL_PROJECTOR_PUBKEY_PATH:attPub,
  PATH:process.env.PATH||'/usr/bin:/bin',HOME:work,LANG:'C',
};
const journalEnv={
  GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_IPC_WITNESS_CI:'true',
  SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
  SAAS_EPHEMERAL_HIGHWATER_CI:'true',
  PATH:process.env.PATH||'/usr/bin:/bin',HOME:work,LANG:'C',
};
const ids=reviewStage?[
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa8101',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa8102',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa8103',
]:extended?[
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7f01',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7f02',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7f03',
]:[
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7e01',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7e02',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7e03',
];
const preCommitUuid=reviewStage?
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa8100':
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7f00';
const driftUuid=reviewStage?[
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa8104',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa8105',
]:[
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7f04',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7f05',
];
const reviewEnv={
  GITHUB_ACTIONS:'true',
  SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
  SAAS_EPHEMERAL_MANUAL_REVIEW_CI:'true',
  PATH:process.env.PATH||'/usr/bin:/bin',HOME:reviewDir,LANG:'C',
};
const observerEnv={
  GITHUB_ACTIONS:'true',
  SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
  SAAS_EPHEMERAL_UNKNOWN_OBSERVATION_CI:'true',
  PATH:process.env.PATH||'/usr/bin:/bin',HOME:work,LANG:'C',
};
const freshId=()=>randomBytes(16).toString('hex');
const hash=v=>createHash('sha256').update(v).digest('hex');
const fingerprint=pem=>hash(createPublicKey(pem)
  .export({type:'spki',format:'der'}));
let hasRole=false,witness=null,journal=null,serial=0,observationCount=0,reviewCount=0;
const other=new Set();
let reviewPin1=null,reviewPin2=null,reviewPin3=null,reviewPin4=null;
function command(cmd,args,env,deny=false) {
  const output=spawnSync(cmd,args,{env,cwd:work,encoding:'utf8',
    timeout:15000,maxBuffer:2000000});
  if(deny)assert.notEqual(output.status,0,
    'Expected failure but command succeeded: '+cmd);
  else assert.equal(output.status,0,
    'Command failed: '+(output.stderr||'').slice(0,600));
  return (output.stdout||'').trim();
}
function sql(query) {
  return command('psql',['-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
    '--dbname',DB,'-c',query],sqlEnv);
}
function restricted(query,deny=false) {
  return command('psql',['-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
    '--dbname',DB,'-c',query],restrictedEnv,deny);
}
function issueSql(uuid) {
  assert.match(uuid,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  return "INSERT INTO saas_rls_private.synthetic_operation_issues "+
    "(operation_id,tenant_id,actor_id,membership_role,collection,"+
    "requested_limit,issued_at,issue_expires_at,recovery_expires_at) VALUES "+
    "('"+uuid+"'::uuid,'ci-7r-proof','ci-7r-actor','tenant-viewer',"+
    "'projects',1,clock_timestamp(),clock_timestamp()+interval '2 minutes',"+
    "clock_timestamp()+interval '2 hours');";
}
async function unknownCommit(uuid,afterCommit) {
  const app=afterCommit?'ci_7r_killed_post_commit':'ci_7r_killed_pre_commit';
  const query=afterCommit?
    'BEGIN;\n'+issueSql(uuid)+'\nCOMMIT;\nSELECT pg_sleep(12);\n':
    'BEGIN;\n'+issueSql(uuid)+'\nSELECT pg_sleep(12);\nCOMMIT;\n';
  const child=spawn('psql',['-X','-q','-v','ON_ERROR_STOP=1'],{
    env:{...sqlEnv,PGAPPNAME:app},stdio:['pipe','pipe','pipe'],
  });
  child.stdout.resume();
  let stderr='';
  child.stderr.on('data',part=>{stderr+=String(part);});
  const finished=once(child,'exit');
  child.stdin.end(query);
  let staged=false;
  for(let i=0;i<130;i++) {
    const current=sql("SELECT COUNT(*) FROM pg_stat_activity WHERE "+
      "application_name='"+app+"' AND wait_event='PgSleep'");
    if(current==='1'){staged=true;break;}
    await new Promise(resolve=>setTimeout(resolve,35));
  }
  assert.ok(staged,'Physical pre/post COMMIT disconnect probe was not staged');
  const killed=sql("SELECT COUNT(*) FROM (SELECT pg_terminate_backend(pid) "+
    "AS terminated FROM pg_stat_activity WHERE application_name='"+
    app+"') q WHERE terminated");
  assert.equal(killed,'1','Expected independent PG backend termination');
  const [exitCode]=await finished;
  assert.notEqual(exitCode,0,'Unknown caller unexpectedly received COMMIT ACK');
  assert.ok(stderr.length>0,'Expected PostgreSQL disconnection evidence');
  assert.equal(sql("SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
    "WHERE operation_id='"+uuid+"'::uuid"),afterCommit?'1':'0',
    'Physical PostgreSQL COMMIT/ROLLBACK outcome not independently observed');
}
function commit(uuid) {
  const query="SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
    "WHERE operation_id='"+uuid+"'::uuid";
  assert.equal(sql(query),'0');
  sql("BEGIN; INSERT INTO saas_rls_private.synthetic_operation_issues "+
    "(operation_id,tenant_id,actor_id,membership_role,collection,"+
    "requested_limit,issued_at,issue_expires_at,recovery_expires_at) VALUES "+
    "('"+uuid+"'::uuid,'ci-7q-proof','ci-7q-actor','tenant-viewer',"+
    "'projects',1,clock_timestamp(),clock_timestamp()+interval '2 minutes',"+
    "clock_timestamp()+interval '2 hours'); COMMIT;");
  assert.equal(sql(query),'1');
}
function start(file,args,env) {
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,[file,...args],{
      env,stdio:['ignore','pipe','pipe'],
    });
    let finished=false,stdout='',stderr='';
    const timer=setTimeout(()=>{
      if(finished)return;
      finished=true;child.kill('SIGKILL');
      reject(Error('Readiness timeout: '+stderr));
    },8000);
    child.stderr.on('data',part=>{stderr+=String(part);});
    child.stdout.on('data',part=>{
      stdout+=String(part);
      if(!finished&&stdout.includes('READY:')) {
        finished=true;clearTimeout(timer);resolve(child);
      }
    });
    child.on('error',err=>{
      if(finished)return;finished=true;clearTimeout(timer);reject(err);
    });
    child.on('exit',(code,signal)=>{
      if(finished)return;finished=true;clearTimeout(timer);
      reject(Error('Server refused startup: '+code+' '+signal+' '+stderr));
    });
  });
}
function startWitness(where=state,path=socket,extra={},fenced=true) {
  const options=fenced?{
    SAAS_EPHEMERAL_HIGHWATER_CI:'true',
    SAAS_EPHEMERAL_HIGHWATER_SOCKET_PATH:journalSocket,
    SAAS_EPHEMERAL_HIGHWATER_PUBLIC_KEY_PATH:join(journalState,'public.pem'),
  }:{};
  return start(witnessFile,[where,path],{...ipcEnv,...options,...extra});
}
function startJournal(where=journalState,path=journalSocket,extra={}) {
  return start(journalFile,['serve',where,path,join(state,'public.pem')],
    {...journalEnv,...extra});
}
function exchange(path,req) {
  return new Promise((resolve,reject)=>{
    const connection=connect({path});
    let complete=false,bytes='';
    const timer=setTimeout(()=>done(Error('IPC response deadline')),6000);
    function done(error,answer) {
      if(complete)return;
      complete=true;clearTimeout(timer);connection.destroy();
      if(error)reject(error);else resolve(answer);
    }
    connection.setEncoding('utf8');
    connection.on('connect',()=>connection.write(JSON.stringify(req)+'\n'));
    connection.on('data',part=>{
      bytes+=String(part);
      if(bytes.length>200000)return done(Error('Oversized IPC reply'));
      if(bytes.includes('\n')) {
        try {
          const [first,...rest]=bytes.split('\n');
          assert.equal(rest.join('').trim(),'');
          done(null,JSON.parse(first));
        }catch(error){done(error);}
      }
    });
    connection.on('end',()=>{
      if(!complete)done(Error('IPC disconnected: UNKNOWN'));
    });
    connection.on('error',err=>done(err));
  });
}
async function denied(path,body) {
  assert.deepEqual(await exchange(path,body),
    {ok:false,error:'DENIED'},'Expected explicit fail-closed denial');
}
async function lost(path,body) {
  await assert.rejects(exchange(path,body),
    'Disconnected publisher may not count as success');
}
async function stop(child,hard=false) {
  if(!child||child.exitCode!==null||child.signalCode!==null)return;
  const done=once(child,'exit');
  child.kill(hard?'SIGKILL':'SIGTERM');
  await done;
}
async function failedStart(file,args,env) {
  await assert.rejects(start(file,args,env),
    /Server refused startup|Readiness timeout/,
    'Stale journal/head must never restart as safe');
}
function save(name,data) {
  const filename=join(work,name);
  writeFileSync(filename,JSON.stringify(data)+'\n',{flag:'wx',mode:0o600});
  return filename;
}
function candidate(uuid,baselineHead) {
  return {
    protocol:'saas-synthetic-uuid-unknown-commit-v1',kind:'issued',
    commitment:projectionFromSql('issued|'+uuid).issued[0],
    baselineHead,
  };
}
function observation(ch,proof,env,previous,journalReceipt,pinnedHead,
  prepared,{deny=false,projectorKey=attPub,
    witnessKey=join(state,'public.pem'),
    highwaterKey=join(journalState,'public.pem'),
    processEnv=observerEnv}={}) {
  const index=String(++observationCount);
  const paths=[
    save('7r-observer-challenge-'+index+'.json',ch),
    save('7r-observer-proof-'+index+'.json',proof),
    save('7r-observer-envelope-'+index+'.json',env),
    previous?save('7r-observer-previous-'+index+'.json',previous):'-',
    save('7r-observer-journal-'+index+'.json',journalReceipt),
    save('7r-observer-pinned-'+index+'.json',pinnedHead),
    save('7r-observer-candidate-'+index+'.json',prepared),
  ];
  const result=spawnSync(process.execPath,[observerFile,'verify',
    projectorKey,witnessKey,highwaterKey,...paths,'--no-gc'],{
    env:processEnv,cwd:work,encoding:'utf8',timeout:15000,maxBuffer:250000,
  });
  if(deny) {
    assert.notEqual(result.status,0,
      'Unsafe observation accepted as valid: '+index);
    assert.match(result.stderr||'',/RECONCILIATION DENIED:/);
    return null;
  }
  assert.equal(result.status,0,
    'Signed offline observation unexpectedly denied: '+(result.stderr||''));
  const data=JSON.parse(result.stdout.trim());
  assert.equal(data.protocol,'saas-synthetic-unknown-outcome-observation-v1');
  assert.equal(data.sourceSnapshotOnly,true);
  assert.equal(data.locallySignedOnly,true);
  for(const field of ['authorizationGranted','reissuePermitted',
    'retryPermitted','deliveryPermitted','gcPermitted'])
    assert.equal(data[field],false,'Offline observer must not grant '+field);
  assert.ok(!JSON.stringify(data).includes('ci-7r-actor')&&
    !JSON.stringify(data).includes('aaaaaaaa-aaaa'),
    'Observer leaked raw actor or operation UUID');
  return data;
}
function setupReviewer() {
  mkdirSync(reviewDir,{mode:0o700});
  chmodSync(reviewDir,0o700);
  const pair=generateKeyPairSync('ed25519');
  writeFileSync(reviewPriv,pair.privateKey.export({type:'pkcs8',format:'pem'}),
    {flag:'wx',mode:0o600});
  writeFileSync(reviewPub,pair.publicKey.export({type:'spki',format:'pem'}),
    {flag:'wx',mode:0o600});
}
function reviewExec(action,args,{deny=false,env=reviewEnv}={}) {
  const result=spawnSync(process.execPath,[reviewerFile,action,...args],{
    cwd:work,env,encoding:'utf8',timeout:15000,maxBuffer:250000,
  });
  if(deny) {
    assert.notEqual(result.status,0,
      'Expected simulated review pin/inspection DENY, got SUCCESS');
    assert.match(result.stderr||'',/MANUAL REVIEW DENIED:/);
    return null;
  }
  assert.equal(result.status,0,
    'Review-only command refused trusted test inputs: '+result.stderr);
  const parsed=JSON.parse(result.stdout.trim());
  assert.equal(parsed.protocol,'saas-synthetic-manual-review-pin-v1');
  assert.equal(parsed.manualReviewRequired,true);
  for(const field of ['authorizationGranted','reissuePermitted',
    'retryPermitted','deliveryPermitted','gcPermitted'])
    assert.equal(parsed[field],false,'Reviewer tool may not grant '+field);
  assert.ok(!JSON.stringify(parsed).includes('aaaaaaaa-aaaa')&&
    !JSON.stringify(parsed).includes('ci-7r-actor'),
    'Manual-only reviewer exposed raw UUID/actor');
  return parsed;
}
function createReviewPin(envelope,journalReceipt,previous=null,{
  deny=false,previousFile=previous,output=null,
  highwaterKey=reviewerHiPub,witnessKey=reviewerWitPub,
  privateKey=reviewPriv,publicKey=reviewPub,
}={}) {
  const id=String(++reviewCount);
  const headFile=save('7s-review-envelope-'+id+'.json',envelope);
  const journalFile=save('7s-review-journal-'+id+'.json',journalReceipt);
  const target=output??join(reviewDir,'anchor-'+id+'.json');
  const args=[
    privateKey,publicKey,witnessKey,highwaterKey,headFile,journalFile,
    previousFile??'-',target,'--no-gc',
  ];
  const response=reviewExec('pin',args,{deny});
  if(deny)return null;
  assert.equal(response.kind,'SIMULATED_REVIEW_PIN_WRITTEN');
  assert.deepEqual(response.head,{
    sequence:envelope.payload.sequence,digest:envelopeDigest(envelope),
  });
  assert.ok(existsSync(target));
  return target;
}
function reviewInspect(envelope,journalReceipt,pinPath,{
  deny=false,publicKey=reviewPub,witnessKey=reviewerWitPub,
  highwaterKey=reviewerHiPub,env=reviewEnv,
}={}) {
  const id=String(++reviewCount);
  const headFile=save('7s-check-envelope-'+id+'.json',envelope);
  const journalFile=save('7s-check-journal-'+id+'.json',journalReceipt);
  const args=[publicKey,witnessKey,highwaterKey,
    headFile,journalFile,pinPath,'--no-gc'];
  const report=reviewExec('inspect',args,{deny,env});
  if(deny)return null;
  assert.equal(report.offHostAnchorVerified,false,
    'Same-runner proof must never assert independent remote authority');
  assert.equal(report.repairPermitted,false);
  assert.equal(report.locallySignedOnly,true);
  return report.status;
}
async function raceReviewPin(envelope,journalReceipt,previous,target) {
  const id=String(++reviewCount);
  const envPath=save('7s-race-envelope-'+id+'.json',envelope);
  const journalPath=save('7s-race-journal-'+id+'.json',journalReceipt);
  const args=['pin',reviewPriv,reviewPub,reviewerWitPub,reviewerHiPub,
    envPath,journalPath,previous,target,'--no-gc'];
  function attempt() {
    return new Promise((resolve,reject)=>{
      const child=spawn(process.execPath,[reviewerFile,...args],{
        cwd:work,env:reviewEnv,stdio:['ignore','pipe','pipe'],
      });
      let stdout='',stderr='';
      child.stdout.on('data',v=>{stdout+=String(v);});
      child.stderr.on('data',v=>{stderr+=String(v);});
      child.on('error',reject);
      child.on('exit',(code,signal)=>resolve({code,signal,stdout,stderr}));
    });
  }
  const results=await Promise.all([attempt(),attempt()]);
  assert.equal(results.filter(x=>x.code===0).length,1,
    'Two simulated reviewer writers must not both overwrite one pin');
  assert.equal(results.filter(x=>x.code!==0).length,1);
  assert.match(results.find(x=>x.code!==0).stderr,/MANUAL REVIEW DENIED:/);
  assert.ok(existsSync(target));
  const receipt=JSON.parse(readFileSync(target,'utf8'));
  assert.deepEqual(receipt.data.head,{
    sequence:envelope.payload.sequence,digest:envelopeDigest(envelope),
  });
  return target;
}
function source(challenge) {
  const n=String(++serial);
  const chfile=save('7q-challenge-'+n+'.json',challenge);
  const output=join(work,'7q-attestation-'+n+'.json');
  command(process.execPath,[projectorFile,'attest',attPriv,attPub,chfile,output],
    restrictedEnv);
  return JSON.parse(readFileSync(output,'utf8'));
}
async function challenge(requestId,expected,path=socket) {
  const res=await exchange(path,{op:'challenge-pg',requestId,expected});
  assert.equal(res.ok,true);assert.equal(res.gcPermitted,false);
  assert.equal(res.requestId,requestId);
  assert.deepEqual(res.challenge.expected,expected);
  assert.match(res.challenge.nonce,/^[0-9a-f]{32}$/);
  return res.challenge;
}
const proposal=(requestId,expected,proof)=>({
  op:'append-pg',requestId,expected,attestation:proof,
});
function verifyJournal(receipt,expected,publicPem,witnessPem) {
  assert.deepEqual(receipt.data,{
    protocol:JPROTOCOL,
    witnessFingerprint:fingerprint(witnessPem),
    head:expected,
  });
  assert.equal(edVerify(null,Buffer.from(JPROTOCOL+'\n'+
    JSON.stringify(receipt.data)),publicPem,
    Buffer.from(receipt.signature,'base64url')),true,
    'Independent journal signature not valid');
}
async function checkedJournal(head,path=journalSocket,dir=journalState) {
  const r=await exchange(path,{op:'status'});
  assert.equal(r.ok,true);assert.equal(r.gcPermitted,false);
  assert.equal(r.state,'HIGHWATER');
  verifyJournal(r.receipt,head,
    readFileSync(join(dir,'public.pem'),'utf8'),
    readFileSync(join(state,'public.pem'),'utf8'));
  return r.receipt;
}
function verifyWitness(reply,expected,priorEnvelope,requestId) {
  assert.equal(reply.ok,true);
  assert.equal(reply.state,'SEALED');
  assert.equal(reply.gcPermitted,false);
  const pem=readFileSync(join(state,'public.pem'),'utf8');
  const payload=verifyEnvelope(reply.envelope,pem);
  const head={sequence:payload.sequence,digest:envelopeDigest(reply.envelope)};
  assert.equal(payload.sequence,(expected?.sequence??0)+1);
  assert.equal(payload.previous,expected?.digest??null);
  assert.deepEqual(reply.head,head);
  verifyCheckpoint(reply.envelope,pem,head,payload.projection,priorEnvelope);
  assert.deepEqual(reply.receipt.data,{
    protocol:RPROTOCOL,requestId,
    sequence:head.sequence,digest:head.digest,
  });
  assert.equal(edVerify(null,Buffer.from(RPROTOCOL+'\n'+
    JSON.stringify(reply.receipt.data)),pem,
    Buffer.from(reply.receipt.signature,'base64url')),true);
  return head;
}
function clone(src,dest) {cpSync(src,dest,{recursive:true});}
function staleSocket(path) {if(existsSync(path))unlinkSync(path);}
function fencedEnv(socketPath=journalSocket,pubPath=join(journalState,'public.pem')) {
  return {...ipcEnv,SAAS_EPHEMERAL_HIGHWATER_CI:'true',
    SAAS_EPHEMERAL_HIGHWATER_SOCKET_PATH:socketPath,
    SAAS_EPHEMERAL_HIGHWATER_PUBLIC_KEY_PATH:pubPath};
}
try {
  assert.equal(sql('SELECT current_database()'),DB);
  assert.equal(sql("SELECT COUNT(*) FROM pg_roles WHERE rolname='"+ROLE+"'"),'0');
  const oldAudit=sql('SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox');
  assert.equal(sql("SELECT gc_permitted::text FROM "+
    "saas_rls_private.synthetic_operation_retention_health('demo-north')"),'false');
  sql("CREATE ROLE "+ROLE+" WITH LOGIN NOINHERIT PASSWORD '"+password+"';"+
    "GRANT CONNECT ON DATABASE "+DB+" TO "+ROLE+";"+
    "GRANT USAGE ON SCHEMA saas_rls_private TO "+ROLE+";"+
    "GRANT SELECT (operation_id) ON "+
    "saas_rls_private.synthetic_operation_issues TO "+ROLE+";"+
    "GRANT SELECT (operation_id) ON "+
    "saas_rls_private.synthetic_producer_operations TO "+ROLE+";");
  hasRole=true;
  restricted('SELECT operation_id FROM saas_rls_private.synthetic_operation_issues LIMIT 1');
  restricted('SELECT tenant_id FROM saas_rls_private.synthetic_operation_issues',true);
  restricted('SELECT secret FROM saas_rls_private.scope_signers',true);
  const pair=generateKeyPairSync('ed25519');
  writeFileSync(attPriv,pair.privateKey.export({type:'pkcs8',format:'pem'}),
    {flag:'wx',mode:0o600});
  writeFileSync(attPub,pair.publicKey.export({type:'spki',format:'pem'}),
    {flag:'wx',mode:0o600});
  // Witness generates its OWN key inside an empty proof-only 7p state.
  // Then separate journal pins it, and witness pins the journal public key
  // before the FIRST checkpoint. No retrospective enrollment is accepted.
  witness=await startWitness(state,socket,{},false);
  assert.ok(existsSync(join(state,'public.pem')));
  await stop(witness);witness=null;
  journal=await startJournal();
  await checkedJournal(null);
  witness=await startWitness(state,socket,{SAAS_WITNESS_TEST_LOSE_ACK:'2'});
  assert.ok(existsSync(join(state,'highwater-pin.json')));
  await denied(socket,{op:'append',requestId:freshId(),expected:null,
    projection:{}});
  const req1=freshId(),proof1=source(await challenge(req1,null));
  const first=await exchange(socket,proposal(req1,null,proof1));
  const head1=verifyWitness(first,null,null,req1);
  await checkedJournal(head1);
  if(reviewStage) {
    setupReviewer();
    reviewPin1=createReviewPin(first.envelope,await checkedJournal(head1));
    assert.equal(reviewInspect(first.envelope,await checkedJournal(head1),
      reviewPin1),'PIN_MATCHED_FOR_MANUAL_INSPECTION');
    assert.equal(reviewInspect(first.envelope,await checkedJournal(head1),
      reviewPin1,{env:{...reviewEnv,PGHOST:'127.0.0.1'},deny:true}),null);
    console.info('PASS 7s: separately signed CI-only reviewer genesis pin; no SQL, reissue, repair, delivery or GC authority');
  }
  if(extended) {
    // A real PostgreSQL transaction is severed while INSERT is still
    // uncommitted. The caller sees UNKNOWN; a fresh signed read-only PG
    // snapshot that omits the candidate cannot authorize reissuance.
    await unknownCommit(preCommitUuid,false);
    const beforeCh=await challenge(freshId(),head1);
    const beforeProof=source(beforeCh);
    const absent=observation(beforeCh,beforeProof,first.envelope,null,
      await checkedJournal(head1),head1,candidate(preCommitUuid,head1));
    assert.equal(absent.status,'NOT_OBSERVED_IN_ONE_SNAPSHOT_UNKNOWN');
    console.info('PASS 7r: physical pre-COMMIT connection death stays UNKNOWN; signed source absence never authorizes retry');
  }
  const journalGenesis=join(work,'saved-journal-genesis');
  const witnessGenesis=join(work,'saved-witness-genesis');
  clone(journalState,journalGenesis);clone(state,witnessGenesis);
  console.info('PASS 7q: independently signed local high-water genesis before witness ACK, no raw UUID/DB credentials in either signer');

  // A committed UUID is NOT sufficient while separate journal is down.
  if(extended)await unknownCommit(ids[0],true);
  else commit(ids[0]);
  const req2=freshId(),ch2=await challenge(req2,head1),proof2=source(ch2);
  const preparedFirst=extended?candidate(ids[0],head1):null;
  if(extended) {
    const waiting=observation(ch2,proof2,first.envelope,null,
      await checkedJournal(head1),head1,preparedFirst);
    assert.equal(waiting.status,'PG_SNAPSHOT_ONLY_UNWITNESSED');
    console.info('PASS 7r: physical post-COMMIT connection death and signed PostgreSQL UUID remain UNWITNESSED without direct high-water successor');
  }
  const p2=proposal(req2,head1,proof2);
  await stop(journal);journal=null;
  await denied(socket,{op:'head'});
  await denied(socket,p2);
  await lost(journalSocket,{op:'status'});
  journal=await startJournal();
  await checkedJournal(head1);
  // Loss AFTER witness and journal fsync is caller UNKNOWN. Restarted
  // daemon must return EXACT earlier signed receipt without second advance.
  await lost(socket,p2);
  await stop(witness,true);witness=null;staleSocket(socket);
  const witnessRow2=JSON.parse(readFileSync(join(state,'checkpoints',
    '00000002.json'),'utf8'));
  assert.deepEqual(witnessRow2.attestation,proof2);
  const journalRow2=JSON.parse(readFileSync(join(journalState,'checkpoints',
    '00000002.json'),'utf8'));
  assert.deepEqual(journalRow2.envelope,witnessRow2.envelope);
  const head2={sequence:2,digest:envelopeDigest(journalRow2.envelope)};
  await checkedJournal(head2);
  witness=await startWitness();
  const recovered=await exchange(socket,p2);
  assert.deepEqual(recovered.envelope,journalRow2.envelope);
  assert.deepEqual(recovered.receipt,witnessRow2.receipt);
  assert.equal(recovered.head.sequence,2);
  await checkedJournal(head2);
  if(reviewStage) {
    const currentReceipt=await checkedJournal(head2);
    assert.equal(reviewInspect(recovered.envelope,currentReceipt,reviewPin1),
      'UNPINNED_LOCAL_ADVANCE_REVIEW_REQUIRED');
    reviewPin2=createReviewPin(recovered.envelope,currentReceipt,reviewPin1);
    assert.equal(reviewInspect(recovered.envelope,currentReceipt,reviewPin2),
      'PIN_MATCHED_FOR_MANUAL_INSPECTION');
    // A previous pin can never be overwritten or used as genesis of a
    // later sequence; manual reviewer chain is append-only within CI.
    createReviewPin(recovered.envelope,currentReceipt,reviewPin1,
      {output:reviewPin2,deny:true});
    createReviewPin(recovered.envelope,currentReceipt,null,{deny:true});
    const wrongKey=join(reviewDir,'wrong-reviewer-public.pem');
    writeFileSync(wrongKey,
      generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'pem'}),
      {flag:'wx',mode:0o600});
    reviewInspect(recovered.envelope,currentReceipt,reviewPin2,
      {publicKey:wrongKey,deny:true});
    reviewInspect(recovered.envelope,currentReceipt,reviewPin2,
      {witnessKey:wrongKey,deny:true});
    reviewInspect(recovered.envelope,currentReceipt,reviewPin2,
      {highwaterKey:wrongKey,deny:true});
    const alteredPin=JSON.parse(readFileSync(reviewPin2,'utf8'));
    alteredPin.data.head.digest='f'.repeat(64);
    const alteredPath=save('7s-tampered-review-pin.json',alteredPin);
    reviewInspect(recovered.envelope,currentReceipt,alteredPath,{deny:true});
    const alteredReceipt=structuredClone(currentReceipt);
    alteredReceipt.data.head.digest='f'.repeat(64);
    reviewInspect(recovered.envelope,alteredReceipt,reviewPin2,{deny:true});
    const forgedEnvelope=structuredClone(recovered.envelope);
    forgedEnvelope.payload.sequence=99;
    reviewInspect(forgedEnvelope,currentReceipt,reviewPin2,{deny:true});
    assert.equal(reviewInspect(first.envelope,currentReceipt,reviewPin2),
      'SPLIT_SIGNED_LOCAL_HEADS_REVIEW_REQUIRED');
    reviewExec('repair',[],{deny:true});
    console.info('PASS 7s: pinned direct successor after lost IPC ACK, stale reviewer pin and mismatched pair remain review-only; key/proof/overwrite/downgrade DENY');
  }
  if(extended) {
    // A fresh independent PG read and separately signed journal/witness
    // converge after lost ACK. This is OBSERVATION ONLY, not a producer
    // release/GC authorization or permission to retry the UUID.
    const currentCh=await challenge(freshId(),head2);
    const currentProof=source(currentCh);
    const high=await checkedJournal(head2);
    const latest=observation(currentCh,currentProof,recovered.envelope,
      first.envelope,high,head2,preparedFirst);
    assert.equal(latest.status,'DUAL_LOCAL_SIGNED_IDENTITY_OBSERVED');
    assert.equal(latest.reissuePermitted,false);
    assert.equal(latest.deliveryPermitted,false);
    const wrong=join(work,'7r-wrong-signer.pem');
    writeFileSync(wrong,
      generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'pem'}),
      {flag:'wx',mode:0o600});
    const fakeProof=structuredClone(currentProof);
    fakeProof.statement.projection.issuedCount++;
    observation(currentCh,fakeProof,recovered.envelope,first.envelope,
      high,head2,preparedFirst,{deny:true});
    const badNonce={...currentCh,nonce:randomBytes(16).toString('hex')};
    observation(badNonce,currentProof,recovered.envelope,first.envelope,
      high,head2,preparedFirst,{deny:true});
    const otherHead={sequence:head2.sequence,digest:'f'.repeat(64)};
    observation(currentCh,currentProof,recovered.envelope,first.envelope,
      high,otherHead,preparedFirst,{deny:true});
    observation(currentCh,currentProof,recovered.envelope,first.envelope,
      high,head2,preparedFirst,{deny:true,projectorKey:wrong});
    observation(currentCh,currentProof,recovered.envelope,first.envelope,
      high,head2,preparedFirst,{deny:true,highwaterKey:wrong});
    observation(currentCh,currentProof,recovered.envelope,first.envelope,
      high,head2,preparedFirst,{deny:true,witnessKey:wrong});
    const alteredHigh=structuredClone(high);
    alteredHigh.data.head.digest='f'.repeat(64);
    observation(currentCh,currentProof,recovered.envelope,first.envelope,
      alteredHigh,head2,preparedFirst,{deny:true});
    observation(currentCh,proof2,recovered.envelope,first.envelope,
      high,head2,preparedFirst,{deny:true});
    observation(currentCh,currentProof,recovered.envelope,null,
      high,head2,preparedFirst,{deny:true});
    observation(currentCh,currentProof,recovered.envelope,first.envelope,
      high,head2,{...preparedFirst,commitment:'f'.repeat(64)},
      {deny:true});
    observation(currentCh,currentProof,recovered.envelope,first.envelope,
      high,head2,{...preparedFirst,baselineHead:head2},
      {deny:true});
    observation(currentCh,currentProof,recovered.envelope,first.envelope,
      high,head2,{...preparedFirst,unknown:'smuggled'},{deny:true});
    observation(currentCh,currentProof,recovered.envelope,first.envelope,
      high,head2,preparedFirst,{
        deny:true,processEnv:{...observerEnv,PGHOST:'127.0.0.1'},
      });
    console.info('PASS 7r: 3-source signed observation after lost ACK, all reissue/delivery/GC flags false; forged nonce/key/proof/head/candidate/PG-credential verifier deny');
  }
  console.info('PASS 7q: journal outage DENY; fsynced journal+witness lose ACK -> identical signed receipt after restart');

  // Independent rollback: either only witness OR only high-water is
  // stale, so protected witness startup must refuse the mismatch.
  const staleWitnessSocket=join(work,'rewound-witness.sock');
  await failedStart(witnessFile,[witnessGenesis,staleWitnessSocket],
    fencedEnv());
  const staleJournalSocket=join(work,'rewound-journal.sock');
  const oldJournal=await startJournal(journalGenesis,staleJournalSocket);
  other.add(oldJournal);
  await checkedJournal(head1,staleJournalSocket,journalGenesis);
  await failedStart(witnessFile,[state,join(work,'newer-witness.sock')],
    fencedEnv(staleJournalSocket,join(journalGenesis,'public.pem')));
  // A separately trusted journal is still one local CI trust domain.
  // Cloning BOTH old roots can fool a caller that also lost the new pin.
  const oldWitness=await startWitness(witnessGenesis,
    join(work,'joint-rollback.sock'),{
      SAAS_EPHEMERAL_HIGHWATER_SOCKET_PATH:staleJournalSocket,
      SAAS_EPHEMERAL_HIGHWATER_PUBLIC_KEY_PATH:
        join(journalGenesis,'public.pem'),
    });
  other.add(oldWitness);
  const rolled=await exchange(join(work,'joint-rollback.sock'),{op:'head'});
  assert.deepEqual(rolled.head,head1);
  assert.notDeepEqual(rolled.head,head2);
  if(reviewStage) {
    const oldReceipt=await checkedJournal(head1,
      staleJournalSocket,journalGenesis);
    assert.equal(reviewInspect(rolled.envelope,oldReceipt,reviewPin2),
      'COORDINATED_LOCAL_ROLLBACK_SUSPECTED');
    // Simulate loss/rollback of the reviewer's OWN saved pin too.
    // This passes cryptographic self-consistency; the test explicitly
    // proves that SAME-runner pinning is NOT a durable remote root.
    assert.equal(reviewInspect(rolled.envelope,oldReceipt,reviewPin1),
      'PIN_MATCHED_FOR_MANUAL_INSPECTION');
    console.info('PASS 7s: retaining newer reviewer pin detects jointly rolled-back local histories; jointly rolled-back reviewer pin defeats same-runner observation (production blocker)');
  }
  if(extended) {
    // A valid historical journal signature is not evidence for the
    // newer pinned head. A coordinated rollback defeats a LOST pin,
    // but never the externally preserved newer head in this test.
    const staleChallenge=await challenge(freshId(),head1,
      join(work,'joint-rollback.sock'));
    const staleProof=source(staleChallenge);
    const staleHigh=await checkedJournal(head1,staleJournalSocket,journalGenesis);
    observation(staleChallenge,staleProof,rolled.envelope,null,staleHigh,
      head2,preparedFirst,{deny:true});
    console.info('PASS 7r: historical two-signer rollback with newer independently pinned head DENY (joint rollback with lost pin remains SPEC)');
  }
  await stop(oldWitness);other.delete(oldWitness);
  await stop(oldJournal);other.delete(oldJournal);
  console.info('PASS 7q: partial witness/journal rollback DENY; joint runner rollback remains open production blocker');

  // A crash AFTER witness local head fsync but BEFORE journal advance
  // leaves a valid-looking local checkpoint but journal head still old:
  // restart MUST fail, no automatic replay, no second UUID issuance.
  commit(ids[1]);
  const crashedWitnessState=join(work,'crashed-witness');
  const crashedSocket=join(work,'crashed-witness.sock');
  clone(state,crashedWitnessState);
  const crashed=await startWitness(crashedWitnessState,crashedSocket,{
    SAAS_WITNESS_TEST_KILL_BEFORE_HIGHWATER:'3'});
  other.add(crashed);
  const req3=freshId();
  const pg3=source(await challenge(req3,head2,crashedSocket));
  await lost(crashedSocket,proposal(req3,head2,pg3));
  await stop(crashed,true);other.delete(crashed);staleSocket(crashedSocket);
  assert.ok(existsSync(join(crashedWitnessState,'checkpoints','00000003.json')));
  if(extended) {
    const orphan=JSON.parse(readFileSync(join(crashedWitnessState,
      'checkpoints','00000003.json'),'utf8'));
    const supposed={sequence:3,digest:envelopeDigest(orphan.envelope)};
    const olderJournal=await checkedJournal(head2);
    if(reviewStage) {
      assert.equal(reviewInspect(orphan.envelope,olderJournal,reviewPin2),
        'SPLIT_SIGNED_LOCAL_HEADS_REVIEW_REQUIRED');
      console.info('PASS 7s: witness-fsynced / journal-not-advanced divergence produces manual dispute with no repair authorization');
    }
    observation({protocol:'saas-synthetic-pg-projection-challenge-v1',
      nonce:pg3.statement.challenge,expected:head2},pg3,orphan.envelope,
      recovered.envelope,olderJournal,supposed,candidate(ids[1],head2),
      {deny:true});
    console.info('PASS 7r: fsynced witness but lagging signed high-water cannot be treated as verified settlement');
  }
  await checkedJournal(head2);
  await failedStart(witnessFile,[crashedWitnessState,crashedSocket],fencedEnv());
  // An intact signer can still publish the same committed identity once.
  const live3=freshId(),src3=source(await challenge(live3,head2));
  const r3=await exchange(socket,proposal(live3,head2,src3));
  const head3=verifyWitness(r3,head2,recovered.envelope,live3);
  await checkedJournal(head3);
  if(reviewStage) {
    const signed3=await checkedJournal(head3);
    assert.equal(reviewInspect(r3.envelope,signed3,reviewPin2),
      'UNPINNED_LOCAL_ADVANCE_REVIEW_REQUIRED');
    reviewPin3=await raceReviewPin(r3.envelope,signed3,reviewPin2,
      join(reviewDir,'concurrent-pin-3.json'));
    assert.equal(reviewInspect(r3.envelope,signed3,reviewPin3),
      'PIN_MATCHED_FOR_MANUAL_INSPECTION');
    console.info('PASS 7s: two simultaneous reviewer signers cannot overwrite the same pinned successor; direct monotonic chain remains manual-only');
  }
  console.info('PASS 7q: witness-fsynced / journal-not-advanced SIGKILL creates DENY-only orphan, no silent repair');

  // Independent journal crashes after its checkpoint fsync but BEFORE
  // its own head publication. Neither process may claim settlement.
  commit(ids[2]);
  const brokenJournal=join(work,'broken-journal');
  const brokenJournalSocket=join(work,'broken-journal.sock');
  const brokenWitness=join(work,'broken-witness');
  const brokenWitnessSocket=join(work,'broken-witness.sock');
  clone(journalState,brokenJournal);
  clone(state,brokenWitness);
  const dyingJournal=await startJournal(brokenJournal,brokenJournalSocket,{
    SAAS_HIGHWATER_TEST_KILL_BEFORE_HEAD:'4'});
  other.add(dyingJournal);
  const dyingWitness=await startWitness(brokenWitness,brokenWitnessSocket,{
    SAAS_EPHEMERAL_HIGHWATER_SOCKET_PATH:brokenJournalSocket,
    SAAS_EPHEMERAL_HIGHWATER_PUBLIC_KEY_PATH:
      join(brokenJournal,'public.pem'),
  });
  other.add(dyingWitness);
  const req4=freshId(),proof4=source(await challenge(req4,head3,brokenWitnessSocket));
  await denied(brokenWitnessSocket,proposal(req4,head3,proof4));
  await stop(dyingJournal,true);other.delete(dyingJournal);
  staleSocket(brokenJournalSocket);
  assert.ok(existsSync(join(brokenJournal,'checkpoints','00000004.json')));
  if(extended) {
    const orphanJournal=JSON.parse(readFileSync(join(brokenJournal,
      'checkpoints','00000004.json'),'utf8'));
    const supposed={sequence:4,
      digest:envelopeDigest(orphanJournal.envelope)};
    if(reviewStage) {
      assert.equal(reviewInspect(r3.envelope,orphanJournal.receipt,reviewPin3),
        'SPLIT_SIGNED_LOCAL_HEADS_REVIEW_REQUIRED');
      console.info('PASS 7s: journal checkpoint signed but unpublished head is a split/manual incident, not a safe repaired high-water');
    }
    observation({protocol:'saas-synthetic-pg-projection-challenge-v1',
      nonce:proof4.statement.challenge,expected:head3},
      proof4,orphanJournal.envelope,r3.envelope,
      orphanJournal.receipt,supposed,candidate(ids[2],head3),
      {deny:true});
    console.info('PASS 7r: crash before journal head publication yields an orphan, not an independently current settlement certificate');
  }
  await failedStart(journalFile,['serve',brokenJournal,brokenJournalSocket,
    join(state,'public.pem')],journalEnv);
  await stop(dyingWitness);other.delete(dyingWitness);
  await failedStart(witnessFile,[brokenWitness,brokenWitnessSocket],fencedEnv());
  await checkedJournal(head3);
  const req4b=freshId(),safe4=source(await challenge(req4b,head3));
  const r4=await exchange(socket,proposal(req4b,head3,safe4));
  const head4=verifyWitness(r4,head3,r3.envelope,req4b);
  await checkedJournal(head4);
  if(reviewStage) {
    const signed4=await checkedJournal(head4);
    assert.equal(reviewInspect(r4.envelope,signed4,reviewPin3),
      'UNPINNED_LOCAL_ADVANCE_REVIEW_REQUIRED');
    createReviewPin(r4.envelope,signed4,reviewPin1,{deny:true});
    reviewPin4=createReviewPin(r4.envelope,signed4,reviewPin3);
    assert.equal(reviewInspect(r4.envelope,signed4,reviewPin4),
      'PIN_MATCHED_FOR_MANUAL_INSPECTION');
    // Reviewer's offline tool cannot be turned into a network/DB
    // producer, and even a MATCHED status is not an approval.
    reviewInspect(r4.envelope,signed4,reviewPin4,{
      deny:true,env:{...reviewEnv,PGUSER:'postgres'},
    });
    console.info('PASS 7s: historic reviewer pin fork/gap denied; latest signed root is still non-authorizing with zero PostgreSQL credentials');
  }
  if(extended) {
    // Two physically distinct COMMITs arriving since the same signed
    // witness head may never be downgraded to a single-operation
    // identity settlement in this bounded proof.
    commit(driftUuid[0]);commit(driftUuid[1]);
    const ch=await challenge(freshId(),head4);
    const snapshot=source(ch);
    observation(ch,snapshot,r4.envelope,r3.envelope,
      await checkedJournal(head4),head4,candidate(driftUuid[0],head4),
      {deny:true});
    console.info('PASS 7r: multiple newly COMMITTED UUIDs since pinned head are not mistaken for one recoverable operation');
  }
  console.info('PASS 7q: journal-fsynced / head-not-published crash DENY, original journal+witness can publish fresh direct successor');

  // A journal key replacement and retrospective journal downgrade are
  // not valid after the first protected signed checkpoint.
  const fake=join(work,'wrong-journal-public.pem');
  writeFileSync(fake,
    generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'pem'}),
    {flag:'wx',mode:0o600});
  await failedStart(witnessFile,[state,join(work,'wrong-journal.sock')],
    fencedEnv(journalSocket,fake));
  await failedStart(witnessFile,[state,join(work,'no-journal.sock')],ipcEnv);
  assert.equal(sql('SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox'),
    oldAudit,'High-water must not emit publication intent/ACK');
  assert.equal(sql("SELECT gc_permitted::text FROM "+
    "saas_rls_private.synthetic_operation_retention_health('demo-north')"),
    'false');
  const output=JSON.stringify(r4);
  assert.ok(!ids.some(uuid=>output.includes(uuid)));
  assert.ok(!output.includes('ci-7q-actor'));
  console.info('PASS 7q: signer pin substitution/downgrade DENY, no 009/013 effects, no raw UUID, GC always false');
  console.info('LIMITATION 7q: TWO signer processes on ONE runner do not give independent durable root or atomic PostgreSQL settlement');
  if(reviewStage)
    console.info('LIMITATION 7s: reviewer signer and saved pin share CI trust domain; preserved pin detects local rollback only while reviewer pin/root remain independently available; no production WORM, actor authorization or repair');
} finally {
  await stop(witness).catch(()=>{});
  await stop(journal).catch(()=>{});
  for(const child of other)await stop(child,true).catch(()=>{});
  if(hasRole) {
    try {
      sql("REVOKE ALL ON saas_rls_private.synthetic_operation_issues FROM "+ROLE+";"+
        "REVOKE ALL ON saas_rls_private.synthetic_producer_operations FROM "+ROLE+";"+
        "REVOKE ALL ON SCHEMA saas_rls_private FROM "+ROLE+";"+
        "REVOKE CONNECT ON DATABASE "+DB+" FROM "+ROLE+";"+
        "DROP ROLE "+ROLE+";");
    }catch(err){console.error('Ephemeral role cleanup failed: '+err.message);}
  }
  rmSync(work,{recursive:true,force:true});
}
