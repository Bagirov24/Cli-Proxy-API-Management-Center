#!/usr/bin/env node
// 2G.4d.7q: physical disposable PG16 -> attested IPC witness ->
// separate signed local high-water process. ONE CI RUNNER, NOT WORM.
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {connect} from 'node:net';
import {
  mkdtempSync,chmodSync,readFileSync,writeFileSync,cpSync,rmSync,
  existsSync,unlinkSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  generateKeyPairSync,randomBytes,createHash,createPublicKey,
  verify as edVerify,
} from 'node:crypto';
import {envelopeDigest,verifyEnvelope,verifyCheckpoint}
  from './archive-witness-protocol.mjs';

const ROLE='saas_witness_projection_7o',DB='saas_ephemeral_test';
const JPROTOCOL='saas-synthetic-ipc-highwater-receipt-v1';
const RPROTOCOL='saas-synthetic-ipc-witness-receipt-v1';
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
const state=join(work,'witness-state'),socket=join(work,'witness.sock');
const journalState=join(work,'highwater-state'),journalSocket=join(work,'highwater.sock');
const attPriv=join(work,'projector-private.pem'),attPub=join(work,'projector-public.pem');
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
const ids=[
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7e01',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7e02',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7e03',
];
const freshId=()=>randomBytes(16).toString('hex');
const hash=v=>createHash('sha256').update(v).digest('hex');
const fingerprint=pem=>hash(createPublicKey(pem)
  .export({type:'spki',format:'der'}));
let hasRole=false,witness=null,journal=null,serial=0;
const other=new Set();
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
  const journalGenesis=join(work,'saved-journal-genesis');
  const witnessGenesis=join(work,'saved-witness-genesis');
  clone(journalState,journalGenesis);clone(state,witnessGenesis);
  console.info('PASS 7q: independently signed local high-water genesis before witness ACK, no raw UUID/DB credentials in either signer');

  // A committed UUID is NOT sufficient while separate journal is down.
  commit(ids[0]);
  const req2=freshId(),proof2=source(await challenge(req2,head1));
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
  await checkedJournal(head2);
  await failedStart(witnessFile,[crashedWitnessState,crashedSocket],fencedEnv());
  // An intact signer can still publish the same committed identity once.
  const live3=freshId(),src3=source(await challenge(live3,head2));
  const r3=await exchange(socket,proposal(live3,head2,src3));
  const head3=verifyWitness(r3,head2,recovered.envelope,live3);
  await checkedJournal(head3);
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
  await failedStart(journalFile,['serve',brokenJournal,brokenJournalSocket,
    join(state,'public.pem')],journalEnv);
  await stop(dyingWitness);other.delete(dyingWitness);
  await failedStart(witnessFile,[brokenWitness,brokenWitnessSocket],fencedEnv());
  await checkedJournal(head3);
  const req4b=freshId(),safe4=source(await challenge(req4b,head3));
  const r4=await exchange(socket,proposal(req4b,head3,safe4));
  const head4=verifyWitness(r4,head3,r3.envelope,req4b);
  await checkedJournal(head4);
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
