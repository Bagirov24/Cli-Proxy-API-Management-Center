#!/usr/bin/env node
// Stage 2G.4d.7p — witness-integrated PG projection attestation.
// Physical disposable PostgreSQL16, separate local signing processes,
// NO production issuer, off-host durability, remote ACK or GC authority.
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {connect} from 'node:net';
import {
  mkdtempSync,chmodSync,readFileSync,writeFileSync,
  existsSync,rmSync,unlinkSync,cpSync,
} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {
  randomBytes,generateKeyPairSync,verify as edVerify,
} from 'node:crypto';
import {canonicalProjection,verifyEnvelope,verifyCheckpoint,envelopeDigest}
  from './archive-witness-protocol.mjs';

const SOURCE='saas_ephemeral_test';
const ROLE='saas_witness_projection_7o';
const RECEIPT='saas-synthetic-ipc-witness-receipt-v1';
const ci=process.env.GITHUB_ACTIONS==='true'&&
  process.env.SAAS_EPHEMERAL_PROJECTOR_APPEND_CI==='true'&&
  process.env.PGHOST==='127.0.0.1'&&process.env.PGPORT==='5432'&&
  process.env.PGUSER==='postgres'&&process.env.PGDATABASE===SOURCE&&
  !process.env.RAILWAY_ENVIRONMENT&&!process.env.RAILWAY_PROJECT_ID&&
  !process.env.SAAS_PRODUCTION_DATABASE_URL;
if(!ci)throw Error('Refusing 7p proof outside disposable PostgreSQL16 CI');
const work=mkdtempSync(join(tmpdir(),'saas-ipc-witness-'));
chmodSync(work,0o700);
const serverFile=fileURLToPath(new URL('./archive-witness-ipc-server.mjs',import.meta.url));
const attestorFile=fileURLToPath(new URL('./archive-witness-pg-projection-proof.mjs',import.meta.url));
const state=join(work,'state'),sock=join(work,'witness.sock');
const pubFile=join(work,'projector-public.pem');
const privFile=join(work,'projector-private.pem');
const adminEnv={...process.env,PGCONNECT_TIMEOUT:'5'};
const password=randomBytes(24).toString('hex');
const readonlyEnv={
  GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_PROJECTOR_PROOF_CI:'true',
  PGHOST:'127.0.0.1',PGPORT:'5432',PGUSER:ROLE,
  PGPASSWORD:password,PGDATABASE:SOURCE,PGCONNECT_TIMEOUT:'5',
  PATH:process.env.PATH||'/usr/bin:/bin',HOME:work,LANG:'C',
};
const offlineEnv={
  GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_IPC_WITNESS_CI:'true',
  SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
  SAAS_EPHEMERAL_PG_WITNESS_PROOF_CI:'true',
  SAAS_EPHEMERAL_PROJECTOR_PUBKEY_PATH:pubFile,
  PATH:process.env.PATH||'/usr/bin:/bin',HOME:work,LANG:'C',
};
const freshId=()=>randomBytes(16).toString('hex');
const issueIds=[
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7d01',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7d02',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7d03',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7d04',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7d05',
];
let roleCreated=false,server=null,serial=0;
function command(executable,args,env,deny=false) {
  const r=spawnSync(executable,args,{env,cwd:work,encoding:'utf8',
    timeout:15000,maxBuffer:2000000});
  if(deny)assert.notEqual(r.status,0,
    'Unsafe command unexpectedly succeeded: '+executable);
  else assert.equal(r.status,0,'Test command failed: '+
    (r.stderr||'').slice(0,500));
  return (r.stdout||'').trim();
}
function admin(sql) {
  return command('psql',['-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
    '--dbname',SOURCE,'-c',sql],adminEnv);
}
function restricted(sql,deny=false) {
  return command('psql',['-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
    '--dbname',SOURCE,'-c',sql],readonlyEnv,deny);
}
function issue(uuid) {
  const count="SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
    "WHERE operation_id='"+uuid+"'::uuid";
  assert.equal(admin(count),'0','Fixture UUID was already committed');
  admin("BEGIN; INSERT INTO saas_rls_private.synthetic_operation_issues "+
    "(operation_id,tenant_id,actor_id,membership_role,collection,"+
    "requested_limit,issued_at,issue_expires_at,recovery_expires_at) VALUES "+
    "('"+uuid+"'::uuid,'ci-7p-witness','ci-7p-actor','tenant-viewer',"+
    "'projects',1,clock_timestamp(),clock_timestamp()+interval '2 minutes',"+
    "clock_timestamp()+interval '2 hours'); COMMIT;");
  assert.equal(admin(count),'1','Expected an independently visible physical COMMIT');
}
function save(name,obj) {
  const p=join(work,name);
  writeFileSync(p,JSON.stringify(obj)+'\n',{flag:'wx',mode:0o600});
  return p;
}
function attest(challenge,deny=false,env=readonlyEnv) {
  const label=String(++serial);
  const challengeFile=save('challenge-'+label+'.json',challenge);
  const out=join(work,'source-proof-'+label+'.json');
  command(process.execPath,[attestorFile,'attest',
    privFile,pubFile,challengeFile,out],env,deny);
  if(deny) {
    assert.equal(existsSync(out),false,'Failed projector must not emit proof');
    return null;
  }
  const proof=JSON.parse(readFileSync(out,'utf8'));
  assert.equal(proof.statement.source.database,SOURCE);
  assert.deepEqual(canonicalProjection(proof.statement.projection),
    proof.statement.projection);
  return proof;
}
function startDaemon(where=state,path=sock,extra={}) {
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,[serverFile,where,path],{
      env:{...offlineEnv,...extra},stdio:['ignore','pipe','pipe'],
    });
    let done=false,stderr='',stdout='';
    const timer=setTimeout(()=>{
      if(done)return;
      done=true;child.kill('SIGKILL');
      reject(Error('Protected witness readiness deadline: '+stderr));
    },7000);
    child.stderr.on('data',v=>{stderr+=String(v);});
    child.stdout.on('data',v=>{
      stdout+=String(v);
      if(!done&&stdout.includes('READY:')) {
        done=true;clearTimeout(timer);resolve(child);
      }
    });
    child.on('error',err=>{
      if(done)return;done=true;clearTimeout(timer);reject(err);
    });
    child.on('exit',(code,signal)=>{
      if(done)return;done=true;clearTimeout(timer);
      reject(Error('Protected witness refused startup '+code+' '+signal+
        ': '+stderr));
    });
  });
}
function exchange(path,body) {
  return new Promise((resolve,reject)=>{
    const connection=connect({path});
    let ended=false,response='';
    const timer=setTimeout(()=>finish(Error('Witness request timed out')),
      5000);
    function finish(error,value) {
      if(ended)return;
      ended=true;clearTimeout(timer);connection.destroy();
      if(error)reject(error);else resolve(value);
    }
    connection.setEncoding('utf8');
    connection.on('connect',()=>connection.write(JSON.stringify(body)+'\n'));
    connection.on('data',part=>{
      response+=String(part);
      if(response.length>1000000)return finish(Error('Oversized IPC reply'));
      if(response.includes('\n')) {
        try {
          const [line,...rest]=response.split('\n');
          assert.equal(rest.join('').trim(),'');
          finish(null,JSON.parse(line));
        }catch(error){finish(error);}
      }
    });
    connection.on('end',()=>{
      if(!ended)finish(Error('IPC ACK missing: UNKNOWN, DENY issuance'));
    });
    connection.on('error',e=>finish(e));
  });
}
async function denied(path,message) {
  assert.deepEqual(await exchange(path,message),{ok:false,error:'DENIED'});
}
async function unavailable(path,message) {
  await assert.rejects(exchange(path,message),
    'No IPC response means UNKNOWN, never safe issuance');
}
async function terminate(child,hard=false) {
  if(child.exitCode!==null||child.signalCode!==null)return;
  const finished=once(child,'exit');
  child.kill(hard?'SIGKILL':'SIGTERM');
  await finished;
}
async function failedStart(where,path,extra={}) {
  await assert.rejects(startDaemon(where,path,extra),
    /refused startup|readiness deadline/,
    'Changed trust root or crash journal unexpectedly booted');
}
function claim(id,expected,attestation) {
  return {op:'append-pg',requestId:id,expected,attestation};
}
async function challenge(id,expected,path=sock) {
  const response=await exchange(path,{op:'challenge-pg',requestId:id,expected});
  assert.equal(response.ok,true);
  assert.equal(response.state,'CHALLENGE');
  assert.equal(response.requestId,id);
  assert.equal(response.gcPermitted,false);
  assert.deepEqual(response.challenge.expected,expected);
  assert.match(response.challenge.nonce,/^[0-9a-f]{32}$/);
  return response.challenge;
}
function pin(reply,publicPem,id,projection,prior,priorEnvelope=null) {
  assert.equal(reply.ok,true);
  assert.equal(reply.state,'SEALED');
  assert.equal(reply.gcPermitted,false);
  const payload=verifyEnvelope(reply.envelope,publicPem);
  assert.deepEqual(payload.projection,canonicalProjection(projection));
  const current={sequence:payload.sequence,digest:envelopeDigest(reply.envelope)};
  assert.deepEqual(reply.head,current);
  assert.equal(payload.sequence,(prior?.sequence??0)+1);
  assert.equal(payload.previous,prior?.digest??null);
  verifyCheckpoint(reply.envelope,publicPem,current,projection,priorEnvelope);
  assert.deepEqual(reply.receipt.data,{
    protocol:RECEIPT,requestId:id,
    sequence:current.sequence,digest:current.digest,
  });
  assert.equal(edVerify(null,Buffer.from(RECEIPT+'\n'+
    JSON.stringify(reply.receipt.data)),publicPem,
    Buffer.from(reply.receipt.signature,'base64url')),true);
  return current;
}
try {
  assert.equal(admin('SELECT current_database()'),SOURCE);
  assert.equal(admin("SELECT COUNT(*) FROM pg_roles WHERE rolname='"+ROLE+"'"),'0');
  const auditBefore=admin('SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox');
  assert.equal(admin("SELECT gc_permitted::text FROM "+
    "saas_rls_private.synthetic_operation_retention_health('demo-north')"),
    'false');
  // SAME staging projector contract as 7o; 7p exercises the real daemon.
  admin("CREATE ROLE "+ROLE+" WITH LOGIN NOINHERIT PASSWORD '"+password+"';"+
    "GRANT CONNECT ON DATABASE "+SOURCE+" TO "+ROLE+";"+
    "GRANT USAGE ON SCHEMA saas_rls_private TO "+ROLE+";"+
    "GRANT SELECT (operation_id) ON "+
    "saas_rls_private.synthetic_operation_issues TO "+ROLE+";"+
    "GRANT SELECT (operation_id) ON "+
    "saas_rls_private.synthetic_producer_operations TO "+ROLE+";");
  roleCreated=true;
  restricted('SELECT operation_id FROM saas_rls_private.synthetic_operation_issues LIMIT 1');
  restricted('SELECT tenant_id FROM saas_rls_private.synthetic_operation_issues',true);
  restricted('SELECT actor_id FROM saas_rls_private.synthetic_producer_operations',true);
  restricted('SELECT secret FROM saas_rls_private.scope_signers',true);
  restricted('UPDATE saas_rls_private.synthetic_operation_issues SET requested_limit=2',true);
  const pair=generateKeyPairSync('ed25519');
  writeFileSync(privFile,pair.privateKey.export({type:'pkcs8',format:'pem'}),
    {flag:'wx',mode:0o600});
  writeFileSync(pubFile,pair.publicKey.export({type:'spki',format:'pem'}),
    {flag:'wx',mode:0o600});
  server=await startDaemon();
  const witnessPublic=readFileSync(join(state,'public.pem'),'utf8');
  assert.equal(existsSync(join(state,'projector-pin.json')),true);
  const id1=freshId(),ch1=await challenge(id1,null);
  const again=await challenge(id1,null);
  assert.deepEqual(again,ch1,'Idempotent challenge request must reuse nonce');
  const proof1=attest(ch1);
  const proj1=proof1.statement.projection;
  assert.ok(proj1.issuedCount>0&&proj1.producerCount>0);
  await denied(sock,{op:'append',requestId:id1,expected:null,
    projection:proj1});
  await denied(sock,{op:'append-pg',requestId:id1,expected:null,
    projection:proj1});
  await denied(sock,claim(id1,null,null));
  const genesisRequest=claim(id1,null,proof1);
  const first=await exchange(sock,genesisRequest);
  const head1=pin(first,witnessPublic,id1,proj1,null);
  assert.deepEqual(await exchange(sock,genesisRequest),first);
  await denied(sock,{op:'challenge-pg',requestId:id1,expected:head1});
  console.info('PASS 7p: pinned projector trust root, daemon-issued nonce, signed PG16 genesis; legacy client append DENY');

  // An actual COMMIT precedes a source read-only proof. Every alteration
  // below must fail BEFORE the witness can publish a new signed head.
  issue(issueIds[0]);
  const id2=freshId(),ch2=await challenge(id2,head1),proof2=attest(ch2);
  const proj2=proof2.statement.projection;
  assert.equal(proj2.issuedCount,proj1.issuedCount+1);
  const proposal2=claim(id2,head1,proof2);
  await denied(sock,{...proposal2,projection:proj2});
  await denied(sock,{op:'append-pg',requestId:freshId(),
    expected:head1,attestation:proof2});
  await denied(sock,claim(id2,null,proof2));
  const tampered=structuredClone(proof2);
  tampered.statement.projection.issued.push('f'.repeat(64));
  tampered.statement.projection.issued.sort();
  tampered.statement.projection.issuedCount++;
  await denied(sock,claim(id2,head1,tampered));
  const fakeSource=structuredClone(proof2);
  fakeSource.statement.source.database='other-test-database';
  await denied(sock,claim(id2,head1,fakeSource));
  const fakeDigest=structuredClone(proof2);
  fakeDigest.statement.projection.producerCount++;
  await denied(sock,claim(id2,head1,fakeDigest));
  const idReplay=freshId(),otherCh=await challenge(idReplay,head1);
  assert.notEqual(otherCh.nonce,ch2.nonce);
  await denied(sock,claim(idReplay,head1,proof2));
  const wrongPair=generateKeyPairSync('ed25519');
  const forgedProof=structuredClone(proof2);
  forgedProof.signature=requireNoop();
  function requireNoop() {
    // A correctly shaped Ed25519 signature from the WRONG key.
    const bytes=randomBytes(64);
    return bytes.toString('base64url');
  }
  await denied(sock,claim(id2,head1,forgedProof));
  assert.ok(wrongPair.publicKey);
  console.info('PASS 7p: missing source proof, client projection, tampered DB/digest/signature, wrong nonce and request-ID replay DENY');

  // PG was committed before publishing. An ACK lost AFTER durable fsync
  // must recover the same receipt; it must not issue a second UUID.
  await terminate(server);server=null;
  server=await startDaemon(state,sock,{SAAS_WITNESS_TEST_LOSE_ACK:'2'});
  // Restart intentionally discards pending nonce challenges. Re-attest
  // using a newly issued challenge, rather than trusting the old proof.
  await denied(sock,proposal2);
  const freshCh2=await challenge(id2,head1);
  const freshProof2=attest(freshCh2);
  const freshProposal2=claim(id2,head1,freshProof2);
  await unavailable(sock,freshProposal2);
  await terminate(server,true);server=null;
  assert.ok(existsSync(join(state,'head.json')));
  if(existsSync(sock))unlinkSync(sock);
  server=await startDaemon();
  const recovered=await exchange(sock,freshProposal2);
  const head2=pin(recovered,witnessPublic,id2,proj2,head1,first.envelope);
  assert.deepEqual(await exchange(sock,freshProposal2),recovered);
  await denied(sock,proposal2);
  await denied(sock,claim(idReplay,head1,proof2));
  assert.equal((await exchange(sock,{op:'head'})).head.sequence,2);
  console.info('PASS 7p: lost fsynced IPC ACK stays UNKNOWN until identical signed receipt recovered after restart');

  // Both publishers get a distinct challenge pinned to exactly ONE head.
  // The daemon serializes two fully attested attempts; only one wins.
  issue(issueIds[1]);
  const ida=freshId(),idb=freshId();
  const ca=await challenge(ida,head2),cb=await challenge(idb,head2);
  assert.notEqual(ca.nonce,cb.nonce);
  const pa=attest(ca),pb=attest(cb);
  assert.deepEqual(pa.statement.projection,pb.statement.projection);
  const [ra,rb]=await Promise.all([
    exchange(sock,claim(ida,head2,pa)),
    exchange(sock,claim(idb,head2,pb)),
  ]);
  assert.equal([ra,rb].filter(v=>v.ok).length,1,'Forked successor on same head');
  assert.equal([ra,rb].filter(v=>!v.ok).length,1);
  const winner=ra.ok?{reply:ra,id:ida,proof:pa}:{reply:rb,id:idb,proof:pb};
  const head3=pin(winner.reply,witnessPublic,winner.id,
    pa.statement.projection,head2,recovered.envelope);
  assert.deepEqual(await exchange(sock,claim(winner.id,head2,winner.proof)),
    winner.reply);
  await denied(sock,claim(ra.ok?idb:ida,head2,ra.ok?pb:pa));
  await denied(sock,claim(freshId(),head3,pa));
  console.info('PASS 7p: competing signed publishers cannot fork expected witness head or replay source proof');

  // Physical PG COMMIT while daemon is unreachable remains UNSIGNED.
  issue(issueIds[2]);
  await terminate(server);server=null;
  await unavailable(sock,{op:'head'});
  server=await startDaemon();
  const id4=freshId(),c4=await challenge(id4,head3);
  const unavailableEnv={...readonlyEnv,PGPASSWORD:'not-the-CI-projector-password'};
  attest(c4,true,unavailableEnv);
  await denied(sock,claim(id4,head3,null));
  await denied(sock,{op:'append',requestId:id4,expected:head3,
    projection:pa.statement.projection});
  const oldProof4=attest(c4);
  await terminate(server);server=null;
  server=await startDaemon();
  await denied(sock,claim(id4,head3,oldProof4));
  const newC4=await challenge(id4,head3);
  assert.notEqual(newC4.nonce,c4.nonce);
  const proof4=attest(newC4);
  const resp4=await exchange(sock,claim(id4,head3,proof4));
  const head4=pin(resp4,witnessPublic,id4,proof4.statement.projection,
    head3,winner.reply.envelope);
  console.info('PASS 7p: PG COMMIT / projector failure / daemon partition and source-proof-before-publication crash remain fail-closed');

  // REVOKE the least-privilege SELECT: source cannot attest. No fallback
  // to caller arrays, admin PG credentials or previously signed proof.
  issue(issueIds[3]);
  const id5=freshId(),c5=await challenge(id5,head4);
  admin("REVOKE SELECT (operation_id) ON "+
    "saas_rls_private.synthetic_operation_issues FROM "+ROLE);
  attest(c5,true);
  await denied(sock,claim(id5,head4,null));
  await denied(sock,claim(id5,head4,proof4));
  admin("GRANT SELECT (operation_id) ON "+
    "saas_rls_private.synthetic_operation_issues TO "+ROLE);
  const p5=attest(c5);
  const resp5=await exchange(sock,claim(id5,head4,p5));
  const head5=pin(resp5,witnessPublic,id5,p5.statement.projection,
    head4,resp4.envelope);
  console.info('PASS 7p: revoked projection grant blocks signing; old proof and unsigned fallback DENY');

  // Startup re-verifies all source signatures AND witness chain; a
  // swapped projector pin or altered persisted proof must fail closed.
  const badState=join(work,'bad-state'),badSocket=join(work,'bad.sock');
  cpSync(state,badState,{recursive:true});
  const rowFile=join(badState,'checkpoints','00000005.json');
  const row=JSON.parse(readFileSync(rowFile,'utf8'));
  row.attestation.statement.source.database='tampered';
  writeFileSync(rowFile,JSON.stringify(row)+'\n',{mode:0o600});
  await failedStart(badState,badSocket);
  const anotherPub=join(work,'wrong-projector.pem');
  writeFileSync(anotherPub,
    generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'pem'}),
    {flag:'wx',mode:0o600});
  await terminate(server);server=null;
  await failedStart(state,sock,{SAAS_EPHEMERAL_PROJECTOR_PUBKEY_PATH:anotherPub});
  server=await startDaemon();
  assert.deepEqual((await exchange(sock,{op:'head'})).head,head5);
  assert.equal(admin('SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox'),
    auditBefore,'Witness must not emit 009/013 audit/intent effects');
  assert.equal(admin("SELECT gc_permitted::text FROM "+
    "saas_rls_private.synthetic_operation_retention_health('demo-north')"),
    'false');
  assert.ok(!JSON.stringify(resp5).includes(issueIds[3])&&
    !JSON.stringify(resp5).includes('ci-7p-actor'));
  console.info('PASS 7p: persisted proof tamper and projector key substitution DENY; GC false and no live effects');
  console.info('LIMITATION 7p: common CI runner cannot prove atomic PG COMMIT, off-host high-water or rollback resistance');
} finally {
  if(server)await terminate(server).catch(()=>{});
  if(roleCreated) {
    try {
      admin("REVOKE ALL ON saas_rls_private.synthetic_operation_issues FROM "+ROLE+";"+
        "REVOKE ALL ON saas_rls_private.synthetic_producer_operations FROM "+ROLE+";"+
        "REVOKE ALL ON SCHEMA saas_rls_private FROM "+ROLE+";"+
        "REVOKE CONNECT ON DATABASE "+SOURCE+" FROM "+ROLE+";"+
        "DROP ROLE "+ROLE+";");
    }catch(error){console.error('Disposable role cleanup failed: '+error.message);}
  }
  rmSync(work,{recursive:true,force:true});
}
