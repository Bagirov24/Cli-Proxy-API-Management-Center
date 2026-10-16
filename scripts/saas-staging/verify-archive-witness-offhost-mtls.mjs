#!/usr/bin/env node
// Stage 7v acceptance: real mTLS HTTPS/loopback and fsynced append,
// not real independent off-host operator, HSM, WORM or PostgreSQL settlement.
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {request as tlsRequest} from 'node:https';
import {checkServerIdentity} from 'node:tls';
import {X509Certificate,generateKeyPairSync,createHash,createPublicKey,
  sign as edSign,verify as edVerify,randomBytes} from 'node:crypto';
import {
  mkdtempSync,writeFileSync,readFileSync,copyFileSync,mkdirSync,
  chmodSync,rmSync,existsSync,
} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {projectionFromSql,envelopeDigest,verifyEnvelope}
  from './archive-witness-protocol.mjs';

const ci=process.env.GITHUB_ACTIONS==='true'&&
  process.env.SAAS_EPHEMERAL_EXTERNAL_TRANSPORT_TEST_CI==='true'&&
  process.env.PGHOST==='127.0.0.1'&&
  process.env.PGPORT==='5432'&&
  process.env.PGUSER==='postgres'&&
  process.env.PGDATABASE==='saas_ephemeral_test'&&
  !process.env.RAILWAY_ENVIRONMENT&&!process.env.RAILWAY_PROJECT_ID&&
  !process.env.SAAS_PRODUCTION_DATABASE_URL;
if(!ci)throw Error('7v transport acceptance requires ephemeral PG16 GitHub CI');
const area=mkdtempSync(join(tmpdir(),'saas-ipc-witness-7v-'));
chmodSync(area,0o700);
const serverPath=fileURLToPath(new URL('./archive-witness-offhost-mtls-server.mjs',import.meta.url));
const RECORD='saas-synthetic-offhost-highwater-receipt-v1';
const TRANSPORT='saas-synthetic-offhost-mtls-append-v1';
const JOURNAL='saas-synthetic-ipc-highwater-receipt-v1';
const WIT='saas-synthetic-uuid-witness-v1';
const sha=x=>createHash('sha256').update(x).digest('hex');
const fp=x=>sha((x?.type==='public'?x:createPublicKey(x))
  .export({type:'spki',format:'der'}));
const nonce=()=>randomBytes(16).toString('hex');
const env={
  GITHUB_ACTIONS:'true',
  SAAS_EPHEMERAL_EXTERNAL_TRANSPORT_CI:'true',
  SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
  HOME:area,PATH:process.env.PATH||'/usr/bin:/bin',LANG:'C',
};
const file=name=>join(area,name);
function write(name,value) {
  const target=file(name);
  writeFileSync(target,value,{flag:'wx',mode:0o600});
  return target;
}
function exec(program,args) {
  const result=spawnSync(program,args,{
    env:{PATH:process.env.PATH||'/usr/bin:/bin',HOME:area,LANG:'C'},
    cwd:area,encoding:'utf8',timeout:10000,maxBuffer:100000,
  });
  assert.equal(result.status,0,
    program+' certificate setup: '+(result.stderr||'').slice(-900));
}
function certs() {
  exec('openssl',['req','-new','-x509','-newkey','rsa:2048',
    '-nodes','-days','1','-keyout',file('ca.key'),
    '-out',file('ca.crt'),'-subj','/CN=synthetic-ci-ca']);
  const identities=[
    ['server','/CN=localhost',
      'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n'],
    ['client','/CN=synthetic-ci-client','extendedKeyUsage=clientAuth\n'],
    ['other-client','/CN=synthetic-ci-nonpinned','extendedKeyUsage=clientAuth\n'],
    ['other-server','/CN=synthetic-ci-replaced-server',
      'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n'],
  ];
  for(const [name,subject,extensions] of identities){
    write(name+'.ext',extensions);
    exec('openssl',['req','-new','-newkey','rsa:2048','-nodes',
      '-keyout',file(name+'.key'),'-out',file(name+'.csr'),
      '-subj',subject]);
    exec('openssl',['x509','-req','-in',file(name+'.csr'),
      '-CA',file('ca.crt'),'-CAkey',file('ca.key'),
      '-CAcreateserial','-days','1','-out',file(name+'.crt'),
      '-extfile',file(name+'.ext')]);
  }
}
const keys={};
for(const role of ['authority','witness','journal']) {
  keys[role]=generateKeyPairSync('ed25519');
  write(role+'.pub',keys[role].publicKey.export({type:'spki',format:'pem'}));
  write(role+'.priv',keys[role].privateKey.export({type:'pkcs8',format:'pem'}));
}
const publicPem=role=>readFileSync(file(role+'.pub'),'utf8');
const signature=(data,domain,role)=>({
  data,signature:edSign(null,Buffer.from(domain+'\n'+JSON.stringify(data)),
    keys[role].privateKey).toString('base64url'),
});
function sourceEnvelope(uuids,prior=null) {
  const proj=projectionFromSql(uuids.map(x=>'issued|'+x).join('\n'));
  const payload={
    protocol:WIT,audience:'ephemeral-pg16-proof-only',
    sequence:(prior?.payload.sequence??0)+1,
    previous:prior?envelopeDigest(prior):null,
    projectionRoot:sha(JSON.stringify(proj)),projection:proj,
  };
  const envelope={
    payload,algorithm:'Ed25519',keyFingerprint:fp(publicPem('witness')),
    signature:edSign(null,Buffer.from(WIT+'\n'+JSON.stringify(payload)),
      keys.witness.privateKey).toString('base64url'),
  };
  assert.deepEqual(verifyEnvelope(envelope,publicPem('witness')),payload);
  return envelope;
}
function append(envelope,expected=null,requestNonce=nonce()) {
  const head={sequence:envelope.payload.sequence,digest:envelopeDigest(envelope)};
  return {
    protocol:TRANSPORT,nonce:requestNonce,expected,envelope,
    journalReceipt:signature({
      protocol:JOURNAL,
      witnessFingerprint:fp(publicPem('witness')),head,
    },JOURNAL,'journal'),
  };
}
let policy;
let child;
function launch(state,extra={}){
  return new Promise((resolve,reject)=>{
    const args=[
      'serve',state,file('server.key'),file('server.crt'),file('ca.crt'),
      file('authority.priv'),file('authority.pub'),
      file('witness.pub'),file('journal.pub'),file('client.crt'),
      file('policy.json'),'0',
    ];
    const processChild=spawn(process.execPath,[serverPath,...args],{
      cwd:area,env:{...env,...extra},stdio:['ignore','pipe','pipe'],
    });
    let output='',errors='',done=false;
    const timer=setTimeout(()=>{
      if(done)return;done=true;processChild.kill('SIGKILL');
      reject(Error('Remote prototype listener not ready: '+errors));
    },8500);
    processChild.stdout.on('data',part=>{
      output+=String(part);
      const ready=/READY: synthetic mutual TLS loopback port (\d+)/.exec(output);
      if(!done&&ready){
        done=true;clearTimeout(timer);
        resolve({child:processChild,port:Number(ready[1])});
      }
    });
    processChild.stderr.on('data',part=>{errors+=String(part);});
    processChild.on('error',error=>{
      if(!done){done=true;clearTimeout(timer);reject(error);}
    });
    processChild.on('exit',(code,signal)=>{
      if(!done){
        done=true;clearTimeout(timer);
        reject(Error('Remote service startup DENIED '+code+'/'+signal+
          ': '+errors.slice(-1200)));
      }
    });
  });
}
function https(port,method,path,payload=null,options={}) {
  return new Promise((resolve,reject)=>{
    const key=Object.hasOwn(options,'key')?options.key:file('client.key');
    const cert=Object.hasOwn(options,'cert')?options.cert:file('client.crt');
    let tlsOptions={host:'127.0.0.1',port,method,path,
      ca:readFileSync(file('ca.crt')),rejectUnauthorized:true,
      minVersion:'TLSv1.3',timeout:6500,
      headers:payload===null?{}:{'content-type':'application/json'},
      checkServerIdentity:(host,peer)=>{
        const result=checkServerIdentity(host,peer);
        if(result)return result;
        const observed=fp(new X509Certificate(peer.raw).publicKey);
        const expected=options.serverPin??policy.serverFingerprint;
        if(observed!==expected)
          return Error('Synthetic TLS server pinned public key mismatch');
        return undefined;
      },
    };
    if(key!==null)tlsOptions.key=readFileSync(key);
    if(cert!==null)tlsOptions.cert=readFileSync(cert);
    const req=tlsRequest(tlsOptions,response=>{
      let buf='';
      response.setEncoding('utf8');
      response.on('data',part=>{
        buf+=String(part);
        if(buf.length>1000000)req.destroy(Error('Oversize response'));
      });
      response.on('end',()=>{
        try{resolve({status:response.statusCode,data:JSON.parse(buf)});}
        catch(error){reject(error);}
      });
    });
    req.on('timeout',()=>req.destroy(Error('mTLS transport timeout UNKNOWN')));
    req.on('error',reject);
    req.end(payload===null?undefined:JSON.stringify(payload));
  });
}
function verifyAck(response,request,prior=null){
  assert.equal(response.status,200);
  const ack=response.data;
  assert.equal(ack.ok,true);assert.equal(ack.gcPermitted,false);
  for(const flag of ['authorizationGranted','retryPermitted',
    'reissuePermitted','deliveryPermitted','repairPermitted'])
    assert.equal(ack[flag],false);
  assert.equal(ack.manualReviewRequired,true);
  const signed=ack.receipt;
  const publicKey=publicPem('authority');
  assert.equal(edVerify(null,Buffer.from(RECORD+'\n'+
    JSON.stringify(signed.data)),publicKey,
    Buffer.from(signed.signature,'base64url')),true,
    'External transport receipt not signed by pinned authority');
  assert.equal(signed.data.challengeNonce,request.nonce);
  assert.equal(signed.data.revision,request.envelope.payload.sequence);
  assert.equal(signed.data.previousReceiptDigest,
    prior?sha(JSON.stringify(prior)):null);
  assert.equal(signed.data.journalReceiptDigest,
    sha(JSON.stringify(request.journalReceipt)));
  return signed;
}
async function stop(running,hard=false){
  if(!running||running.child.exitCode!==null||
    running.child.signalCode!==null)return;
  const ready=once(running.child,'exit');
  running.child.kill(hard?'SIGKILL':'SIGTERM');
  await ready;
}
async function denied(port,body,options={}) {
  const res=await https(port,'POST','/v1/append',body,options);
  assert.notEqual(res.status,200,
    'Invalid identity/replay/fork erroneously received signed success');
  assert.equal(res.data.ok,false);
}
async function startupDeny(state,extra={}) {
  await assert.rejects(launch(state,extra),
    /startup DENIED|not ready/);
}
try {
  certs();
  const certPem=readFileSync(file('client.crt'));
  const serverPem=readFileSync(file('server.crt'));
  const certFp=cert=>fp(new X509Certificate(cert).publicKey);
  policy={
    protocol:'saas-synthetic-offhost-mtls-policy-v1',
    audience:'disposable-ci-network-loopback-only',
    logId:nonce(),epoch:1,
    authorityFingerprint:fp(publicPem('authority')),
    witnessFingerprint:fp(publicPem('witness')),
    journalFingerprint:fp(publicPem('journal')),
    clientFingerprint:certFp(certPem),
    serverFingerprint:certFp(serverPem),
  };
  write('policy.json',JSON.stringify(policy)+'\n');
  const state=file('durable-remote-prototype');
  let running=await launch(state);
  const uuid1='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa9001';
  const uuid2='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa9002';
  const uuid3='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa9003';
  const uuid4='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa9004';
  const uuid5='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa9005';
  const e1=sourceEnvelope([uuid1]),p1=append(e1);
  const ack1=verifyAck(await https(running.port,'POST','/v1/append',p1),p1);
  const head=await https(running.port,'GET','/v1/head');
  assert.equal(head.status,200);
  assert.deepEqual(head.data.receipt,ack1);
  assert.equal(head.data.gcPermitted,false);
  await denied(running.port,{...p1,nonce:nonce(),expected:null});
  await denied(running.port,{...p1,nonce:p1.nonce,extra:'smuggled'});
  const changed=structuredClone(p1);
  changed.envelope.payload.sequence=99;
  await denied(running.port,changed);
  const bogus=structuredClone(p1);
  bogus.journalReceipt.data.head.digest='f'.repeat(64);
  await denied(running.port,bogus);
  const otherClient=await https(running.port,'GET','/v1/head',null,{
    key:file('other-client.key'),cert:file('other-client.crt'),
  });
  assert.equal(otherClient.status,403);
  await assert.rejects(https(running.port,'GET','/v1/head',null,{
    key:null,cert:null,
  }));
  await assert.rejects(https(running.port,'GET','/v1/head',null,{
    serverPin:'f'.repeat(64),
  }),/pinned public key/);
  console.info('PASS 7v: actual loopback TLS1.3 mutual-cert authentication with pinned client/server identities and source-signed witness/journal verification; no issuer/GC');
  await stop(running);
  running=await launch(state,{SAAS_TRANSPORT_TEST_LOSE_ACK_SEQ:'2'});
  const e2=sourceEnvelope([uuid1,uuid2],e1),p2=append(e2,ack1);
  await assert.rejects(https(running.port,'POST','/v1/append',p2));
  await stop(running,true);
  running=await launch(state);
  const ack2=verifyAck(await https(running.port,'POST','/v1/append',p2),p2,ack1);
  const repeated=await https(running.port,'POST','/v1/append',p2);
  assert.deepEqual(repeated.data.receipt,ack2);
  await denied(running.port,{...p2,nonce:nonce()});
  const rebound=structuredClone(p2);rebound.expected=null;
  await denied(running.port,rebound);
  assert.equal(readFileSync(join(state,'signed-append.jsonl'),'utf8')
    .trim().split('\n').length,2);
  console.info('PASS 7v: fsync before ACK, simulated SIGKILL, restart and exact idempotent signed receipt after UNKNOWN; nonce rebind/stale expected denied');
  const e3a=sourceEnvelope([uuid1,uuid2,uuid3],e2);
  const e3b=sourceEnvelope([uuid1,uuid2,uuid4],e2);
  const p3a=append(e3a,ack2),p3b=append(e3b,ack2);
  const concurrent=await Promise.all([
    https(running.port,'POST','/v1/append',p3a),
    https(running.port,'POST','/v1/append',p3b),
  ]);
  const winners=concurrent.map((res,i)=>({res,req:i?p3b:p3a,
    envelope:i?e3b:e3a,uuid:i?uuid4:uuid3}))
    .filter(x=>x.res.status===200);
  assert.equal(winners.length,1,'Only one competing signed successor allowed');
  assert.equal(concurrent.filter(x=>x.status===409).length,1);
  const winning=winners[0];
  const ack3=verifyAck(winning.res,winning.req,ack2);
  const sameWin=await https(running.port,'POST','/v1/append',winning.req);
  assert.deepEqual(sameWin.data.receipt,ack3);
  const wrongExpected=append(
    sourceEnvelope([uuid1,uuid2,uuid3,uuid4],winning.envelope),ack2);
  await denied(running.port,wrongExpected);
  console.info('PASS 7v: concurrent publishers against identical signed previous receipt produce exactly ONE successor; losing fork/stale replay DENY');
  const tampered=file('tampered-log-state');
  mkdirSync(tampered,{mode:0o700});
  const raw=readFileSync(join(state,'signed-append.jsonl'),'utf8');
  const rows=raw.trim().split('\n').map(x=>JSON.parse(x));
  rows[1].receipt.data.revision=33;
  writeFileSync(join(tampered,'signed-append.jsonl'),
    rows.map(x=>JSON.stringify(x)).join('\n')+'\n',{mode:0o600});
  await startupDeny(tampered);
  const wrongSigner=generateKeyPairSync('ed25519')
    .privateKey.export({type:'pkcs8',format:'pem'});
  const swappedPriv=write('wrong-authority-private.pem',wrongSigner);
  await stop(running);
  const wrongArgs=[
    'serve',state,file('server.key'),file('server.crt'),file('ca.crt'),
    swappedPriv,file('authority.pub'),file('witness.pub'),
    file('journal.pub'),file('client.crt'),file('policy.json'),'0',
  ];
  const wrongRun=spawnSync(process.execPath,[serverPath,...wrongArgs],{
    env,cwd:area,encoding:'utf8',timeout:3000,
  });
  assert.notEqual(wrongRun.status,0,
    'Wrong authority private key must not start');
  running=await launch(state);
  const broken=file('torn-log-state');
  mkdirSync(broken,{mode:0o700});
  copyFileSync(join(state,'signed-append.jsonl'),
    join(broken,'signed-append.jsonl'));
  let torn=await launch(broken,{SAAS_TRANSPORT_TEST_TORN_SEQ:'4'});
  const allIds=[uuid1,uuid2,winning.uuid,uuid5];
  const e4=sourceEnvelope(allIds,winning.envelope);
  const p4=append(e4,ack3);
  await assert.rejects(https(torn.port,'POST','/v1/append',p4));
  await stop(torn,true);
  await startupDeny(broken);
  await assert.rejects(https(torn.port,'GET','/v1/head'));
  assert.equal((await https(running.port,'GET','/v1/head')).data
    .receipt.data.revision,3);
  assert.equal(readFileSync(join(state,'signed-append.jsonl'),'utf8')
    .trim().split('\n').length,3);
  const injected=spawnSync(process.execPath,[serverPath,...wrongArgs],{
    env:{...env,PGHOST:'127.0.0.1'},cwd:area,
    encoding:'utf8',timeout:3000,
  });
  assert.notEqual(injected.status,0);
  console.info('PASS 7v: signed log tamper, swapped authority key, orphan/torn fsync record, server outage and PG/production credentials DENY without auto-repair');
  console.info('LIMITATION 7v: mTLS listener is bound to 127.0.0.1 on ONE CI runner; file permissions/fsync are NOT independent remote custody, HSM, WORM, multi-host fencing, atomic PostgreSQL COMMIT, real recipient ACK or production readiness');
  await stop(running);
}finally{
  rmSync(area,{recursive:true,force:true});
}
