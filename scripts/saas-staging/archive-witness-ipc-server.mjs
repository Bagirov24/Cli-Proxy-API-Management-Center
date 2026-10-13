#!/usr/bin/env node
// Stage 2G.4d.7n: ONE-RUNNER Unix-socket witness daemon, TEST ONLY.
// Independently running process, NOT independent host, operator or WORM.
// It cannot access PG, Railway, HTTP, client secrets, issue UUIDs or GC.
// Signed envelopes are only canonical synthetic UUID commitments.
import { createServer } from 'node:net';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync,
  openSync, closeSync, fsyncSync, renameSync, chmodSync, unlinkSync,
} from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  generateKeyPairSync, createPrivateKey, createPublicKey, createHash,
  sign as edSign, verify as edVerify, randomUUID, randomBytes,
} from 'node:crypto';
import {
  canonicalProjection, envelopeDigest, verifyEnvelope, verifyCheckpoint,
} from './archive-witness-protocol.mjs';

const PROTOCOL='saas-synthetic-uuid-witness-v1';
const AUDIENCE='ephemeral-pg16-proof-only';
const RECEIPT='saas-synthetic-ipc-witness-receipt-v1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[0-9a-f]{32}$/;
const PG_ATTEST='saas-synthetic-pg-projection-attestation-v1';
const PG_CHALLENGE='saas-synthetic-pg-projection-challenge-v1';
const PG_PIN='saas-synthetic-ipc-pg-projector-pin-v1';
const HIGHWATER='saas-synthetic-ipc-highwater-receipt-v1';
const HIGHWATER_PIN='saas-synthetic-ipc-highwater-pin-v1';
const highwaterClient=fileURLToPath(new URL('./archive-witness-highwater-ipc.mjs',import.meta.url));
const check=(v,why)=>{if(!v)throw Error(why);};
const exact=(x,names)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
  Object.keys(x).sort().join(',')===names.slice().sort().join(',');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const hash=data=>createHash('sha256').update(data).digest('hex');
const headOf=env=>({sequence:env.payload.sequence,digest:envelopeDigest(env)});
const canonicalHead=x=>x===null||(
  exact(x,['sequence','digest'])&&
  Number.isSafeInteger(x.sequence)&&x.sequence>0&&
  typeof x.digest==='string'&&HEX.test(x.digest));
function guard() {
  check(process.env.GITHUB_ACTIONS==='true'&&
    process.env.SAAS_EPHEMERAL_IPC_WITNESS_CI==='true'&&
    process.env.SAAS_EPHEMERAL_WITNESS_OFFLINE==='true'&&
    !Object.keys(process.env).some(name=>
      name.startsWith('PG')||name.startsWith('RAILWAY')||
      name==='DATABASE_URL'||name==='SAAS_PRODUCTION_DATABASE_URL'),
    'Refusing witness daemon with DB, Railway or production credentials');
  check(process.argv.length===4,'daemon requires only state-dir and local socket');
  const [dir,socket]=process.argv.slice(2).map(path=>resolve(path));
  const prefix=resolve(tmpdir(),'saas-ipc-witness-');
  check(dir.startsWith(prefix)&&socket.startsWith(prefix) &&
    !dir.startsWith(socket+'/')&&!socket.startsWith(dir+'/')&&
    !dir.includes('/../')&&!socket.includes('/../')&&
    !existsSync(socket),
    'Refusing witness state outside disposable private CI directory');
  // 7p is a separate opt-in proof-only daemon. Its trust root is configured
  // at startup, NEVER received from an IPC caller. Old 7n append stays
  // available only in the deliberately unprotected legacy test mode.
  const proofMode=process.env.SAAS_EPHEMERAL_PG_WITNESS_PROOF_CI==='true';
  const pinPath=process.env.SAAS_EPHEMERAL_PROJECTOR_PUBKEY_PATH;
  let projectorPem=null;
  if(proofMode) {
    check(typeof pinPath==='string'&&
      resolve(pinPath).startsWith(dirname(dir)+'/')&&
      resolve(pinPath)!==dir&&existsSync(pinPath),
      'Only a private disposable projector trust root may be pinned');
    projectorPem=readFileSync(pinPath,'utf8');
    check(projectorPem.length>0&&projectorPem.length<16000&&
      createPublicKey(projectorPem).asymmetricKeyType==='ed25519',
      'Malformed pinned ephemeral Ed25519 projector key');
  } else check(!pinPath,'Projector key only allowed in proof-only mode');
  // Optional 7q LOCAL journal mode is not an independently administered
  // root. Strictly avoid silent downgrade of an already journal-fenced state.
  const highwaterEnabled=process.env.SAAS_EPHEMERAL_HIGHWATER_CI==='true';
  const highwaterSocket=process.env.SAAS_EPHEMERAL_HIGHWATER_SOCKET_PATH;
  const highwaterPublicPath=process.env.SAAS_EPHEMERAL_HIGHWATER_PUBLIC_KEY_PATH;
  let highwater=null;
  if(highwaterEnabled) {
    check(proofMode&&typeof highwaterSocket==='string'&&
      typeof highwaterPublicPath==='string'&&
      resolve(highwaterSocket).startsWith(dirname(dir)+'/')&&
      resolve(highwaterPublicPath).startsWith(dirname(dir)+'/')&&
      existsSync(highwaterPublicPath),
      'Local high-water requires protected staging witness and private pin');
    const publicPem=readFileSync(highwaterPublicPath,'utf8');
    check(publicPem.length>0&&publicPem.length<16000&&
      createPublicKey(publicPem).asymmetricKeyType==='ed25519',
      'Invalid high-water public root');
    highwater={socket:resolve(highwaterSocket),publicPem};
  } else check(!highwaterSocket&&!highwaterPublicPath,
    'Refusing unsigned high-water configuration downgrade');
  return {dir,socket,proofMode,projectorPem,highwater};
}
function fsyncDir(path) {
  const fd=openSync(path,'r');
  try {fsyncSync(fd);} finally {closeSync(fd);}
}
function exclusive(path,data) {
  const fd=openSync(path,'wx',0o600);
  try {writeFileSync(fd,data);fsyncSync(fd);} finally {closeSync(fd);}
  fsyncDir(dirname(path));
}
function atomic(path,object) {
  const pending=join(dirname(path),'.pending-'+randomUUID());
  exclusive(pending,JSON.stringify(object)+'\n');
  renameSync(pending,path);
  fsyncDir(dirname(path));
}
function readJson(path) {
  const raw=readFileSync(path,'utf8');
  check(raw.length>0&&raw.length<3_000_000,'Torn or excessive witness file');
  return JSON.parse(raw);
}
function getPath(dir,seq) {
  return join(dir,'checkpoints',String(seq).padStart(8,'0')+'.json');
}
function signReceipt(data,privatePem) {
  const signature=edSign(null,Buffer.from(RECEIPT+'\n'+JSON.stringify(data)),
    createPrivateKey(privatePem)).toString('base64url');
  return {data,signature};
}
function verifyReceipt(receipt,publicPem,record) {
  check(exact(receipt,['data','signature'])&&
    exact(receipt.data,['protocol','requestId','sequence','digest']) &&
    receipt.data.protocol===RECEIPT &&
    receipt.data.requestId===record.requestId &&
    receipt.data.sequence===record.envelope.payload.sequence &&
    receipt.data.digest===envelopeDigest(record.envelope) &&
    typeof receipt.signature==='string' &&
    /^[A-Za-z0-9_-]{80,120}$/.test(receipt.signature),
    'Malformed signed IPC receipt');
  check(edVerify(null,Buffer.from(RECEIPT+'\n'+JSON.stringify(receipt.data)),
      publicPem,Buffer.from(receipt.signature,'base64url')),
    'Signed IPC receipt verification failed');
}
function signEnvelope(projection,old,privatePem,publicPem) {
  const seq=(old?.payload.sequence??0)+1;
  const payload={
    protocol:PROTOCOL,audience:AUDIENCE,sequence:seq,
    previous:old?envelopeDigest(old):null,
    projectionRoot:hash(JSON.stringify(projection)),projection,
  };
  const signature=edSign(null,Buffer.from(PROTOCOL+'\n'+JSON.stringify(payload)),
    createPrivateKey(privatePem)).toString('base64url');
  const keyFingerprint=hash(createPublicKey(publicPem)
    .export({type:'spki',format:'der'}));
  return {payload,algorithm:'Ed25519',keyFingerprint,signature};
}
function exactSingleNew(current,previous) {
  const old=canonicalProjection(previous),now=canonicalProjection(current);
  let total=0;
  for(const kind of ['issued','producer']) {
    const seen=new Set(old[kind]);
    check(old[kind].every(item=>now[kind].includes(item)),
      'Monotonic witness history rollback denied');
    total+=now[kind].filter(item=>!seen.has(item)).length;
  }
  check(total===1,'Only exactly ONE newly committed synthetic UUID per successor');
}
function projectorFingerprint(pem) {
  return hash(createPublicKey(pem).export({type:'spki',format:'der'}));
}
function sourceProjection(proof,challenge,projectorPem) {
  check(exact(challenge,['protocol','nonce','expected'])&&
    challenge.protocol===PG_CHALLENGE&&ID.test(challenge.nonce)&&
    canonicalHead(challenge.expected),
    'Wrong witness-issued source challenge');
  check(exact(proof,['statement','signature'])&&
    typeof proof.signature==='string'&&
    /^[A-Za-z0-9_-]{80,120}$/.test(proof.signature),
    'Missing or malformed source signature');
  const signed=proof.statement;
  check(exact(signed,['protocol','audience','challenge','expected','source','projection'])&&
    signed.protocol===PG_ATTEST&&signed.audience===AUDIENCE&&
    signed.challenge===challenge.nonce&&
    equal(signed.expected,challenge.expected)&&
    exact(signed.source,['database','snapshot'])&&
    signed.source.database==='saas_ephemeral_test'&&
    typeof signed.source.snapshot==='string'&&
    /^[0-9:,]{3,256}$/.test(signed.source.snapshot),
    'Source identity, nonce or predecessor not bound');
  const projection=canonicalProjection(signed.projection);
  check(equal(projection,signed.projection),
    'Noncanonical signed PostgreSQL projection');
  const sig=Buffer.from(proof.signature,'base64url');
  check(sig.length===64&&edVerify(null,
    Buffer.from(PG_ATTEST+'\n'+JSON.stringify(signed)),projectorPem,sig),
    'Untrusted source signature or signed projection');
  return projection;
}
function initialize(dir,proofMode,projectorPem,highwater) {
  if(!existsSync(dir)) {
    mkdirSync(join(dir,'checkpoints'),{recursive:true,mode:0o700});
    chmodSync(dir,0o700);
    fsyncDir(dirname(dir));
    const pair=generateKeyPairSync('ed25519');
    exclusive(join(dir,'private.pem'),
      pair.privateKey.export({type:'pkcs8',format:'pem'}));
    exclusive(join(dir,'public.pem'),
      pair.publicKey.export({type:'spki',format:'pem'}));
    if(proofMode)exclusive(join(dir,'projector-pin.json'),JSON.stringify({
      protocol:PG_PIN,fingerprint:projectorFingerprint(projectorPem),
    })+'\n');
  }
  // Bootstrap journal fencing ONLY onto a still-EMPTY witness. Existing
  // signed checkpoints cannot silently acquire a different trust root.
  const highwaterPin=join(dir,'highwater-pin.json');
  if(highwater&&!existsSync(highwaterPin)) {
    check(!existsSync(join(dir,'head.json'))&&
      readdirSync(join(dir,'checkpoints')).length===0,
      'Refusing retrospective local journal enrollment');
    exclusive(highwaterPin,JSON.stringify({
      protocol:HIGHWATER_PIN,
      fingerprint:projectorFingerprint(highwater.publicPem),
    })+'\n');
  }
  const files=readdirSync(dir).sort();
  const expected=['checkpoints','private.pem','public.pem',
    ...(proofMode?['projector-pin.json']:[]),
    ...(highwater?['highwater-pin.json']:[]),
    ...(existsSync(join(dir,'head.json'))?['head.json']:[])].sort();
  check(equal(files,expected),'Witness orphan, pending file, or foreign state: DENY');
  const privatePem=readFileSync(join(dir,'private.pem'),'utf8');
  const publicPem=readFileSync(join(dir,'public.pem'),'utf8');
  check(privatePem.length<16000&&publicPem.length<16000,'Invalid witness keys');
  check(createPublicKey(createPrivateKey(privatePem))
      .export({type:'spki',format:'pem'}).toString()===publicPem,
    'Witness key pair mismatch');
  if(proofMode) {
    const pin=readJson(join(dir,'projector-pin.json'));
    check(exact(pin,['protocol','fingerprint'])&&pin.protocol===PG_PIN&&
      pin.fingerprint===projectorFingerprint(projectorPem),
      'Projector trust root changed on restart: DENY');
  }
  if(highwater) {
    const pin=readJson(highwaterPin);
    check(exact(pin,['protocol','fingerprint'])&&
      pin.protocol===HIGHWATER_PIN&&
      pin.fingerprint===projectorFingerprint(highwater.publicPem),
      'High-water trust root substitution denied');
  }
  const entries=readdirSync(join(dir,'checkpoints')).sort();
  check(entries.length<=128,'Witness history capacity exhausted');
  const state={history:[],head:null,privatePem,publicPem,
    proofMode,projectorPem,highwater,pending:new Map(),seenNonces:new Set()};
  const ids=new Set();
  for(let i=0;i<entries.length;i++) {
    check(entries[i]===String(i+1).padStart(8,'0')+'.json',
      'Non-monotonic or orphan witness checkpoint');
    const row=readJson(getPath(dir,i+1));
    check(exact(row,proofMode?
      ['requestId','expected','envelope','receipt','challenge','attestation']:
      ['requestId','expected','envelope','receipt'])&&
      ID.test(row.requestId)&&canonicalHead(row.expected)&&
      !ids.has(row.requestId),'Duplicate or malformed persistent request');
    const previous=state.history.at(-1);
    check(equal(row.expected,previous?headOf(previous.envelope):null),
      'Wrong durable witness predecessor');
    const payload=verifyEnvelope(row.envelope,publicPem);
    verifyCheckpoint(row.envelope,publicPem,headOf(row.envelope),
      payload.projection,previous?.envelope??null);
    if(previous)exactSingleNew(payload.projection,previous.envelope.payload.projection);
    verifyReceipt(row.receipt,publicPem,row);
    if(proofMode) {
      check(equal(row.challenge.expected,row.expected)&&
        !state.seenNonces.has(row.challenge.nonce),
        'Duplicate, wrong or rolled-back source challenge');
      const fromPg=sourceProjection(row.attestation,row.challenge,projectorPem);
      check(equal(fromPg,payload.projection)&&
        payload.projectionRoot===hash(JSON.stringify(fromPg)),
        'Persistent witness does not match verified PG proof digest');
      state.seenNonces.add(row.challenge.nonce);
    }
    state.history.push(row);
    ids.add(row.requestId);
  }
  const exists=existsSync(join(dir,'head.json'));
  check(exists===(state.history.length>0),
    'Witness checkpoint/head publication interrupted; DENY');
  if(exists) {
    const persisted=readJson(join(dir,'head.json'));
    check(canonicalHead(persisted)&&
      equal(persisted,headOf(state.history.at(-1).envelope)),
      'Witness head rollback or orphan signed checkpoint; DENY');
    state.head=persisted;
  }
  return state;
}
function highwaterAction(state,request,expectedHead) {
  if(!state.highwater)return;
  const message=JSON.stringify(request);
  check(message.length<140000,'Journal IPC capacity exhausted: DENY');
  // Synchronous local child invocation preserves 7n single-writer
  // processing, without passing SQL credentials to either signer.
  const response=spawnSync(process.execPath,[
    highwaterClient,'client',state.highwater.socket,message,
  ],{
    env:{
      GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_IPC_WITNESS_CI:'true',
      SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
      SAAS_EPHEMERAL_HIGHWATER_CI:'true',
      PATH:process.env.PATH||'/usr/bin:/bin',
      HOME:dirname(state.highwater.socket),LANG:'C',
    },
    encoding:'utf8',timeout:5500,maxBuffer:250000,
  });
  check(response.status===0,
    'High-water IPC unavailable or disputed: DENY');
  const reply=JSON.parse(response.stdout);
  check(exact(reply,['ok','state','receipt','gcPermitted'])&&
    reply.ok===true&&reply.state==='HIGHWATER'&&
    reply.gcPermitted===false&&
    exact(reply.receipt,['data','signature'])&&
    exact(reply.receipt.data,
      ['protocol','witnessFingerprint','head'])&&
    reply.receipt.data.protocol===HIGHWATER&&
    reply.receipt.data.witnessFingerprint===
      projectorFingerprint(state.publicPem)&&
    canonicalHead(reply.receipt.data.head)&&
    equal(reply.receipt.data.head,expectedHead)&&
    typeof reply.receipt.signature==='string'&&
    /^[A-Za-z0-9_-]{80,120}$/.test(reply.receipt.signature),
    'Unsigned or stale high-water response: DENY');
  const sig=Buffer.from(reply.receipt.signature,'base64url');
  check(sig.length===64&&edVerify(null,Buffer.from(HIGHWATER+'\n'+
    JSON.stringify(reply.receipt.data)),state.highwater.publicPem,sig),
    'High-water signer identity mismatch: DENY');
}
function sealed(row) {
  return {ok:true,state:'SEALED',head:headOf(row.envelope),
    envelope:row.envelope,receipt:row.receipt,gcPermitted:false};
}
function handle(message,state,dir) {
  check(message!==null&&typeof message==='object'&&!Array.isArray(message),
    'Malformed witness request');
  if(state.highwater)highwaterAction(state,{op:'status'},state.head);
  if(message.op==='head') {
    check(exact(message,['op']),'Invalid head operation');
    return state.history.length?sealed(state.history.at(-1)):
      {ok:true,state:'EMPTY',gcPermitted:false};
  }
  if(message.op==='check') {
    check(exact(message,['op','projection']),'Invalid check operation');
    const now=canonicalProjection(message.projection);
    const latest=state.history.at(-1);
    check(latest&&equal(now,latest.envelope.payload.projection),
      'Unsigned, stale or missing committed UUID: DENY');
    return sealed(latest);
  }
  if(message.op==='challenge-pg') {
    check(state.proofMode&&
      exact(message,['op','requestId','expected'])&&
      ID.test(message.requestId)&&canonicalHead(message.expected)&&
      equal(message.expected,state.head)&&
      !state.history.some(row=>row.requestId===message.requestId),
      'Wrong, stale or duplicate source challenge request');
    let challenge=state.pending.get(message.requestId);
    if(challenge)check(equal(challenge.expected,message.expected),
      'Challenge idempotency conflict');
    else {
      check(state.pending.size<32,'Outstanding challenge capacity exhausted');
      let nonce;
      do {nonce=randomBytes(16).toString('hex');}
      while(state.seenNonces.has(nonce));
      state.seenNonces.add(nonce);
      challenge={protocol:PG_CHALLENGE,nonce,expected:message.expected};
      state.pending.set(message.requestId,challenge);
    }
    return {ok:true,state:'CHALLENGE',requestId:message.requestId,
      challenge,gcPermitted:false};
  }
  if(message.op==='append'||message.op==='append-pg') {
    const protectedAppend=message.op==='append-pg';
    check(protectedAppend===state.proofMode&&
      exact(message,protectedAppend?
        ['op','requestId','expected','attestation']:
        ['op','requestId','expected','projection'])&&
      ID.test(message.requestId)&&canonicalHead(message.expected),
      'Malformed append, wrong mode, or untrusted request identifier');
    const prior=state.history.find(x=>x.requestId===message.requestId);
    const challenge=protectedAppend?
      (prior?.challenge??state.pending.get(message.requestId)):null;
    if(protectedAppend)check(challenge&&
      equal(challenge.expected,message.expected),
      'Missing witness-issued challenge: DENY');
    // Projector signature and source identity are validated INSIDE this
    // daemon, before any successor is signed. Client projections are
    // forbidden in protected mode, including on idempotent replay.
    const now=protectedAppend?
      sourceProjection(message.attestation,challenge,state.projectorPem):
      canonicalProjection(message.projection);
    // A lost ACK may recover ONLY an identical request/attestation from
    // the already fsynced record, including after a daemon restart.
    if(prior) {
      check(equal(prior.expected,message.expected)&&
        equal(prior.envelope.payload.projection,now)&&
        (!protectedAppend||equal(prior.attestation,message.attestation)),
        'Idempotency key conflict: DENY');
      return sealed(prior);
    }
    check(equal(message.expected,state.head),
      'Expected witness head is stale, forked or missing');
    check(state.history.length<128,'Witness history capacity exceeded');
    const last=state.history.at(-1);
    if(last)exactSingleNew(now,last.envelope.payload.projection);
    const envelope=signEnvelope(now,last?.envelope??null,
      state.privatePem,state.publicPem);
    verifyCheckpoint(envelope,state.publicPem,headOf(envelope),
      now,last?.envelope??null);
    const receipt=signReceipt({
      protocol:RECEIPT,requestId:message.requestId,
      sequence:envelope.payload.sequence,digest:envelopeDigest(envelope),
    },state.privatePem);
    const row=protectedAppend?
      {requestId:message.requestId,expected:message.expected,envelope,
        receipt,challenge,attestation:message.attestation}:
      {requestId:message.requestId,expected:message.expected,envelope,receipt};
    // This is a single-writer Unix-socket daemon: synchronous processing
    // serializes contenders. It is NOT consensus/atomicity with PostgreSQL.
    exclusive(getPath(dir,envelope.payload.sequence),
      JSON.stringify(row)+'\n');
    if(process.env.SAAS_WITNESS_TEST_KILL_BEFORE_HEAD===
      String(envelope.payload.sequence))process.kill(process.pid,'SIGKILL');
    atomic(join(dir,'head.json'),headOf(envelope));
    state.history.push(row);
    state.head=headOf(envelope);
    if(state.highwater) {
      if(process.env.SAAS_WITNESS_TEST_KILL_BEFORE_HIGHWATER===
        String(envelope.payload.sequence))process.kill(process.pid,'SIGKILL');
      // A signed witness fsync is NOT a positive ACK until a SECOND
      // separately signed journal head has been persisted and verified.
      // Crash between these two local publications means DENY on restart,
      // never automatic duplicate issuance or silent journal repair.
      highwaterAction(state,{op:'advance',envelope},state.head);
    }
    if(protectedAppend)state.pending.delete(message.requestId);
    // Simulate a durable witness ACK lost AFTER fsync+rename, BEFORE any
    // bytes of the receipt reach caller. Restart must replay same receipt.
    if(process.env.SAAS_WITNESS_TEST_LOSE_ACK===
      String(envelope.payload.sequence))process.kill(process.pid,'SIGKILL');
    return sealed(row);
  }
  throw Error('Unknown operation');
}
const {dir,socket,proofMode,projectorPem,highwater}=guard();
let state;
try {
  state=initialize(dir,proofMode,projectorPem,highwater);
  if(state.highwater)highwaterAction(state,{op:'status'},state.head);
}
catch(error) {
  process.stderr.write('IPC WITNESS DENIED: '+error.message+'\n');
  process.exit(2);
}
const server=createServer(client=>{
  client.setEncoding('utf8');
  client.setTimeout(6000,()=>client.destroy());
  let pending='';
  let handled=false;
  client.on('data',part=>{
    if(handled)return;
    pending+=part;
    if(pending.length>1_000_000) {
      client.end(JSON.stringify({ok:false,error:'DENIED'})+'\n');
      return;
    }
    if(!pending.includes('\n'))return;
    handled=true;
    try {
      const line=pending.slice(0,pending.indexOf('\n'));
      check(!pending.slice(pending.indexOf('\n')+1).trim(),
        'One request per connection');
      const reply=handle(JSON.parse(line),state,dir);
      client.end(JSON.stringify(reply)+'\n');
    }catch(_err) {
      client.end(JSON.stringify({ok:false,error:'DENIED'})+'\n');
    }
  });
  client.on('error',()=>{});
});
server.on('error',error=>{
  process.stderr.write('IPC WITNESS DENIED: '+error.message+'\n');
  process.exitCode=2;
});
server.listen(socket,()=>{
  chmodSync(socket,0o600);
  process.stdout.write('READY: isolated test-only Unix-socket witness\n');
});
process.on('SIGTERM',()=>{
  server.close(()=>{
    try{unlinkSync(socket);}catch{}
    process.exit(0);
  });
});
