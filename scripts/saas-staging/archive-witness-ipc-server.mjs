#!/usr/bin/env node
// Stage 2G.4d.7n: ONE-RUNNER Unix-socket witness daemon, TEST ONLY.
// Independently running process, NOT independent host, operator or WORM.
// It cannot access PG, Railway, HTTP, client secrets, issue UUIDs or GC.
// Signed envelopes are only canonical synthetic UUID commitments.
import { createServer } from 'node:net';
import {
  existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync,
  openSync, closeSync, fsyncSync, renameSync, chmodSync, unlinkSync,
} from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  generateKeyPairSync, createPrivateKey, createPublicKey, createHash,
  sign as edSign, verify as edVerify, randomUUID,
} from 'node:crypto';
import {
  canonicalProjection, envelopeDigest, verifyEnvelope, verifyCheckpoint,
} from './archive-witness-protocol.mjs';

const PROTOCOL='saas-synthetic-uuid-witness-v1';
const AUDIENCE='ephemeral-pg16-proof-only';
const RECEIPT='saas-synthetic-ipc-witness-receipt-v1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[0-9a-f]{32}$/;
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
  return {dir,socket};
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
function initialize(dir) {
  if(!existsSync(dir)) {
    mkdirSync(join(dir,'checkpoints'),{recursive:true,mode:0o700});
    chmodSync(dir,0o700);
    fsyncDir(dirname(dir));
    const pair=generateKeyPairSync('ed25519');
    exclusive(join(dir,'private.pem'),
      pair.privateKey.export({type:'pkcs8',format:'pem'}));
    exclusive(join(dir,'public.pem'),
      pair.publicKey.export({type:'spki',format:'pem'}));
  }
  const files=readdirSync(dir).sort();
  const expected=['checkpoints','private.pem','public.pem',...(existsSync(join(dir,'head.json'))?['head.json']:[])].sort();
  check(equal(files,expected),'Witness orphan, pending file, or foreign state: DENY');
  const privatePem=readFileSync(join(dir,'private.pem'),'utf8');
  const publicPem=readFileSync(join(dir,'public.pem'),'utf8');
  check(privatePem.length<16000&&publicPem.length<16000,'Invalid witness keys');
  check(createPublicKey(createPrivateKey(privatePem))
      .export({type:'spki',format:'pem'}).toString()===publicPem,
    'Witness key pair mismatch');
  const entries=readdirSync(join(dir,'checkpoints')).sort();
  check(entries.length<=128,'Witness history capacity exhausted');
  const state={history:[],head:null,privatePem,publicPem};
  const ids=new Set();
  for(let i=0;i<entries.length;i++) {
    check(entries[i]===String(i+1).padStart(8,'0')+'.json',
      'Non-monotonic or orphan witness checkpoint');
    const row=readJson(getPath(dir,i+1));
    check(exact(row,['requestId','expected','envelope','receipt'])&&
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
function sealed(row) {
  return {ok:true,state:'SEALED',head:headOf(row.envelope),
    envelope:row.envelope,receipt:row.receipt,gcPermitted:false};
}
function handle(message,state,dir) {
  check(message!==null&&typeof message==='object'&&!Array.isArray(message),
    'Malformed witness request');
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
  if(message.op==='append') {
    check(exact(message,['op','requestId','expected','projection'])&&
      ID.test(message.requestId)&&canonicalHead(message.expected),
      'Malformed append or untrusted request identifier');
    const now=canonicalProjection(message.projection);
    // Idempotent recovery after a lost COMMIT/receipt response: the
    // same operation + same predecessor + same projection yields EXACT
    // original signed receipt. A changed replay is always rejected.
    const prior=state.history.find(x=>x.requestId===message.requestId);
    if(prior) {
      check(equal(prior.expected,message.expected)&&
        equal(prior.envelope.payload.projection,now),
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
    verifyEnvelope(envelope,state.publicPem);
    const receipt=signReceipt({
      protocol:RECEIPT,requestId:message.requestId,
      sequence:envelope.payload.sequence,digest:envelopeDigest(envelope),
    },state.privatePem);
    const row={requestId:message.requestId,expected:message.expected,
      envelope,receipt};
    // This is a single-writer Unix-socket daemon: synchronous processing
    // serializes contenders. It is NOT consensus/atomicity with PostgreSQL.
    exclusive(getPath(dir,envelope.payload.sequence),
      JSON.stringify(row)+'\n');
    if(process.env.SAAS_WITNESS_TEST_KILL_BEFORE_HEAD===
      String(envelope.payload.sequence))process.kill(process.pid,'SIGKILL');
    atomic(join(dir,'head.json'),headOf(envelope));
    state.history.push(row);
    state.head=headOf(envelope);
    // Simulate a durable witness ACK lost AFTER fsync+rename, BEFORE any
    // bytes of the receipt reach caller. Restart must replay same receipt.
    if(process.env.SAAS_WITNESS_TEST_LOSE_ACK===
      String(envelope.payload.sequence))process.kill(process.pid,'SIGKILL');
    return sealed(row);
  }
  throw Error('Unknown operation');
}
const {dir,socket}=guard();
let state;
try {state=initialize(dir);}
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
