#!/usr/bin/env node
// Stage 2G.4d.7q: separate local high-water IPC signer, disposable CI ONLY.
// Not off-host durable storage, WORM, producer authority or atomic PG commit.
import {createServer,connect} from 'node:net';
import {dirname,resolve,join} from 'node:path';
import {tmpdir} from 'node:os';
import {
  existsSync,mkdirSync,chmodSync,readdirSync,readFileSync,writeFileSync,
  openSync,closeSync,fsyncSync,renameSync,unlinkSync,
} from 'node:fs';
import {
  createHash,generateKeyPairSync,createPublicKey,createPrivateKey,
  sign as edSign,verify as edVerify,randomUUID,
} from 'node:crypto';
import {
  verifyEnvelope,verifyCheckpoint,envelopeDigest,canonicalProjection,
} from './archive-witness-protocol.mjs';

const PROTOCOL='saas-synthetic-ipc-highwater-receipt-v1';
const HEX=/^[0-9a-f]{64}$/;
const check=(value,message)=>{if(!value)throw Error(message);};
const exact=(x,keys)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
  Object.keys(x).sort().join(',')===keys.slice().sort().join(',');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const hash=x=>createHash('sha256').update(x).digest('hex');
const fingerprint=pem=>hash(createPublicKey(pem).export({type:'spki',format:'der'}));
const headOf=env=>({sequence:env.payload.sequence,digest:envelopeDigest(env)});
const headValid=x=>x===null||(exact(x,['sequence','digest'])&&
  Number.isSafeInteger(x.sequence)&&x.sequence>0&&
  typeof x.digest==='string'&&HEX.test(x.digest));
function guard() {
  check(process.env.GITHUB_ACTIONS==='true'&&
    process.env.SAAS_EPHEMERAL_IPC_WITNESS_CI==='true'&&
    process.env.SAAS_EPHEMERAL_WITNESS_OFFLINE==='true'&&
    process.env.SAAS_EPHEMERAL_HIGHWATER_CI==='true'&&
    !Object.keys(process.env).some(k=>k.startsWith('PG')||
      k.startsWith('RAILWAY')||k==='DATABASE_URL'||
      k==='SAAS_PRODUCTION_DATABASE_URL'),
    'Refusing high-water process with PG/production credentials');
}
function pathGuard(path) {
  check(path.startsWith(resolve(tmpdir(),'saas-ipc-witness-')),
    'Refusing high-water path outside disposable private runner directory');
}
function fsyncDir(path) {
  const fd=openSync(path,'r');
  try {fsyncSync(fd);} finally {closeSync(fd);}
}
function exclusive(path,bytes) {
  const fd=openSync(path,'wx',0o600);
  try {writeFileSync(fd,bytes);fsyncSync(fd);} finally {closeSync(fd);}
  fsyncDir(dirname(path));
}
function atomic(path,value) {
  const pending=join(dirname(path),'.pending-'+randomUUID());
  exclusive(pending,JSON.stringify(value)+'\n');
  renameSync(pending,path);
  fsyncDir(dirname(path));
}
function readJson(path) {
  const data=readFileSync(path,'utf8');
  check(data.length>0&&data.length<250000,
    'Torn or oversized high-water record');
  return JSON.parse(data);
}
function recordPath(dir,seq) {
  return join(dir,'checkpoints',String(seq).padStart(8,'0')+'.json');
}
function seal(head,privatePem,witnessPem) {
  const data={protocol:PROTOCOL,witnessFingerprint:fingerprint(witnessPem),head};
  const signature=edSign(null,Buffer.from(PROTOCOL+'\n'+JSON.stringify(data)),
    createPrivateKey(privatePem)).toString('base64url');
  return {data,signature};
}
function verifySeal(receipt,publicPem,witnessPem,head) {
  check(exact(receipt,['data','signature'])&&
    exact(receipt.data,['protocol','witnessFingerprint','head'])&&
    receipt.data.protocol===PROTOCOL&&
    receipt.data.witnessFingerprint===fingerprint(witnessPem)&&
    headValid(receipt.data.head)&&equal(receipt.data.head,head)&&
    typeof receipt.signature==='string'&&
    /^[A-Za-z0-9_-]{80,120}$/.test(receipt.signature),
    'Invalid signed high-water receipt');
  const sig=Buffer.from(receipt.signature,'base64url');
  check(sig.length===64&&edVerify(null,
    Buffer.from(PROTOCOL+'\n'+JSON.stringify(receipt.data)),publicPem,sig),
    'High-water Ed25519 signature mismatch');
}
function validateDelta(candidate,previous) {
  const now=canonicalProjection(candidate);
  const old=canonicalProjection(previous);
  let added=0;
  for(const kind of ['issued','producer']) {
    const present=new Set(now[kind]);
    check(old[kind].every(x=>present.has(x)),
      'High-water historical UUID rollback');
    added+=now[kind].length-old[kind].length;
  }
  check(added===1,'High-water permits only one newly signed UUID');
}
function initialize(dir,witnessPem) {
  if(!existsSync(dir)) {
    mkdirSync(join(dir,'checkpoints'),{recursive:true,mode:0o700});
    chmodSync(dir,0o700);fsyncDir(dirname(dir));
    const pair=generateKeyPairSync('ed25519');
    exclusive(join(dir,'private.pem'),
      pair.privateKey.export({type:'pkcs8',format:'pem'}));
    exclusive(join(dir,'public.pem'),
      pair.publicKey.export({type:'spki',format:'pem'}));
    exclusive(join(dir,'witness-pin.json'),JSON.stringify({
      protocol:PROTOCOL,fingerprint:fingerprint(witnessPem),
    })+'\n');
  }
  const entries=readdirSync(dir).sort();
  const required=['checkpoints','private.pem','public.pem','witness-pin.json',
    ...(existsSync(join(dir,'head.json'))?['head.json']:[])].sort();
  check(equal(entries,required),'High-water pending/orphan or foreign state');
  const pin=readJson(join(dir,'witness-pin.json'));
  check(exact(pin,['protocol','fingerprint'])&&pin.protocol===PROTOCOL&&
    pin.fingerprint===fingerprint(witnessPem),
    'Independent witness trust root mismatch');
  const privatePem=readFileSync(join(dir,'private.pem'),'utf8');
  const publicPem=readFileSync(join(dir,'public.pem'),'utf8');
  check(createPublicKey(createPrivateKey(privatePem))
    .export({type:'spki',format:'pem'}).toString()===publicPem,
    'High-water signing key mismatch');
  const files=readdirSync(join(dir,'checkpoints')).sort();
  check(files.length<=128,'High-water capacity exceeded');
  const state={head:null,previous:null,history:[],witnessPem,privatePem,publicPem};
  for(let i=0;i<files.length;i++) {
    check(files[i]===String(i+1).padStart(8,'0')+'.json',
      'Out-of-order high-water checkpoints');
    const row=readJson(recordPath(dir,i+1));
    check(exact(row,['envelope','receipt']),'Malformed high-water journal row');
    const payload=verifyEnvelope(row.envelope,witnessPem);
    const next=headOf(row.envelope);
    verifyCheckpoint(row.envelope,witnessPem,next,payload.projection,
      state.previous);
    if(state.previous)validateDelta(payload.projection,
      state.previous.payload.projection);
    check(payload.sequence===i+1,'High-water witness sequence gap');
    verifySeal(row.receipt,publicPem,witnessPem,next);
    state.head=next;
    state.previous=row.envelope;
    state.history.push(row);
  }
  const present=existsSync(join(dir,'head.json'));
  check(present===(state.history.length>0),
    'High-water crash after checkpoint before head: DENY');
  if(present)check(equal(readJson(join(dir,'head.json')),state.head),
    'High-water head drift/rollback: DENY');
  return state;
}
function reply(state) {
  const receipt=state.history.at(-1)?.receipt??seal(null,
    state.privatePem,state.witnessPem);
  return {ok:true,state:'HIGHWATER',receipt,gcPermitted:false};
}
function handle(message,state,dir) {
  check(message!==null&&typeof message==='object'&&!Array.isArray(message),
    'Malformed high-water request');
  if(message.op==='status') {
    check(exact(message,['op']),'Extra status fields');
    return reply(state);
  }
  check(message.op==='advance'&&exact(message,['op','envelope']),
    'Only signed witness advance accepted');
  const payload=verifyEnvelope(message.envelope,state.witnessPem);
  const next=headOf(message.envelope);
  if(equal(next,state.head)) {
    check(equal(message.envelope,state.previous),
      'High-water same-head envelope mismatch');
    return reply(state);
  }
  check(state.history.length<128,'High-water history full');
  verifyCheckpoint(message.envelope,state.witnessPem,next,payload.projection,
    state.previous);
  if(state.previous)validateDelta(payload.projection,
    state.previous.payload.projection);
  check(payload.sequence===(state.head?.sequence??0)+1,
    'High-water fork/gap/predecessor denied');
  const receipt=seal(next,state.privatePem,state.witnessPem);
  const row={envelope:message.envelope,receipt};
  exclusive(recordPath(dir,next.sequence),JSON.stringify(row)+'\n');
  if(process.env.SAAS_HIGHWATER_TEST_KILL_BEFORE_HEAD===
    String(next.sequence))process.kill(process.pid,'SIGKILL');
  atomic(join(dir,'head.json'),next);
  state.history.push(row);state.previous=message.envelope;state.head=next;
  if(process.env.SAAS_HIGHWATER_TEST_LOSE_ACK===
    String(next.sequence))process.kill(process.pid,'SIGKILL');
  return reply(state);
}
function serve(args) {
  check(args.length===3,
    'serve requires separate high-water state, socket and pinned witness public key');
  const [dir,socket,pubPath]=args.map(x=>resolve(x));
  [dir,socket,pubPath].forEach(pathGuard);
  check(!existsSync(socket)&&
    !socket.startsWith(dir+'/')&&!dir.startsWith(socket+'/'),
    'Unsafe high-water socket path');
  const witnessPem=readFileSync(pubPath,'utf8');
  check(witnessPem.length>0&&witnessPem.length<16000&&
    createPublicKey(witnessPem).asymmetricKeyType==='ed25519',
    'Invalid trusted witness public key');
  const state=initialize(dir,witnessPem);
  const server=createServer(client=>{
    client.setEncoding('utf8');
    client.setTimeout(6000,()=>client.destroy());
    let pending='',handled=false;
    client.on('data',part=>{
      if(handled)return;
      pending+=String(part);
      if(pending.length>200000) {
        handled=true;client.end('{"ok":false,"error":"DENIED"}\n');return;
      }
      if(!pending.includes('\n'))return;
      handled=true;
      try {
        const idx=pending.indexOf('\n');
        check(!pending.slice(idx+1).trim(),'Only one journal message');
        const response=handle(JSON.parse(pending.slice(0,idx)),state,dir);
        client.end(JSON.stringify(response)+'\n');
      }catch(_err){client.end('{"ok":false,"error":"DENIED"}\n');}
    });
    client.on('error',()=>{});
  });
  server.on('error',err=>{
    process.stderr.write('HIGHWATER DENIED: '+err.message+'\n');
    process.exitCode=2;
  });
  server.listen(socket,()=>{
    chmodSync(socket,0o600);
    process.stdout.write('READY: isolated local high-water journal\n');
  });
  process.on('SIGTERM',()=>server.close(()=>{
    try{unlinkSync(socket);}catch{}
    process.exit(0);
  }));
}
function client(args) {
  check(args.length===2,'client requires local socket and canonical JSON request');
  const socket=resolve(args[0]);pathGuard(socket);
  const body=args[1];
  check(typeof body==='string'&&body.length>0&&body.length<150000,
    'Bounded high-water message required');
  const connection=connect({path:socket});
  connection.setEncoding('utf8');
  connection.setTimeout(4500,()=>connection.destroy(Error('High-water timeout')));
  let got='',finished=false;
  connection.on('connect',()=>connection.write(body+'\n'));
  connection.on('data',chunk=>{
    got+=String(chunk);
    if(got.length>200000)connection.destroy(Error('Large high-water reply'));
    if(got.includes('\n')&&!finished) {
      finished=true;
      try {
        const [first,...rest]=got.split('\n');
        check(!rest.join('').trim(),'Unexpected high-water response');
        const parsed=JSON.parse(first);
        check(parsed.ok===true,'High-water refused publication');
        process.stdout.write(JSON.stringify(parsed)+'\n');
        connection.end();
      }catch(error){
        process.stderr.write('HIGHWATER DENIED: '+error.message+'\n');
        process.exitCode=1;connection.destroy();
      }
    }
  });
  connection.on('error',err=>{
    process.stderr.write('HIGHWATER DENIED: '+err.message+'\n');
    process.exitCode=1;
  });
  connection.on('end',()=>{
    if(!finished)process.exitCode=1;
  });
}
try {
  guard();
  const [mode,...args]=process.argv.slice(2);
  if(mode==='serve')serve(args);
  else if(mode==='client')client(args);
  else throw Error('Expected high-water serve/client');
}catch(err){
  process.stderr.write('HIGHWATER DENIED: '+(err?.message||String(err))+'\n');
  process.exitCode=2;
}
