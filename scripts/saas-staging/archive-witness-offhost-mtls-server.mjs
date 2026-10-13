#!/usr/bin/env node
// Stage 2G.4d.7v: actual HTTPS/mTLS + append-only fsync transport
// prototype. LOOPBACK ONLY, disposable CI, not off-host/WORM or
// production authorization. No PG credentials, issuer, retry or GC.
import {createServer} from 'node:https';
import {
  createHash,createPrivateKey,createPublicKey,X509Certificate,
  sign as edSign,verify as edVerify,
} from 'node:crypto';
import {
  readFileSync,existsSync,mkdirSync,chmodSync,openSync,closeSync,
  writeSync,fsyncSync,statSync,lstatSync,
} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {
  verifyEnvelope,verifyCheckpoint,envelopeDigest,
} from './archive-witness-protocol.mjs';

const TRANSPORT='saas-synthetic-offhost-mtls-append-v1';
const POLICY='saas-synthetic-offhost-mtls-policy-v1';
const AUDIENCE='disposable-ci-network-loopback-only';
const RECORD='saas-synthetic-offhost-transport-journal-row-v1';
const RECEIPT='saas-synthetic-offhost-highwater-receipt-v1';
const RECEIPT_AUD='disposable-ci-offhost-conformance-only';
const JOURNAL='saas-synthetic-ipc-highwater-receipt-v1';
const NONCE=/^[0-9a-f]{32}$/;
const HEX=/^[0-9a-f]{64}$/;
const SIG=/^[A-Za-z0-9_-]{80,120}$/;
const check=(yes,why)=>{if(!yes)throw Error(why);};
const exact=(x,keys)=>x!==null&&typeof x==='object'&&
  !Array.isArray(x)&&
  Object.keys(x).sort().join(',')===keys.slice().sort().join(',');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sha=v=>createHash('sha256').update(v).digest('hex');
const fp=pem=>sha(createPublicKey(pem).export({type:'spki',format:'der'}));
const x509fp=cert=>sha(new X509Certificate(cert).publicKey
  .export({type:'spki',format:'der'}));
const headOf=env=>({sequence:env.payload.sequence,digest:envelopeDigest(env)});
function safe(path){
  const dest=resolve(path);
  check(dest.startsWith(resolve(tmpdir(),'saas-ipc-witness-')),
    'Only private disposable synthetic runner paths supported');
  if(existsSync(dest))check(!lstatSync(dest).isSymbolicLink(),
    'Refusing symlinked witness/transport data');
  return dest;
}
function read(path,cap=16000) {
  const file=readFileSync(safe(path));
  check(file.length>0&&file.length<cap,'Missing or oversized transport data');
  return file;
}
function guard(){
  check(process.env.GITHUB_ACTIONS==='true'&&
    process.env.SAAS_EPHEMERAL_EXTERNAL_TRANSPORT_CI==='true'&&
    process.env.SAAS_EPHEMERAL_WITNESS_OFFLINE==='true'&&
    !Object.keys(process.env).some(k=>
      k.startsWith('PG')||k.startsWith('RAILWAY')||
      k==='DATABASE_URL'||k==='SAAS_PRODUCTION_DATABASE_URL'),
    'No production, PG credentials or non-CI network transport');
}
function signature(doc,pem,domain){
  check(exact(doc,['data','signature'])&&
    typeof doc.signature==='string'&&SIG.test(doc.signature),
    'Malformed remote signed receipt');
  const sig=Buffer.from(doc.signature,'base64url');
  check(sig.length===64&&edVerify(null,Buffer.from(
    domain+'\n'+JSON.stringify(doc.data)),pem,sig),
    'Remote signer/journal identity or signature mismatch');
  return doc.data;
}
function currentJournal(row,witnessPem,journalPem) {
  const data=signature(row,journalPem,JOURNAL);
  check(exact(data,['protocol','witnessFingerprint','head'])&&
    data.protocol===JOURNAL&&
    data.witnessFingerprint===fp(witnessPem)&&
    exact(data.head,['sequence','digest'])&&
    Number.isSafeInteger(data.head.sequence)&&data.head.sequence>0&&
    typeof data.head.digest==='string'&&HEX.test(data.head.digest),
    'Journal witness binding invalid');
  return data.head;
}
function validateRequest(req,prev,policy,keys){
  check(exact(req,['protocol','nonce','expected','envelope','journalReceipt'])&&
    req.protocol===TRANSPORT&&
    typeof req.nonce==='string'&&NONCE.test(req.nonce),
    'No valid append request/nonce');
  check(equal(req.expected,prev?.receipt??null),
    'Stale or altered external expected signed receipt');
  const payload=verifyEnvelope(req.envelope,keys.witness);
  const head=headOf(req.envelope);
  const journalHead=currentJournal(req.journalReceipt,keys.witness,keys.journal);
  check(equal(head,journalHead),'Local journal/witness split DENY');
  verifyCheckpoint(req.envelope,keys.witness,head,payload.projection,
    prev?.request.envelope??null);
  check(payload.sequence===(prev?.receipt.data.revision??0)+1,
    'Remote revision/sequence gap or fork');
  if(prev) {
    let delta=0;
    const before=verifyEnvelope(prev.request.envelope,keys.witness).projection;
    for(const type of ['issued','producer']){
      const current=new Set(payload.projection[type]);
      check(before[type].every(x=>current.has(x)),
        'Historical UUID commitment removed by remote append');
      delta+=payload.projection[type].length-before[type].length;
    }
    check(delta===1,'Expected exactly one signed UUID successor');
  }
  check(payload.sequence<=64,'CI-only bounded high-water capacity reached');
  return head;
}
function dataFor(req,previous,head,policy) {
  return {
    protocol:RECEIPT,audience:RECEIPT_AUD,
    logId:policy.logId,epoch:policy.epoch,
    revision:head.sequence,head,
    previousReceiptDigest:previous?sha(JSON.stringify(previous.receipt)):null,
    witnessFingerprint:policy.witnessFingerprint,
    journalFingerprint:policy.journalFingerprint,
    journalReceiptDigest:sha(JSON.stringify(req.journalReceipt)),
    challengeNonce:req.nonce,
  };
}
function sign(data,key){
  return {data,signature:edSign(null,Buffer.from(
    RECEIPT+'\n'+JSON.stringify(data)),key).toString('base64url')};
}
function validateRecord(record,previous,policy,keys){
  check(exact(record,['protocol','request','receipt'])&&
    record.protocol===RECORD,'Malformed transport durable record');
  const head=validateRequest(record.request,previous,policy,keys);
  const data=signature(record.receipt,keys.authority,RECEIPT);
  check(equal(data,dataFor(record.request,previous,head,policy)),
    'Durable receipt not bound to exact append or old head');
}
function store(dir,policy,keys) {
  const location=safe(dir);
  if(!existsSync(location)){
    mkdirSync(location,{mode:0o700});
    const parentFd=openSync(dirname(location),'r');
    try{fsyncSync(parentFd);}finally{closeSync(parentFd);}
  }
  check(statSync(location).isDirectory()&&
    (statSync(location).mode&0o077)===0,
    'Remote log directory must be private 0700');
  const log=safe(location+'/signed-append.jsonl');
  if(!existsSync(log)){
    const fd=openSync(log,'wx',0o600);
    try{fsyncSync(fd);}finally{closeSync(fd);}
    const d=openSync(location,'r');
    try{fsyncSync(d);}finally{closeSync(d);}
  }
  const raw=readFileSync(log,'utf8');
  check(raw.length<12500000,'Bounded transport journal exceeded');
  check(raw.length===0||raw.endsWith('\n'),
    'Torn remote append is UNKNOWN; refusing automatic truncation/repair');
  const history=[],used=new Map();
  for(const line of raw.split('\n').filter(Boolean)){
    check(line.length<800000,'Journal row exceeds limit');
    const row=JSON.parse(line);
    validateRecord(row,history.at(-1)??null,policy,keys);
    const digest=sha(JSON.stringify(row.request));
    check(!used.has(row.request.nonce),
      'Duplicate nonce in append-only receipt journal');
    used.set(row.request.nonce,{digest,receipt:row.receipt});
    history.push(row);
  }
  return {log,history,used};
}
function advance(req,state,policy,keys) {
  const digest=sha(JSON.stringify(req));
  const existing=state.used.get(req?.nonce);
  if(existing){
    check(existing.digest===digest,
      'Rebound replay nonce with different payload DENY');
    return existing.receipt;
  }
  const previous=state.history.at(-1)??null;
  const head=validateRequest(req,previous,policy,keys);
  const receipt=sign(dataFor(req,previous,head,policy),keys.private);
  const row={protocol:RECORD,request:req,receipt};
  const raw=JSON.stringify(row)+'\n';
  check(raw.length<800000,'Remote request too large for journal');
  if(process.env.SAAS_TRANSPORT_TEST_TORN_SEQ===String(head.sequence)){
    const fd=openSync(state.log,'a',0o600);
    try{writeSync(fd,raw.slice(0,Math.floor(raw.length/3)));fsyncSync(fd);}
    finally{closeSync(fd);}
    process.kill(process.pid,'SIGKILL');
  }
  const fd=openSync(state.log,'a',0o600);
  try {
    const bytes=Buffer.from(raw);
    let at=0;
    while(at<bytes.length)at+=writeSync(fd,bytes,at,bytes.length-at);
    fsyncSync(fd);
  }finally{closeSync(fd);}
  state.history.push(row);
  state.used.set(req.nonce,{digest,receipt});
  if(process.env.SAAS_TRANSPORT_TEST_LOSE_ACK_SEQ===String(head.sequence))
    process.kill(process.pid,'SIGKILL');
  return receipt;
}
function respond(res,status,content){
  res.writeHead(status,{'content-type':'application/json',
    'cache-control':'no-store','x-content-type-options':'nosniff'});
  res.end(JSON.stringify(content)+'\n');
}
function serverMain(args){
  check(args.length===11,
    'serve stateDir TLS-key TLS-cert CA authorityPrivate authorityPub witnessPub journalPub clientCert policy port');
  const [dir,tlsKey,tlsCert,caFile,authorityPrivate,authorityPub,
    witnessPub,journalPub,clientCert,policyPath,portText]=args;
  check(/^(0|[1-9][0-9]{0,4})$/.test(portText),
    'Only bounded explicit loopback port');
  const port=Number(portText);check(port<=65535,'Invalid listener port');
  const keys={
    private:createPrivateKey(read(authorityPrivate)),
    authority:read(authorityPub),witness:read(witnessPub),
    journal:read(journalPub),
  };
  const policy=JSON.parse(read(policyPath,3000));
  check(exact(policy,['protocol','audience','logId','epoch',
    'authorityFingerprint','witnessFingerprint','journalFingerprint',
    'clientFingerprint','serverFingerprint'])&&
    policy.protocol===POLICY&&policy.audience===AUDIENCE&&
    typeof policy.logId==='string'&&NONCE.test(policy.logId)&&
    policy.epoch===1&&
    policy.authorityFingerprint===fp(keys.authority)&&
    policy.witnessFingerprint===fp(keys.witness)&&
    policy.journalFingerprint===fp(keys.journal)&&
    policy.clientFingerprint===x509fp(read(clientCert))&&
    policy.serverFingerprint===x509fp(read(tlsCert))&&
    fp(createPublicKey(keys.private))===fp(keys.authority),
    'Unpinned authority, TLS client, signer identity or policy');
  const state=store(dir,policy,keys);
  const server=createServer({
    key:read(tlsKey),cert:read(tlsCert),ca:read(caFile),
    requestCert:true,rejectUnauthorized:true,
    minVersion:'TLSv1.3',
  },(req,res)=>{
    try{
      check(req.socket.authorized===true&&
        req.socket.getPeerCertificate(true)?.raw,
        'Mutual TLS certificate required');
      const client= x509fp(req.socket.getPeerCertificate(true).raw);
      check(client===policy.clientFingerprint,
        'Authenticated but unpinned publisher certificate DENY');
      if(req.url==='/v1/head'&&req.method==='GET'){
        return respond(res,200,{
          protocol:TRANSPORT,receipt:state.history.at(-1)?.receipt??null,
          manualReviewRequired:true,authorizationGranted:false,
          reissuePermitted:false,retryPermitted:false,
          repairPermitted:false,deliveryPermitted:false,gcPermitted:false,
        });
      }
      check(req.url==='/v1/append'&&req.method==='POST',
        'No production/recovery/issuer endpoints');
      check(req.headers['content-type']==='application/json',
        'Strict JSON content type');
      let chunks='',done=false;
      req.setTimeout(6000,()=>req.destroy());
      req.on('data',part=>{
        if(done)return;
        chunks+=part;
        if(chunks.length>800000) {
          done=true;respond(res,413,{ok:false,error:'DENIED'});
          req.destroy();
        }
      });
      req.on('end',()=>{
        if(done)return;done=true;
        try{
          const request=JSON.parse(chunks);
          const receipt=advance(request,state,policy,keys);
          respond(res,200,{
            ok:true,receipt,manualReviewRequired:true,
            authorizationGranted:false,reissuePermitted:false,
            retryPermitted:false,repairPermitted:false,
            deliveryPermitted:false,gcPermitted:false,
          });
        }catch(_e){respond(res,409,{ok:false,error:'DENIED'});}
      });
    }catch(_err){respond(res,403,{ok:false,error:'DENIED'});}
  });
  server.on('error',error=>{
    process.stderr.write('TRANSPORT DENIED: '+error.message+'\n');
    process.exitCode=2;
  });
  server.listen(port,'127.0.0.1',()=>{
    process.stdout.write('READY: synthetic mutual TLS loopback port '+
      server.address().port+'\n');
  });
  process.on('SIGTERM',()=>server.close(()=>process.exit(0)));
}
try{
  guard();
  const [cmd,...args]=process.argv.slice(2);
  check(cmd==='serve','Only test-only mTLS service; no issuer/repair commands');
  serverMain(args);
}catch(error){
  process.stderr.write('TRANSPORT DENIED: '+(error?.message||String(error))+'\n');
  process.exitCode=2;
}
