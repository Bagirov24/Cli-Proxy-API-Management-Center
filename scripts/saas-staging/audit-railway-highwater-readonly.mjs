#!/usr/bin/env node
// Stage 7x: read-only sandbox evidence/PKI expiry audit. No repair or
// authority. --selftest is disposable GitHub PG16 CI only.
// --railway-sandbox requires an operator-retained signer pin and minimum.
// Both modes fail closed: never rewrite, truncate, reissue or authorize GC.
import assert from 'node:assert/strict';
import {createHash,createPublicKey,X509Certificate,generateKeyPairSync,
  randomBytes,sign as edSign,verify as edVerify} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,chmodSync,lstatSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {verifyEnvelope,verifyCheckpoint,envelopeDigest}
  from './archive-witness-protocol.mjs';

const PROJECT='dba33407-7200-40e0-a9c8-08c43d41e5e4';
const DOMAIN='staging-highwater.internal.invalid';
const POLICY='saas-synthetic-offhost-mtls-policy-v1';
const AUDIENCE='disposable-ci-network-loopback-only';
const W='saas-synthetic-uuid-witness-v1';
const J='saas-synthetic-ipc-highwater-receipt-v1';
const R='saas-synthetic-offhost-highwater-receipt-v1';
const T='saas-synthetic-offhost-mtls-append-v1';
const RECORD='saas-synthetic-offhost-transport-journal-row-v1';
const HEX=/^[0-9a-f]{64}$/;
const NONCE=/^[0-9a-f]{32}$/;
const sha=v=>createHash('sha256').update(v).digest('hex');
const fp=pem=>sha(createPublicKey(pem).export({type:'spki',format:'der'}));
const xfp=pem=>sha(new X509Certificate(pem).publicKey.export({type:'spki',format:'der'}));
const check=(ok,why)=>{if(!ok)throw Error('AUDIT DENIED: '+why);};
const exact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&
  Object.keys(v).sort().join(',')===keys.slice().sort().join(',');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const signed=(data,domain,publicPem,signature)=>{
  check(typeof signature==='string'&&/^[A-Za-z0-9_-]{80,120}$/.test(signature),
    'malformed detached signature');
  const bytes=Buffer.from(signature,'base64url');
  check(bytes.length===64&&edVerify(null,
    Buffer.from(domain+'\n'+JSON.stringify(data)),publicPem,bytes),
    'Ed25519 signer, domain or receipt mismatch');
};
const pub=(pem,field)=>{
  check(typeof pem==='string'&&pem.startsWith('-----BEGIN PUBLIC KEY-----')&&
    pem.length<15000,'missing pinned public key '+field);
  check(createPublicKey(pem).asymmetricKeyType==='ed25519',
    'non-Ed25519 public key '+field);
  return fp(pem);
};

function inspectCert(name,pem,now,rotationWindowMs){
  check(typeof pem==='string'&&pem.length<15000,'invalid public certificate '+name);
  const cert=new X509Certificate(pem);
  const before=Date.parse(cert.validFrom),after=Date.parse(cert.validTo);
  check(Number.isFinite(before)&&Number.isFinite(after)&&after>before,
    'invalid certificate times '+name);
  const status=now<before?'not-yet-valid':now>=after?'expired':
    after-now<=rotationWindowMs?'rotate-now':'valid';
  return {status,notBefore:new Date(before).toISOString(),
    notAfter:new Date(after).toISOString(),
    publicSpkiSha256:sha(cert.publicKey.export({type:'spki',format:'der'}))};
}

export function inspectPublicPolicy(b,expectedAuthorityFp,now=Date.now(),
  rotationWindowMs=48*60*60*1000){
  check(typeof expectedAuthorityFp==='string'&&HEX.test(expectedAuthorityFp),
    'operator-retained authority pin required');
  check(b&&typeof b==='object'&&!Array.isArray(b)&&
    typeof b.logId==='string'&&NONCE.test(b.logId),
    'synthetic log ID missing');
  const authorityFp=pub(b.authorityPublic,'authority');
  const witnessFp=pub(b.witnessPublic,'witness');
  const journalFp=pub(b.journalPublic,'journal');
  check(authorityFp===expectedAuthorityFp,
    'live signer does not match independent operator supplied pin');
  const ca=new X509Certificate(b.caCert);
  const server=new X509Certificate(b.serverCert);
  const client=new X509Certificate(b.clientCert);
  check(ca.ca&&ca.verify(ca.publicKey),
    'test CA invalid or not self-signed');
  for(const [role,leaf] of [['server',server],['client',client]]){
    check(leaf.checkIssued(ca)&&leaf.verify(ca.publicKey),
      'certificate chain mismatch '+role);
  }
  check(server.checkHost(DOMAIN)===DOMAIN,
    'staging-only TLS DNS identity missing');
  const serverFp=xfp(b.serverCert);
  check(serverFp===b.serverFingerprint,'TLS server SPKI mismatch');
  const policy={
    protocol:POLICY,audience:AUDIENCE,logId:b.logId,epoch:1,
    authorityFingerprint:authorityFp,witnessFingerprint:witnessFp,
    journalFingerprint:journalFp,clientFingerprint:xfp(b.clientCert),
    serverFingerprint:serverFp,
  };
  const certificates={
    ca:inspectCert('ca',b.caCert,now,rotationWindowMs),
    server:inspectCert('server',b.serverCert,now,rotationWindowMs),
    client:inspectCert('client',b.clientCert,now,rotationWindowMs),
  };
  const statuses=Object.values(certificates).map(v=>v.status);
  return {policy,certificates,certificateStatus:
    statuses.includes('expired')?'expired':
    statuses.includes('not-yet-valid')?'not-yet-valid':
    statuses.includes('rotate-now')?'rotation-required':'valid'};
}
function dataFor(req,previous,head,policy){
  return {protocol:R,audience:'disposable-ci-offhost-conformance-only',
    logId:policy.logId,epoch:policy.epoch,
    revision:head.sequence,head,
    previousReceiptDigest:previous?sha(JSON.stringify(previous.receipt)):null,
    witnessFingerprint:policy.witnessFingerprint,
    journalFingerprint:policy.journalFingerprint,
    journalReceiptDigest:sha(JSON.stringify(req.journalReceipt)),
    challengeNonce:req.nonce};
}
export function inspectRecords(lines,policy,roots,operatorMinimum){
  check(Number.isSafeInteger(operatorMinimum)&&operatorMinimum>=1&&
    operatorMinimum<=64,'operator retained minimum 1..64 required');
  check(typeof lines==='string'&&lines.length<12500000&&
    lines.endsWith('\n'),'missing final LF or excessive/torn journal');
  const records=lines.slice(0,-1).split('\n').filter(Boolean);
  check(records.length>0&&records.length<=64,'empty or unbounded journal');
  let prev=null;const used=new Set();
  for(const text of records){
    check(text.length<800000,'oversized journal row');
    const row=JSON.parse(text),req=row.request,receipt=row.receipt;
    check(exact(row,['protocol','request','receipt'])&&row.protocol===RECORD,
      'invalid row protocol or fields');
    check(exact(req,['protocol','nonce','expected','envelope','journalReceipt'])&&
      req.protocol===T&&typeof req.nonce==='string'&&NONCE.test(req.nonce)&&
      !used.has(req.nonce),'invalid request, replay nonce or duplicate');
    used.add(req.nonce);
    check(equal(req.expected,prev?.receipt??null),'stale previous signed receipt');
    const payload=verifyEnvelope(req.envelope,roots.witnessPublic);
    const head={sequence:payload.sequence,digest:envelopeDigest(req.envelope)};
    check(exact(req.journalReceipt,['data','signature'])&&
      exact(req.journalReceipt.data,['protocol','witnessFingerprint','head'])&&
      req.journalReceipt.data.protocol===J&&
      req.journalReceipt.data.witnessFingerprint===policy.witnessFingerprint&&
      equal(req.journalReceipt.data.head,head),
      'local witness and journal head split');
    signed(req.journalReceipt.data,J,roots.journalPublic,
      req.journalReceipt.signature);
    verifyCheckpoint(req.envelope,roots.witnessPublic,head,
      payload.projection,prev?.request.envelope??null);
    check(payload.sequence===(prev?.receipt.data.revision??0)+1&&
      payload.sequence<=64,'remote nonmonotonic witness sequence');
    if(prev){
      let delta=0;
      for(const type of ['issued','producer']){
        const earlier=prev.request.envelope.payload.projection[type];
        const current=payload.projection[type];
        check(earlier.every(v=>current.includes(v)),'deleted witness commitment');
        delta+=current.length-earlier.length;
      }
      check(delta===1,'expected one synthetic committed successor');
    }
    check(exact(receipt,['data','signature'])&&
      equal(receipt.data,dataFor(req,prev,head,policy)),
      'receipt is not bound to exact request/nonce/predecessor');
    signed(receipt.data,R,roots.authorityPublic,receipt.signature);
    prev=row;
  }
  const revision=prev.receipt.data.revision;
  check(revision>=operatorMinimum,
    'observed head below separately supplied retained minimum');
  return {recordCount:records.length,signedRevision:revision,
    signedHeadDigest:prev.receipt.data.head.digest,
    signedReceiptSha256:sha(JSON.stringify(prev.receipt))};
}
export function audit(b,marker,lines,expectedAuthorityFp,min,now=Date.now()){
  const out=inspectPublicPolicy(b,expectedAuthorityFp,now);
  check(marker===sha(JSON.stringify(out.policy))+'\n',
    'private on-volume signer/TLS policy pin changed');
  const journal=inspectRecords(lines,out.policy,b,min);
  return {scope:'RAILWAY_SYNTHETIC_SANDBOX_ONLY',
    certificateStatus:out.certificateStatus,
    certificates:out.certificates,
    authoritySpkiSha256:out.policy.authorityFingerprint,
    policySha256:sha(JSON.stringify(out.policy)),
    ...journal,
    manualReviewRequired:true,independentCustodyVerified:false,
    authorityToIssue:false,reissuePermitted:false,retryPermitted:false,
    repairPermitted:false,deliveryPermitted:false,gcPermitted:false};
}
function privateRead(path,cap){
  const s=lstatSync(path);
  check(s.isFile()&&!s.isSymbolicLink()&&(s.mode&0o077)===0&&s.size<cap,
    'private regular file, mode 0600 or bounded size required');
  return readFileSync(path,'utf8');
}
function railway(){
  check(process.env.SAAS_REMOTE_STAGING_ONLY==='true'&&
    process.env.SAAS_HIGHWATER_TRANSPORT_SCOPE==='SYNTHETIC_NO_ISSUER'&&
    process.env.RAILWAY_PROJECT_ID===PROJECT&&
    process.env.RAILWAY_ENVIRONMENT_NAME==='sandbox'&&
    process.env.GITHUB_ACTIONS!=='true'&&
    !Object.keys(process.env).some(k=>k.startsWith('PG')||
      k==='DATABASE_URL'||k==='SAAS_PRODUCTION_DATABASE_URL'),
    'only isolated Railway synthetic sandbox can be audited');
  const args=process.argv.slice(3);
  check(args.length===2&&HEX.test(args[0])&&/^[1-9][0-9]?$/.test(args[1]),
    'usage: --railway-sandbox <operator-pin-sha256> <retained-minimum>');
  const packed=process.env.SAAS_REMOTE_BOOTSTRAP_B64||'';
  check(packed.length>700&&packed.length<22000,
    'missing bounded synthetic bootstrap');
  const b=JSON.parse(Buffer.from(packed,'base64').toString('utf8'));
  const root='/staging-highwater/private-log';
  const report=audit(b,privateRead(root+'/pinned-identity-sha256',3000),
    privateRead(root+'/signed-append.jsonl',12500000),
    args[0],Number(args[1]));
  process.stdout.write(JSON.stringify(report,null,2)+'\n');
  if(report.certificateStatus!=='valid')process.exitCode=3;
}
function selftest(){
  check(process.env.GITHUB_ACTIONS==='true'&&
    process.env.SAAS_EPHEMERAL_RAILWAY_AUDIT_CI==='true'&&
    process.env.PGHOST==='127.0.0.1'&&
    process.env.PGPORT==='5432'&&
    process.env.PGUSER==='postgres'&&
    process.env.PGDATABASE==='saas_ephemeral_test'&&
    !process.env.RAILWAY_PROJECT_ID&&
    !process.env.SAAS_REMOTE_BOOTSTRAP_B64,
    'selftest requires ephemeral PostgreSQL16 CI, never Railway');
  const dir=mkdtempSync(join(tmpdir(),'saas-7x-audit-'));
  chmodSync(dir,0o700);
  const path=name=>join(dir,name);
  const openssl=args=>execFileSync('openssl',args,{cwd:dir,
    stdio:['ignore','ignore','pipe'],timeout:10000});
  try {
    openssl(['req','-new','-x509','-newkey','rsa:2048','-nodes',
      '-days','10','-keyout','ca.key','-out','ca.crt',
      '-subj','/CN=synthetic-ci-audit-ca',
      '-addext','basicConstraints=critical,CA:TRUE']);
    const leaf=(name,subject,extensions)=>{
      openssl(['req','-new','-newkey','rsa:2048','-nodes',
        '-keyout',name+'.key','-out',name+'.csr','-subj',subject]);
      writeFileSync(path(name+'.ext'),extensions,{mode:0o600});
      openssl(['x509','-req','-in',name+'.csr','-CA','ca.crt',
        '-CAkey','ca.key','-CAcreateserial','-out',name+'.crt',
        '-days','4','-extfile',name+'.ext']);
      return readFileSync(path(name+'.crt'),'utf8');
    };
    const serverCert=leaf('server','/CN='+DOMAIN,
      'subjectAltName=DNS:'+DOMAIN+'\nextendedKeyUsage=serverAuth\n');
    const clientCert=leaf('client','/CN=synthetic-ci-publisher',
      'extendedKeyUsage=clientAuth\n');
    const keys={};
    for(const name of ['authority','witness','journal']){
      const pair=generateKeyPairSync('ed25519');
      keys[name]={private:pair.privateKey,
        public:pair.publicKey.export({type:'spki',format:'pem'}).toString()};
    }
    const b={caCert:readFileSync(path('ca.crt'),'utf8'),serverCert,
      clientCert,authorityPublic:keys.authority.public,
      witnessPublic:keys.witness.public,journalPublic:keys.journal.public,
      logId:randomBytes(16).toString('hex'),serverFingerprint:xfp(serverCert)};
    const pin=fp(b.authorityPublic);
    const out=inspectPublicPolicy(b,pin);
    const mark=sha(JSON.stringify(out.policy))+'\n';
    const uuid=['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa9401',
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa9402'];
    const commit=uuid.map(u=>sha(W+'\0issued\0'+u));
    const rows=[];let old=null;
    for(let index=0;index<2;index++){
      const issued=commit.slice(0,index+1).sort();
      const projection={protocol:W+'-commitments',issued,producer:[],
        issuedCount:issued.length,producerCount:0};
      const payload={protocol:W,audience:'ephemeral-pg16-proof-only',
        sequence:index+1,previous:old?envelopeDigest(old.request.envelope):null,
        projectionRoot:sha(JSON.stringify(projection)),projection};
      const sign=(data,domain,key)=>edSign(null,
        Buffer.from(domain+'\n'+JSON.stringify(data)),key).toString('base64url');
      const env={payload,algorithm:'Ed25519',keyFingerprint:fp(b.witnessPublic),
        signature:sign(payload,W,keys.witness.private)};
      const head={sequence:index+1,digest:envelopeDigest(env)};
      const journalData={protocol:J,witnessFingerprint:fp(b.witnessPublic),head};
      const request={protocol:T,nonce:randomBytes(16).toString('hex'),
        expected:old?.receipt??null,envelope:env,
        journalReceipt:{data:journalData,
          signature:sign(journalData,J,keys.journal.private)}};
      const data=dataFor(request,old,head,out.policy);
      const receipt={data,signature:sign(data,R,keys.authority.private)};
      old={protocol:RECORD,request,receipt};rows.push(old);
    }
    const text=rows.map(x=>JSON.stringify(x)+'\n').join('');
    const verify=(raw=text,marker=mark,min=2,pub=b,expected=pin,now=Date.now())=>
      audit(pub,marker,raw,expected,min,now);
    const good=verify();
    assert.equal(good.signedRevision,2);
    assert.equal(good.recordCount,2);
    assert.equal(good.gcPermitted,false);
    assert.equal(good.certificateStatus,'valid');
    const rejects=fn=>assert.throws(fn,/AUDIT DENIED|signature|mismatch|Detached|Missing|Unpinned|Stale/);
    rejects(()=>verify(text.slice(0,-1)));
    rejects(()=>verify(rows.slice(0,1).map(x=>JSON.stringify(x)+'\n').join('')));
    rejects(()=>verify(text,mark,3));
    rejects(()=>verify(text,mark,2,b,'0'.repeat(64)));
    rejects(()=>verify(text,mark+'altered'));
    const corrupt=structuredClone(rows);corrupt[1].receipt.data.challengeNonce='0'.repeat(32);
    rejects(()=>verify(corrupt.map(x=>JSON.stringify(x)+'\n').join('')));
    const rebound=structuredClone(rows);rebound[1].request.nonce=rebound[0].request.nonce;
    rejects(()=>verify(rebound.map(x=>JSON.stringify(x)+'\n').join('')));
    const stale=structuredClone(rows);stale[1].request.expected=null;
    rejects(()=>verify(stale.map(x=>JSON.stringify(x)+'\n').join('')));
    const rotated=verify(text,mark,2,b,pin,Date.now()+3*86400000);
    assert.equal(rotated.certificateStatus,'rotation-required');
    const expired=verify(text,mark,2,b,pin,Date.now()+5*86400000);
    assert.equal(expired.certificateStatus,'expired');
    const fake=structuredClone(b);fake.serverFingerprint='0'.repeat(64);
    rejects(()=>verify(text,mark,2,fake));
    process.stdout.write('PASS 7x: synthetic public-only mTLS PKI expiry, '+
      'signed monotonic 2-row high-water, nonce, quorum-free rollback floor, '+
      'marker/torn record/tamper/incorrect pin/stale expected DENY; '+
      'no issuer or GC\n');
  }finally{rmSync(dir,{recursive:true,force:true});}
}
try {
  if(process.argv[2]==='--selftest'&&process.argv.length===3)selftest();
  else if(process.argv[2]==='--railway-sandbox')railway();
  else throw Error('Only --selftest or --railway-sandbox with explicit pin/minimum');
}catch(error){
  process.stderr.write('AUDIT QUARANTINE: '+(error?.message||String(error))+'\n');
  process.exitCode=2;
}
