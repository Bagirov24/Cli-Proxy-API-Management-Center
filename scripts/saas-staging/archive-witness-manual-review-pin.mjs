#!/usr/bin/env node
// Stage 2G.4d.7s — SIMULATED reviewer-held signed head, manual-only.
// Third signing key and saved pin live on the SAME disposable CI runner.
// Not an independent off-host root, approval, recovery or producer API.
import {readFileSync,openSync,writeFileSync,fsyncSync,closeSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {
  createHash,createPublicKey,createPrivateKey,
  sign as edSign,verify as edVerify,
} from 'node:crypto';
import {verifyEnvelope,envelopeDigest} from './archive-witness-protocol.mjs';

const TYPE='saas-synthetic-manual-review-pin-v1';
const JOURNAL='saas-synthetic-ipc-highwater-receipt-v1';
const AUDIENCE='disposable-ci-manual-review-only';
const HEX=/^[0-9a-f]{64}$/;
const SIGNATURE=/^[A-Za-z0-9_-]{80,120}$/;
const check=(x,message)=>{if(!x)throw Error(message);};
const exact=(v,fields)=>v!==null&&typeof v==='object'&&
  !Array.isArray(v)&&
  Object.keys(v).sort().join(',')===fields.slice().sort().join(',');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const hash=data=>createHash('sha256').update(data).digest('hex');
const fp=pem=>hash(createPublicKey(pem).export({type:'spki',format:'der'}));
const headOf=env=>({sequence:env.payload.sequence,digest:envelopeDigest(env)});
const validHead=v=>exact(v,['sequence','digest'])&&
  Number.isSafeInteger(v.sequence)&&v.sequence>0&&
  typeof v.digest==='string'&&HEX.test(v.digest);
function safePath(value) {
  const path=resolve(value);
  check(path.startsWith(resolve(tmpdir(),'saas-ipc-witness-'))&&
    !path.includes('/../'),'No paths outside disposable private CI workspace');
  return path;
}
function fileJson(path) {
  const bytes=readFileSync(safePath(path),'utf8');
  check(bytes.length>0&&bytes.length<400000,
    'Missing, torn or excessive review evidence');
  return JSON.parse(bytes);
}
function readPem(path) {
  const pem=readFileSync(safePath(path),'utf8');
  check(pem.length>0&&pem.length<16000&&
    createPublicKey(pem).asymmetricKeyType==='ed25519',
    'Missing or malformed pinned Ed25519 public key');
  return pem;
}
function guard() {
  check(process.env.GITHUB_ACTIONS==='true'&&
    process.env.SAAS_EPHEMERAL_WITNESS_OFFLINE==='true'&&
    process.env.SAAS_EPHEMERAL_MANUAL_REVIEW_CI==='true'&&
    !Object.keys(process.env).some(x=>x.startsWith('PG')||
      x.startsWith('RAILWAY')||x==='DATABASE_URL'||
      x==='SAAS_PRODUCTION_DATABASE_URL'),
    'Review evidence forbidden outside offline synthetic CI');
}
function verifyJournal(doc,pub,witnessPem) {
  check(exact(doc,['data','signature'])&&
    exact(doc.data,['protocol','witnessFingerprint','head'])&&
    doc.data.protocol===JOURNAL&&
    doc.data.witnessFingerprint===fp(witnessPem)&&
    validHead(doc.data.head)&&
    typeof doc.signature==='string'&&SIGNATURE.test(doc.signature),
    'Malformed or untrusted high-water receipt');
  const sig=Buffer.from(doc.signature,'base64url');
  check(sig.length===64&&edVerify(null,Buffer.from(
    JOURNAL+'\n'+JSON.stringify(doc.data)),pub,sig),
    'Invalid high-water signature');
  return doc.data.head;
}
function verifyPin(pin,pub,witnessPem,journalPem) {
  check(exact(pin,['data','signature'])&&
    exact(pin.data,['protocol','audience','witnessFingerprint',
      'journalFingerprint','head','previousReviewDigest'])&&
    pin.data.protocol===TYPE&&pin.data.audience===AUDIENCE&&
    pin.data.witnessFingerprint===fp(witnessPem)&&
    pin.data.journalFingerprint===fp(journalPem)&&
    validHead(pin.data.head)&&
    (pin.data.previousReviewDigest===null||
      (typeof pin.data.previousReviewDigest==='string'&&
        HEX.test(pin.data.previousReviewDigest)))&&
    typeof pin.signature==='string'&&SIGNATURE.test(pin.signature),
    'Wrong reviewer pin format, pinned signer or sequence');
  const sig=Buffer.from(pin.signature,'base64url');
  check(sig.length===64&&edVerify(null,Buffer.from(
    TYPE+'\n'+JSON.stringify(pin.data)),pub,sig),
    'Reviewer Ed25519 signature denied');
  return pin.data.head;
}
function signPin(args) {
  check(args.length===9&&args[8]==='--no-gc',
    'pin: reviewPriv reviewPub witnessPub journalPub signedWitness journalReceipt prevOrDash output --no-gc');
  const [privatePath,reviewPubPath,witnessPubPath,journalPubPath,
    envelopePath,journalReceiptPath,previousPath,outputPath]=args;
  const reviewerPem=readPem(reviewPubPath);
  const witnessPem=readPem(witnessPubPath);
  const journalPem=readPem(journalPubPath);
  const privatePem=readFileSync(safePath(privatePath),'utf8');
  check(privatePem.length>0&&privatePem.length<16000&&
    createPublicKey(createPrivateKey(privatePem))
      .export({type:'spki',format:'pem'}).toString()===reviewerPem,
    'Reviewer signing root mismatch');
  const env=fileJson(envelopePath);
  verifyEnvelope(env,witnessPem);
  const head=headOf(env);
  const journalHead=verifyJournal(fileJson(journalReceiptPath),
    journalPem,witnessPem);
  check(equal(head,journalHead),'Cannot pin a split or stale local head');
  const previous=previousPath==='-'?null:fileJson(previousPath);
  if(previous) {
    const before=verifyPin(previous,reviewerPem,witnessPem,journalPem);
    check(head.sequence===before.sequence+1&&
      env.payload.previous===before.digest&&
      head.digest!==before.digest,
      'Reviewer pin requires a direct authentic successor');
  }else check(head.sequence===1&&env.payload.previous===null,
    'Reviewer genesis cannot skip an unpinned predecessor');
  const data={
    protocol:TYPE,audience:AUDIENCE,
    witnessFingerprint:fp(witnessPem),
    journalFingerprint:fp(journalPem),
    head,
    previousReviewDigest:previous?hash(JSON.stringify(previous)):null,
  };
  const receipt={data,signature:edSign(null,Buffer.from(
    TYPE+'\n'+JSON.stringify(data)),privatePem).toString('base64url')};
  // O_EXCL + file and parent directory fsync: no accidental overwrite of
  // a saved reviewer root on this ONE disposable runner.
  const file=safePath(outputPath);
  const fd=openSync(file,'wx',0o600);
  try {writeFileSync(fd,JSON.stringify(receipt)+'\n');fsyncSync(fd);}
  finally {closeSync(fd);}
  const dir=openSync(dirname(file),'r');
  try {fsyncSync(dir);} finally {closeSync(dir);}
  process.stdout.write(JSON.stringify({
    protocol:TYPE,kind:'SIMULATED_REVIEW_PIN_WRITTEN',
    head,manualReviewRequired:true,authorizationGranted:false,
    reissuePermitted:false,retryPermitted:false,
    deliveryPermitted:false,gcPermitted:false,
  })+'\n');
}
function inspect(args) {
  check(args.length===7&&args[6]==='--no-gc',
    'inspect: reviewPub witnessPub journalPub signedWitness journalReceipt trustedReviewerPin --no-gc');
  const [reviewPubPath,witnessPubPath,journalPubPath,
    envelopePath,journalReceiptPath,pinPath]=args;
  const reviewerPem=readPem(reviewPubPath);
  const witnessPem=readPem(witnessPubPath);
  const journalPem=readPem(journalPubPath);
  const pin=fileJson(pinPath);
  const anchoredHead=verifyPin(pin,reviewerPem,witnessPem,journalPem);
  const env=fileJson(envelopePath);
  verifyEnvelope(env,witnessPem);
  const witnessHead=headOf(env);
  const journalHead=verifyJournal(fileJson(journalReceiptPath),
    journalPem,witnessPem);
  let status='PIN_MATCHED_FOR_MANUAL_INSPECTION';
  if(!equal(witnessHead,journalHead))
    status='SPLIT_SIGNED_LOCAL_HEADS_REVIEW_REQUIRED';
  else if(witnessHead.sequence<anchoredHead.sequence)
    status='COORDINATED_LOCAL_ROLLBACK_SUSPECTED';
  else if(witnessHead.sequence===anchoredHead.sequence&&
    witnessHead.digest!==anchoredHead.digest)
    status='CONFLICTING_SIGNED_HEAD_REVIEW_REQUIRED';
  else if(witnessHead.sequence>anchoredHead.sequence)
    status='UNPINNED_LOCAL_ADVANCE_REVIEW_REQUIRED';
  process.stdout.write(JSON.stringify({
    protocol:TYPE,status,
    manualReviewRequired:true,locallySignedOnly:true,
    offHostAnchorVerified:false,
    authorizationGranted:false,reissuePermitted:false,
    retryPermitted:false,deliveryPermitted:false,
    gcPermitted:false,repairPermitted:false,
  })+'\n');
}
try {
  guard();
  const [mode,...args]=process.argv.slice(2);
  if(mode==='pin')signPin(args);
  else if(mode==='inspect')inspect(args);
  else throw Error('Only offline pin or inspect; no repair/retry/GC operations');
}catch(err){
  process.stderr.write('MANUAL REVIEW DENIED: '+
    (err?.message||String(err))+'\n');
  process.exitCode=1;
}
