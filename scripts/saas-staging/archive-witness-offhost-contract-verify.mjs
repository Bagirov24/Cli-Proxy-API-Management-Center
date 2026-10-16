#!/usr/bin/env node
// Stage 2G.4d.7t: verify a PROPOSED off-host signed high-water wire
// contract against pinned local evidence. CI-only, offline/read-only.
// This never contacts, runs, or proves an independent off-host service;
// the producer/reviewer cannot use any result to issue/retry/repair/GC.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {
  verifyEnvelope,verifyCheckpoint,envelopeDigest,
} from './archive-witness-protocol.mjs';

const POLICY='saas-synthetic-offhost-policy-v1';
const RECEIPT='saas-synthetic-offhost-highwater-receipt-v1';
const INPUT='saas-synthetic-offhost-inspection-bundle-v1';
const CHALLENGE='saas-synthetic-offhost-nonce-challenge-v1';
const JOURNAL='saas-synthetic-ipc-highwater-receipt-v1';
const AUDIENCE='disposable-ci-offhost-conformance-only';
const HEX=/^[0-9a-f]{64}$/;
const TOKEN=/^[0-9a-f]{32}$/;
const SIG=/^[A-Za-z0-9_-]{80,120}$/;
const check=(condition,why)=>{if(!condition)throw Error(why);};
const exact=(x,keys)=>x!==null&&typeof x==='object'&&
  !Array.isArray(x)&&
  Object.keys(x).sort().join(',')===keys.slice().sort().join(',');
const same=(x,y)=>JSON.stringify(x)===JSON.stringify(y);
const sha=x=>createHash('sha256').update(x).digest('hex');
const fingerprint=pem=>sha(createPublicKey(pem).export({type:'spki',format:'der'}));
const headOf=env=>({sequence:env.payload.sequence,digest:envelopeDigest(env)});
const validHead=head=>exact(head,['sequence','digest'])&&
  Number.isSafeInteger(head.sequence)&&head.sequence>0&&
  typeof head.digest==='string'&&HEX.test(head.digest);
function safeRead(path) {
  const full=resolve(path);
  check(full.startsWith(resolve(tmpdir(),'saas-ipc-witness-')),
    'Proof inputs restricted to disposable private CI area');
  const value=readFileSync(full,'utf8');
  check(value.length>0&&value.length<3500000,
    'Missing or excessive off-host proof input');
  return value;
}
function readJson(path) {return JSON.parse(safeRead(path));}
function readPublic(path) {
  const pem=safeRead(path);
  check(pem.length<16000&&
    createPublicKey(pem).asymmetricKeyType==='ed25519',
    'Pinned Ed25519 root must be valid');
  return pem;
}
function offlineOnly() {
  check(process.env.GITHUB_ACTIONS==='true'&&
    process.env.SAAS_EPHEMERAL_WITNESS_OFFLINE==='true'&&
    process.env.SAAS_EPHEMERAL_OFFHOST_CONFORMANCE_CI==='true'&&
    !Object.keys(process.env).some(k=>
      k.startsWith('PG')||k.startsWith('RAILWAY')||
      k==='DATABASE_URL'||k==='SAAS_PRODUCTION_DATABASE_URL'),
    'No production, PostgreSQL credentials or network mode allowed');
}
function pinnedPolicy(policy,authorityPem,witnessPem,journalPem) {
  check(exact(policy,['protocol','audience','logId','epoch',
    'authorityFingerprint','witnessFingerprint','journalFingerprint'])&&
    policy.protocol===POLICY&&policy.audience===AUDIENCE&&
    typeof policy.logId==='string'&&TOKEN.test(policy.logId)&&
    policy.epoch===1&&
    policy.authorityFingerprint===fingerprint(authorityPem)&&
    policy.witnessFingerprint===fingerprint(witnessPem)&&
    policy.journalFingerprint===fingerprint(journalPem),
    'Pinned off-host policy/identity/epoch was substituted');
}
function signedReceipt(doc,pem,policy) {
  check(exact(doc,['data','signature'])&&
    exact(doc.data,['protocol','audience','logId','epoch','revision',
      'head','previousReceiptDigest','witnessFingerprint',
      'journalFingerprint','journalReceiptDigest','challengeNonce'])&&
    doc.data.protocol===RECEIPT&&doc.data.audience===AUDIENCE&&
    doc.data.logId===policy.logId&&doc.data.epoch===policy.epoch&&
    Number.isSafeInteger(doc.data.revision)&&doc.data.revision>0&&
    validHead(doc.data.head)&&
    doc.data.revision===doc.data.head.sequence&&
    doc.data.witnessFingerprint===policy.witnessFingerprint&&
    doc.data.journalFingerprint===policy.journalFingerprint&&
    typeof doc.data.journalReceiptDigest==='string'&&
    HEX.test(doc.data.journalReceiptDigest)&&
    typeof doc.data.challengeNonce==='string'&&
    TOKEN.test(doc.data.challengeNonce)&&
    (doc.data.previousReceiptDigest===null||
      (typeof doc.data.previousReceiptDigest==='string'&&
        HEX.test(doc.data.previousReceiptDigest)))&&
    typeof doc.signature==='string'&&SIG.test(doc.signature),
    'External receipt shape, domain, revisions or identity mismatch');
  const signature=Buffer.from(doc.signature,'base64url');
  check(signature.length===64&&
    edVerify(null,Buffer.from(RECEIPT+'\n'+
      JSON.stringify(doc.data)),pem,signature),
    'External signed high-water receipt rejected');
  return doc.data;
}
function journalHead(doc,journalPem,witnessPem) {
  check(exact(doc,['data','signature'])&&
    exact(doc.data,['protocol','witnessFingerprint','head'])&&
    doc.data.protocol===JOURNAL&&
    doc.data.witnessFingerprint===fingerprint(witnessPem)&&
    validHead(doc.data.head)&&
    typeof doc.signature==='string'&&SIG.test(doc.signature),
    'Local journal identity/head malformed');
  const sig=Buffer.from(doc.signature,'base64url');
  check(sig.length===64&&edVerify(null,Buffer.from(JOURNAL+'\n'+
    JSON.stringify(doc.data)),journalPem,sig),
    'Signed local journal receipt not trusted');
  return doc.data.head;
}
function inspect(policy,challenge,bundle,retained,keys) {
  const {authority,witness,journal}=keys;
  pinnedPolicy(policy,authority,witness,journal);
  check(exact(challenge,['protocol','logId','nonce'])&&
    challenge.protocol===CHALLENGE&&challenge.logId===policy.logId&&
    typeof challenge.nonce==='string'&&TOKEN.test(challenge.nonce),
    'Caller-issued fresh challenge required');
  check(exact(bundle,['protocol','external','local'])&&
    bundle.protocol===INPUT&&
    exact(bundle.external,['receipt','envelope','journalReceipt',
      'previousReceipt','previousEnvelope'])&&
    exact(bundle.local,['envelope','journalReceipt']),
    'Malformed externally supplied proof bundle');
  const ext=bundle.external,loc=bundle.local;
  const latest=signedReceipt(ext.receipt,authority,policy);
  const minimum=signedReceipt(retained,authority,policy);
  check(latest.challengeNonce===challenge.nonce,
    'Old receipt cannot answer a new caller challenge');
  if(latest.revision===1) {
    check(ext.previousReceipt===null&&
      ext.previousEnvelope===null&&
      latest.previousReceiptDigest===null,
      'Signed genesis must not have a missing/hidden predecessor');
  }else{
    check(ext.previousReceipt!==null&&ext.previousEnvelope!==null,
      'External monotonic sequence must provide direct predecessor');
    const previous=signedReceipt(ext.previousReceipt,authority,policy);
    check(previous.revision===latest.revision-1&&
      latest.previousReceiptDigest===sha(JSON.stringify(ext.previousReceipt))&&
      previous.head.digest===ext.envelope.payload.previous,
      'External receipt chain fork, gap or predecessor digest mismatch');
    const priorPayload=verifyEnvelope(ext.previousEnvelope,witness);
    check(same(headOf(ext.previousEnvelope),previous.head)&&
      priorPayload.sequence===previous.revision,
      'External historic witness evidence does not bind previous receipt');
  }
  // A saved prior signed anchor is the *minimum* head under this caller's
  // custody. Its authenticity is necessary but NOT sufficient to prove it
  // was held independently from the local runner.
  check(latest.revision>=minimum.revision&&
    latest.revision<=minimum.revision+1,
    'Rollback or skipped independently pinned external high-water');
  if(latest.revision===minimum.revision)
    check(same(ext.receipt,retained),
      'Signed external fork at identical preserved revision');
  else
    check(same(ext.previousReceipt,retained),
      'External successor must extend exact preserved prior receipt');
  const ep=verifyEnvelope(ext.envelope,witness);
  check(same(headOf(ext.envelope),latest.head),
    'External signed head lacks witness evidence');
  verifyCheckpoint(ext.envelope,witness,latest.head,ep.projection,
    ext.previousEnvelope);
  if(ext.previousEnvelope!==null) {
    const before=verifyEnvelope(ext.previousEnvelope,witness).projection;
    const after=ep.projection;
    let added=0;
    for(const name of ['issued','producer']) {
      const present=new Set(after[name]);
      check(before[name].every(x=>present.has(x)),
        'Off-host successor lost historical UUID commitments');
      added+=after[name].length-before[name].length;
    }
    check(added===1,
      'Off-host successor must bind exactly one new UUID commitment');
  }
  const externalJournal=journalHead(ext.journalReceipt,journal,witness);
  check(same(externalJournal,latest.head)&&
    latest.journalReceiptDigest===sha(JSON.stringify(ext.journalReceipt)),
    'Signed off-host receipt not bound to real witness/journal pair');
  const lp=verifyEnvelope(loc.envelope,witness);
  const localWitness=headOf(loc.envelope);
  const localJournal=journalHead(loc.journalReceipt,journal,witness);
  // No local publication or source can be called safe. Classify only.
  let status='SIGNED_EXTERNAL_CONTRACT_MATCH_REVIEW_ONLY';
  if(!same(localWitness,localJournal))
    status='LOCAL_SIGNED_SPLIT_MANUAL_REVIEW';
  else if(localWitness.sequence<latest.head.sequence)
    status='LOCALS_BEHIND_PRESERVED_EXTERNAL_HEAD_REVIEW';
  else if(localWitness.sequence>latest.head.sequence)
    status='EXTERNAL_HIGHWATER_LAG_REVIEW';
  else if(localWitness.digest!==latest.head.digest)
    status='SIGNED_FORK_CONFLICT_MANUAL_REVIEW';
  check(lp.sequence===localWitness.sequence,
    'Local witness payload inconsistent');
  return {
    protocol:'saas-synthetic-offhost-conformance-result-v1',status,
    manualReviewRequired:true,
    signedWireContractVerified:true,
    actualOffHostCustodyVerified:false,
    independentDurabilityVerified:false,
    authenticSourceCommitVerified:false,
    automaticRecoveryPermitted:false,
    authorizationGranted:false,reissuePermitted:false,
    retryPermitted:false,deliveryPermitted:false,
    repairPermitted:false,gcPermitted:false,
  };
}
try{
  offlineOnly();
  const [mode,...args]=process.argv.slice(2);
  check(mode==='inspect'&&args.length===9&&args[8]==='--no-gc',
    'inspect: authorityPub witnessPub journalPub policy challenge evidenceBundle retainedPin --strict-review --no-gc');
  check(args[7]==='--strict-review',
    'Strict manual-review-only marker required');
  const [authorityPub,witnessPub,journalPub,policyPath,
    challengePath,bundlePath,retainedPath]=args;
  const result=inspect(readJson(policyPath),readJson(challengePath),
    readJson(bundlePath),readJson(retainedPath),{
      authority:readPublic(authorityPub),
      witness:readPublic(witnessPub),
      journal:readPublic(journalPub),
    });
  check(result.actualOffHostCustodyVerified===false&&
    result.independentDurabilityVerified===false&&
    result.automaticRecoveryPermitted===false&&
    result.reissuePermitted===false&&result.gcPermitted===false,
    'Conformance cannot authorize real off-host/producer/GC');
  process.stdout.write(JSON.stringify(result)+'\n');
}catch(error){
  process.stderr.write('OFFHOST CONTRACT DENIED: '+
    (error?.message||String(error))+'\n');
  process.exitCode=1;
}
