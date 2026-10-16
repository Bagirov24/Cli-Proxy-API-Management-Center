#!/usr/bin/env node
// 2G.4d.7u: synthetic dual-role operator onboarding and DR inspection.
// Offline/read-only. All keys and retained receipts are on ONE CI runner.
// No operator identity, independent WORM, recovery approval or production.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {createPublicKey,createHash,verify as edVerify} from 'node:crypto';
import {
  verifyEnvelope,verifyCheckpoint,envelopeDigest,
} from './archive-witness-protocol.mjs';

const AUD='disposable-ci-operator-dr-only';
const POLICY='saas-synthetic-operator-policy-v1';
const REQUEST='saas-synthetic-dr-review-request-v1';
const APPROVAL='saas-synthetic-dr-review-approval-v1';
const EXTERNAL='saas-synthetic-offhost-highwater-receipt-v1';
const EX_AUD='disposable-ci-offhost-conformance-only';
const JOURNAL='saas-synthetic-ipc-highwater-receipt-v1';
const BUNDLE='saas-synthetic-offhost-inspection-bundle-v1';
const HEX=/^[0-9a-f]{64}$/;
const NONCE=/^[0-9a-f]{32}$/;
const SIGNATURE=/^[A-Za-z0-9_-]{80,120}$/;
const check=(x,why)=>{if(!x)throw Error(why);};
const exact=(x,keys)=>x!==null&&typeof x==='object'&&
  !Array.isArray(x)&&
  Object.keys(x).sort().join(',')===keys.slice().sort().join(',');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const hash=x=>createHash('sha256').update(x).digest('hex');
const fingerprint=pem=>hash(createPublicKey(pem)
  .export({type:'spki',format:'der'}));
const headOf=env=>({sequence:env.payload.sequence,digest:envelopeDigest(env)});
const validHead=x=>exact(x,['sequence','digest'])&&
  Number.isSafeInteger(x.sequence)&&x.sequence>0&&
  typeof x.digest==='string'&&HEX.test(x.digest);
function readLimited(path) {
  const full=resolve(path);
  const prefix=resolve(tmpdir(),'saas-ipc-witness-');
  check(full.startsWith(prefix),
    'Operator proof path must be in disposable staging directory');
  const value=readFileSync(full,'utf8');
  check(value.length>0&&value.length<1500000,
    'Torn/oversized/manual review input');
  return value;
}
const readJson=path=>JSON.parse(readLimited(path));
function readPublic(path) {
  const pem=readLimited(path);
  check(pem.length<16000&&
    createPublicKey(pem).asymmetricKeyType==='ed25519',
    'Invalid pinned Ed25519 root');
  return pem;
}
function guard() {
  check(process.env.GITHUB_ACTIONS==='true'&&
    process.env.SAAS_EPHEMERAL_WITNESS_OFFLINE==='true'&&
    process.env.SAAS_EPHEMERAL_OPERATOR_DR_CI==='true'&&
    !Object.keys(process.env).some(k=>k.startsWith('PG')||
      k.startsWith('RAILWAY')||k==='DATABASE_URL'||
      k==='SAAS_PRODUCTION_DATABASE_URL'),
    'DR review cannot use database/production secrets or network mode');
}
function signature(doc,pem,protocol) {
  check(exact(doc,['data','signature'])&&
    typeof doc.signature==='string'&&
    SIGNATURE.test(doc.signature),'Malformed signed proof');
  const bytes=Buffer.from(doc.signature,'base64url');
  check(bytes.length===64&&edVerify(null,Buffer.from(
    protocol+'\n'+JSON.stringify(doc.data)),pem,bytes),
    'Detached signature wrong or untrusted signer');
  return doc.data;
}
function policyCheck(doc,keys) {
  const data=signature(doc,keys.governance,POLICY);
  check(exact(data,['protocol','audience','logId','epoch',
    'governanceFingerprint','authorityFingerprint',
    'witnessFingerprint','journalFingerprint','operatorFingerprints',
    'minimumQuorum'])&&
    data.protocol===POLICY&&data.audience===AUD&&
    typeof data.logId==='string'&&NONCE.test(data.logId)&&
    data.epoch===1&&data.minimumQuorum===2&&
    exact(data.operatorFingerprints,['security','operations'])&&
    data.governanceFingerprint===fingerprint(keys.governance)&&
    data.authorityFingerprint===fingerprint(keys.authority)&&
    data.witnessFingerprint===fingerprint(keys.witness)&&
    data.journalFingerprint===fingerprint(keys.journal)&&
    data.operatorFingerprints.security===fingerprint(keys.security)&&
    data.operatorFingerprints.operations===fingerprint(keys.operations)&&
    data.operatorFingerprints.security!==data.operatorFingerprints.operations&&
    data.operatorFingerprints.security!==data.governanceFingerprint&&
    data.operatorFingerprints.operations!==data.governanceFingerprint&&
    data.operatorFingerprints.security!==data.authorityFingerprint&&
    data.operatorFingerprints.operations!==data.authorityFingerprint,
    'Operator identity, dual role separation, root pin or policy epoch denied');
  return data;
}
function externalReceipt(doc,keys,policy) {
  const x=signature(doc,keys.authority,EXTERNAL);
  check(exact(x,['protocol','audience','logId','epoch','revision',
    'head','previousReceiptDigest','witnessFingerprint',
    'journalFingerprint','journalReceiptDigest','challengeNonce'])&&
    x.protocol===EXTERNAL&&x.audience===EX_AUD&&
    x.logId===policy.logId&&x.epoch===policy.epoch&&
    Number.isSafeInteger(x.revision)&&x.revision>0&&
    validHead(x.head)&&x.revision===x.head.sequence&&
    x.witnessFingerprint===policy.witnessFingerprint&&
    x.journalFingerprint===policy.journalFingerprint&&
    typeof x.journalReceiptDigest==='string'&&
    HEX.test(x.journalReceiptDigest)&&
    typeof x.challengeNonce==='string'&&NONCE.test(x.challengeNonce)&&
    (x.previousReceiptDigest===null||
      (typeof x.previousReceiptDigest==='string'&&
        HEX.test(x.previousReceiptDigest))),
    'External domain, log, key pin or signed head invalid');
  return x;
}
function journalReceipt(doc,keys) {
  const d=signature(doc,keys.journal,JOURNAL);
  check(exact(d,['protocol','witnessFingerprint','head'])&&
    d.protocol===JOURNAL&&
    d.witnessFingerprint===fingerprint(keys.witness)&&
    validHead(d.head),'Local journal signed head invalid');
  return d.head;
}
function evidenceCheck(evidence,retained,keys,policy) {
  check(exact(evidence,['protocol','external','local'])&&
    evidence.protocol===BUNDLE&&
    exact(evidence.external,['receipt','envelope','journalReceipt',
      'previousReceipt','previousEnvelope'])&&
    exact(evidence.local,['envelope','journalReceipt']),
    'Malformed or incomplete operator incident dossier');
  const e=evidence.external,l=evidence.local;
  const latest=externalReceipt(e.receipt,keys,policy);
  const preserved=externalReceipt(retained,keys,policy);
  check(latest.revision>=preserved.revision&&
    latest.revision<=preserved.revision+1,
    'Missing external revision or rollback below retained minimum');
  if(latest.revision===preserved.revision)
    check(same(e.receipt,retained),
      'External signer equivocation at preserved revision');
  else
    check(same(e.previousReceipt,retained),
      'Successor must extend exact independently retained receipt');
  if(latest.revision===1)
    check(e.previousReceipt===null&&e.previousEnvelope===null&&
      latest.previousReceiptDigest===null,
      'Genesis missing/extra predecessor');
  else {
    check(e.previousReceipt!==null&&e.previousEnvelope!==null,
      'Direct signed predecessor required');
    const prior=externalReceipt(e.previousReceipt,keys,policy);
    check(prior.revision+1===latest.revision&&
      latest.previousReceiptDigest===hash(JSON.stringify(e.previousReceipt))&&
      same(headOf(e.previousEnvelope),prior.head),
      'External receipt chain/fork/gap or predecessor substituted');
  }
  const current=verifyEnvelope(e.envelope,keys.witness);
  check(same(headOf(e.envelope),latest.head),
    'External receipt lacks exact signed witness head');
  verifyCheckpoint(e.envelope,keys.witness,latest.head,
    current.projection,e.previousEnvelope);
  if(e.previousEnvelope) {
    const before=verifyEnvelope(e.previousEnvelope,keys.witness).projection;
    let added=0;
    for(const field of ['issued','producer']) {
      const after=new Set(current.projection[field]);
      check(before[field].every(x=>after.has(x)),
        'Recovered witness chain lost historic UUIDs');
      added+=current.projection[field].length-before[field].length;
    }
    check(added===1,'External successor must add exactly one UUID commitment');
  }
  const exJournal=journalReceipt(e.journalReceipt,keys);
  check(same(exJournal,latest.head)&&
    latest.journalReceiptDigest===hash(JSON.stringify(e.journalReceipt)),
    'Signed external receipt not bound to journal proof');
  verifyEnvelope(l.envelope,keys.witness);
  const localWitness=headOf(l.envelope);
  const localJournal=journalReceipt(l.journalReceipt,keys);
  let status='MATCHED_EVIDENCE_QUARANTINE_REVIEW';
  if(!same(localWitness,localJournal))
    status='SPLIT_LOCAL_EVIDENCE_QUARANTINE_REVIEW';
  else if(localWitness.sequence<latest.revision)
    status='LOCAL_ROLLBACK_QUARANTINE_REVIEW';
  else if(localWitness.sequence>latest.revision)
    status='EXTERNAL_LAG_QUARANTINE_REVIEW';
  else if(localWitness.digest!==latest.head.digest)
    status='SIGNED_FORK_QUARANTINE_REVIEW';
  return status;
}
function review(request,approvals,policyDocument,evidence,retained,keys) {
  const policy=policyCheck(policyDocument,keys);
  check(exact(request,['protocol','audience','logId','epoch',
    'nonce','action','retainedDigest','evidenceDigest'])&&
    request.protocol===REQUEST&&request.audience===AUD&&
    request.logId===policy.logId&&request.epoch===policy.epoch&&
    typeof request.nonce==='string'&&NONCE.test(request.nonce)&&
    request.action==='MANUAL_EVIDENCE_INSPECTION_ONLY'&&
    typeof request.retainedDigest==='string'&&HEX.test(request.retainedDigest)&&
    typeof request.evidenceDigest==='string'&&HEX.test(request.evidenceDigest)&&
    request.retainedDigest===hash(JSON.stringify(retained))&&
    request.evidenceDigest===hash(JSON.stringify(evidence)),
    'Review request is not bound to exact retained minimum and dossier');
  check(exact(approvals,['security','operations']),
    'Both distinct operator roles must sign identical request');
  for(const role of ['security','operations']) {
    const approval=signature(approvals[role],keys[role],APPROVAL);
    check(exact(approval,['protocol','audience','role','logId','epoch',
      'nonce','policyDigest','requestDigest'])&&
      approval.protocol===APPROVAL&&approval.audience===AUD&&
      approval.role===role&&approval.logId===policy.logId&&
      approval.epoch===policy.epoch&&approval.nonce===request.nonce&&
      approval.policyDigest===hash(JSON.stringify(policyDocument))&&
      approval.requestDigest===hash(JSON.stringify(request)),
      'Missing, swapped, stale or modified operator approval');
  }
  const status=evidenceCheck(evidence,retained,keys,policy);
  return {
    protocol:'saas-synthetic-dr-operator-conformance-result-v1',
    status,manualReviewRequired:true,
    cryptographicQuorumShapeVerified:true,
    authenticHumanIdentityVerified:false,
    independentOperatorCustodyVerified:false,
    independentlyHeldMinimumVerified:false,
    realDisasterRecoveryTested:false,
    disasterRecoveryComplete:false,
    authorityToResume:false,
    authorizationGranted:false,reissuePermitted:false,
    retryPermitted:false,repairPermitted:false,
    deliveryPermitted:false,gcPermitted:false,
  };
}
try {
  guard();
  const [command,...args]=process.argv.slice(2);
  check(command==='inspect'&&args.length===13&&
    args[11]==='--strict-review'&&args[12]==='--no-gc',
    'inspect: governancePub securityPub operationsPub authorityPub witnessPub journalPub policy request approvals evidence retained --strict-review --no-gc');
  const [governancePath,securityPath,operationsPath,authorityPath,
    witnessPath,journalPath,policyPath,requestPath,approvalsPath,
    evidencePath,retainedPath]=args;
  const result=review(readJson(requestPath),readJson(approvalsPath),
    readJson(policyPath),readJson(evidencePath),readJson(retainedPath),{
      governance:readPublic(governancePath),
      security:readPublic(securityPath),
      operations:readPublic(operationsPath),
      authority:readPublic(authorityPath),
      witness:readPublic(witnessPath),
      journal:readPublic(journalPath),
    });
  check(result.authorityToResume===false&&
    result.disasterRecoveryComplete===false&&
    result.independentOperatorCustodyVerified===false&&
    result.reissuePermitted===false&&result.gcPermitted===false,
    'No actual operator/governance/recovery permission from CI proof');
  process.stdout.write(JSON.stringify(result)+'\n');
} catch(err) {
  process.stderr.write('OPERATOR DR DENIED: '+
    (err?.message||String(err))+'\n');
  process.exitCode=1;
}
