#!/usr/bin/env node
// 7u simulated operator onboarding + disaster recovery; SAME CI runner.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync,chmodSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {generateKeyPairSync,createHash,sign as edSign,randomBytes,
  createPublicKey} from 'node:crypto';
import {projectionFromSql,verifyEnvelope,envelopeDigest}
  from './archive-witness-protocol.mjs';

const AUD='disposable-ci-operator-dr-only';
const P='saas-synthetic-operator-policy-v1';
const Q='saas-synthetic-dr-review-request-v1';
const A='saas-synthetic-dr-review-approval-v1';
const EXT='saas-synthetic-offhost-highwater-receipt-v1';
const EXAUD='disposable-ci-offhost-conformance-only';
const J='saas-synthetic-ipc-highwater-receipt-v1';
const W='saas-synthetic-uuid-witness-v1';
const B='saas-synthetic-offhost-inspection-bundle-v1';
const db='saas_ephemeral_test';
if(!(process.env.GITHUB_ACTIONS==='true'&&
  process.env.SAAS_EPHEMERAL_OPERATOR_DR_TEST_CI==='true'&&
  process.env.PGHOST==='127.0.0.1'&&process.env.PGPORT==='5432'&&
  process.env.PGUSER==='postgres'&&process.env.PGDATABASE===db&&
  !process.env.RAILWAY_PROJECT_ID&&!process.env.RAILWAY_ENVIRONMENT&&
  !process.env.SAAS_PRODUCTION_DATABASE_URL))
  throw Error('7u requires disposable PG16 GitHub CI');
const work=mkdtempSync(join(tmpdir(),'saas-ipc-witness-7u-'));
chmodSync(work,0o700);
const tool=fileURLToPath(new URL('./archive-witness-operator-dr-contract.mjs',import.meta.url));
const env={GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
  SAAS_EPHEMERAL_OPERATOR_DR_CI:'true',
  HOME:work,LANG:'C',PATH:process.env.PATH||'/usr/bin:/bin'};
const sha=x=>createHash('sha256').update(x).digest('hex');
const nonce=()=>randomBytes(16).toString('hex');
const fp=pem=>sha(createPublicKey(pem).export({type:'spki',format:'der'}));
const pair={},pem={};
for(const role of ['governance','security','operations','authority','witness','journal']) {
  pair[role]=generateKeyPairSync('ed25519');
  pem[role]=pair[role].publicKey.export({type:'spki',format:'pem'});
}
let fileIndex=0;
function save(name,text) {
  const file=join(work,String(++fileIndex).padStart(4,'0')+'-'+name);
  writeFileSync(file,text,{flag:'wx',mode:0o600});
  return file;
}
function sign(data,domain,role) {
  return {data,signature:edSign(null,Buffer.from(domain+'\n'+
    JSON.stringify(data)),pair[role].privateKey).toString('base64url')};
}
function witness(projection,previous=null) {
  const payload={
    protocol:W,audience:'ephemeral-pg16-proof-only',
    sequence:(previous?.payload.sequence??0)+1,
    previous:previous?envelopeDigest(previous):null,
    projectionRoot:sha(JSON.stringify(projection)),projection,
  };
  const answer={
    payload,algorithm:'Ed25519',keyFingerprint:fp(pem.witness),
    signature:edSign(null,Buffer.from(W+'\n'+JSON.stringify(payload)),
      pair.witness.privateKey).toString('base64url'),
  };
  assert.deepEqual(verifyEnvelope(answer,pem.witness),payload);
  return answer;
}
function journal(env) {
  return sign({protocol:J,witnessFingerprint:fp(pem.witness),
    head:{sequence:env.payload.sequence,digest:envelopeDigest(env)}},
    J,'journal');
}
const logId=nonce();
const policy=sign({
  protocol:P,audience:AUD,logId,epoch:1,
  governanceFingerprint:fp(pem.governance),
  authorityFingerprint:fp(pem.authority),
  witnessFingerprint:fp(pem.witness),
  journalFingerprint:fp(pem.journal),
  operatorFingerprints:{
    security:fp(pem.security),operations:fp(pem.operations),
  },minimumQuorum:2,
},P,'governance');
function external(env,j,prior=null) {
  const head={sequence:env.payload.sequence,digest:envelopeDigest(env)};
  return sign({
    protocol:EXT,audience:EXAUD,logId,epoch:1,
    revision:head.sequence,head,
    previousReceiptDigest:prior?sha(JSON.stringify(prior)):null,
    witnessFingerprint:fp(pem.witness),
    journalFingerprint:fp(pem.journal),
    journalReceiptDigest:sha(JSON.stringify(j)),
    challengeNonce:nonce(),
  },EXT,'authority');
}
function bundle(receipt,envelope,journalReceipt,priorReceipt=null,
  priorEnvelope=null,localEnvelope=envelope,localJournal=journalReceipt) {
  return {protocol:B,external:{receipt,envelope,journalReceipt,
    previousReceipt:priorReceipt,previousEnvelope:priorEnvelope},
    local:{envelope:localEnvelope,journalReceipt:localJournal}};
}
function docs(evidence,retained) {
  const request={protocol:Q,audience:AUD,logId,epoch:1,nonce:nonce(),
    action:'MANUAL_EVIDENCE_INSPECTION_ONLY',
    retainedDigest:sha(JSON.stringify(retained)),
    evidenceDigest:sha(JSON.stringify(evidence))};
  const approvals={};
  for(const role of ['security','operations'])
    approvals[role]=sign({protocol:A,audience:AUD,role,logId,epoch:1,
      nonce:request.nonce,policyDigest:sha(JSON.stringify(policy)),
      requestDigest:sha(JSON.stringify(request))},A,role);
  return {policy,request,approvals,evidence,retained};
}
function inspect(input,{deny=false,swap={},overrideEnv=env,mode='inspect'}={}) {
  const args=[];
  for(const role of ['governance','security','operations',
    'authority','witness','journal'])
    args.push(save(role+'.pem',swap[role]??pem[role]));
  for(const field of ['policy','request','approvals','evidence','retained'])
    args.push(save(field+'.json',JSON.stringify(input[field])+'\n'));
  const result=spawnSync(process.execPath,
    [tool,mode,...args,'--strict-review','--no-gc'],
    {cwd:work,env:overrideEnv,encoding:'utf8',timeout:8000,maxBuffer:200000});
  if(deny) {
    assert.notEqual(result.status,0,'Expected DR evidence DENY');
    assert.match(result.stderr||'',/OPERATOR DR DENIED:/);
    return null;
  }
  assert.equal(result.status,0,result.stderr);
  const value=JSON.parse(result.stdout.trim());
  assert.equal(value.protocol,'saas-synthetic-dr-operator-conformance-result-v1');
  assert.equal(value.manualReviewRequired,true);
  assert.equal(value.cryptographicQuorumShapeVerified,true);
  for(const field of ['authenticHumanIdentityVerified',
    'independentOperatorCustodyVerified','independentlyHeldMinimumVerified',
    'realDisasterRecoveryTested','disasterRecoveryComplete',
    'authorityToResume','authorizationGranted','reissuePermitted',
    'retryPermitted','repairPermitted','deliveryPermitted','gcPermitted'])
    assert.equal(value[field],false,
      'Synthetic reviewer illegally authorized '+field);
  assert.ok(!JSON.stringify(value).includes('aaaaaaaa-aaaa'));
  return value.status;
}
try {
  const u1='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa8401';
  const u2='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa8402';
  const u3='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa8403';
  const w1=witness(projectionFromSql('issued|'+u1));
  const j1=journal(w1),e1=external(w1,j1);
  const w2=witness(projectionFromSql('issued|'+u1+'\nissued|'+u2),w1);
  const j2=journal(w2),e2=external(w2,j2,e1);
  const b1=bundle(e1,w1,j1);
  const b2=bundle(e2,w2,j2,e1,w1);
  const d1=docs(b1,e1),d2=docs(b2,e1);
  assert.equal(inspect(d1),'MATCHED_EVIDENCE_QUARANTINE_REVIEW');
  assert.equal(inspect(d2),'MATCHED_EVIDENCE_QUARANTINE_REVIEW');
  assert.equal(inspect(docs(bundle(e2,w2,j2,e1,w1,w1,j1),e2)),
    'LOCAL_ROLLBACK_QUARANTINE_REVIEW');
  assert.equal(inspect(docs(bundle(e1,w1,j1,null,null,w2,j2),e1)),
    'EXTERNAL_LAG_QUARANTINE_REVIEW');
  assert.equal(inspect(docs(bundle(e2,w2,j2,e1,w1,w2,j1),e2)),
    'SPLIT_LOCAL_EVIDENCE_QUARANTINE_REVIEW');
  const fork=witness(projectionFromSql('issued|'+u1+'\nissued|'+u3),w1);
  assert.equal(inspect(docs(bundle(e2,w2,j2,e1,w1,fork,journal(fork)),e2)),
    'SIGNED_FORK_QUARANTINE_REVIEW');
  console.info('PASS 7u: signed governance bootstrap + distinct security and operations approvals; matching, rollback, lag, split, fork are quarantine-only');
  inspect(docs(b1,e2),{deny:true});
  const equiv=bundle(external(w2,j2,e1),w2,j2,e1,w1);
  inspect(docs(equiv,e2),{deny:true});
  const missing=structuredClone(b2);
  missing.external.previousReceipt=null;
  inspect(docs(missing,e1),{deny:true});
  const forgedJournal=structuredClone(b2);
  forgedJournal.external.journalReceipt.data.head.digest='f'.repeat(64);
  inspect(docs(forgedJournal,e1),{deny:true});
  const forgedProjection=structuredClone(b2);
  forgedProjection.external.envelope.payload.projection.issuedCount++;
  inspect(docs(forgedProjection,e1),{deny:true});
  console.info('PASS 7u: stale minimum, authority equivocation, missing predecessor, forged journal and witness projection denied');
  for(const role of ['security','operations']) {
    const omitted=structuredClone(d2);
    delete omitted.approvals[role];
    inspect(omitted,{deny:true});
    const swapped=structuredClone(d2);
    swapped.approvals[role]=d2.approvals[
      role==='security'?'operations':'security'];
    inspect(swapped,{deny:true});
  }
  const replay=structuredClone(d2);replay.request.nonce=nonce();
  inspect(replay,{deny:true});
  const changed=structuredClone(d2);
  changed.request.action='REISSUE_UUID';inspect(changed,{deny:true});
  const changedEvidence=structuredClone(d2);
  changedEvidence.evidence.local.envelope=w1;inspect(changedEvidence,{deny:true});
  const changedPin=structuredClone(d2);
  changedPin.retained=e2;inspect(changedPin,{deny:true});
  const epoch=structuredClone(d2);epoch.policy.data.epoch=2;
  inspect(epoch,{deny:true});
  const extra=structuredClone(d2);extra.request.gcPermitted=true;
  inspect(extra,{deny:true});
  const sameRole=structuredClone(d2);
  sameRole.policy=sign({...policy.data,operatorFingerprints:{
    security:fp(pem.security),operations:fp(pem.security),
  }},P,'governance');
  inspect(sameRole,{deny:true,swap:{operations:pem.security}});
  const wrong=generateKeyPairSync('ed25519').publicKey
    .export({type:'spki',format:'pem'});
  for(const role of ['governance','security','operations','authority'])
    inspect(d2,{deny:true,swap:{[role]:wrong}});
  inspect(d2,{deny:true,overrideEnv:{...env,PGHOST:'127.0.0.1'}});
  inspect(d2,{deny:true,overrideEnv:{...env,RAILWAY_PROJECT_ID:'test'}});
  inspect(d2,{deny:true,mode:'repair'});
  console.info('PASS 7u: missing/duplicate role, policy/nonce/dossier replay, forbidden commands, swapped keys and production credentials deny');
  // A stateless conformance verifier cannot prove single-use nonce,
  // independent operator identity or external retention.
  assert.equal(inspect(d2),'MATCHED_EVIDENCE_QUARANTINE_REVIEW');
  console.info('LIMITATION 7u: exact signed dossier replay passes without independent durable nonce ledger; all signers/roots share CI runner; no humans, remote WORM, mTLS or real DR');
} finally {
  rmSync(work,{recursive:true,force:true});
}
