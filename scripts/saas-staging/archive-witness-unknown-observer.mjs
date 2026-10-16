#!/usr/bin/env node
// Stage 2G.4d.7r: offline, read-only UNKNOWN-outcome observation.
// Verifies a fresh source-attested snapshot against signed 7q witness
// and local high-water evidence. NEVER authorizes issue, retry, dispatch
// or GC, even when all three local proofs match.
// No DB credentials, network access, file writes or production trust.
import {readFileSync} from 'node:fs';
import {createHash,createPublicKey,verify as edVerify} from 'node:crypto';
import {
  canonicalProjection,verifyEnvelope,verifyCheckpoint,envelopeDigest,
} from './archive-witness-protocol.mjs';

const TYPE='saas-synthetic-unknown-outcome-observation-v1';
const CANDIDATE='saas-synthetic-uuid-unknown-commit-v1';
const PG_ATTEST='saas-synthetic-pg-projection-attestation-v1';
const PG_CHALLENGE='saas-synthetic-pg-projection-challenge-v1';
const JW='saas-synthetic-ipc-highwater-receipt-v1';
const AUDIENCE='ephemeral-pg16-proof-only';
const HEX=/^[0-9a-f]{64}$/;
const NONCE=/^[0-9a-f]{32}$/;
const check=(ok,why)=>{if(!ok)throw Error(why);};
const exact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&
  Object.keys(v).sort().join(',')===keys.slice().sort().join(',');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const hash=v=>createHash('sha256').update(v).digest('hex');
const fingerprint=pem=>hash(createPublicKey(pem)
  .export({type:'spki',format:'der'}));
const headOf=e=>({sequence:e.payload.sequence,digest:envelopeDigest(e)});
const headValid=h=>exact(h,['sequence','digest'])&&
  Number.isSafeInteger(h.sequence)&&h.sequence>0&&
  typeof h.digest==='string'&&HEX.test(h.digest);
function readJson(path) {
  const bytes=readFileSync(path,'utf8');
  check(bytes.length>0&&bytes.length<3000000,
    'Missing or oversized signed observation input');
  return JSON.parse(bytes);
}
function readPublic(path) {
  const pem=readFileSync(path,'utf8');
  check(pem.length>0&&pem.length<16000&&
    createPublicKey(pem).asymmetricKeyType==='ed25519',
    'Unpinned or invalid Ed25519 public root');
  return pem;
}
function offlineGuard() {
  check(process.env.GITHUB_ACTIONS==='true'&&
    process.env.SAAS_EPHEMERAL_WITNESS_OFFLINE==='true'&&
    process.env.SAAS_EPHEMERAL_UNKNOWN_OBSERVATION_CI==='true'&&
    !Object.keys(process.env).some(name=>
      name.startsWith('PG')||name.startsWith('RAILWAY')||
      name==='DATABASE_URL'||name==='SAAS_PRODUCTION_DATABASE_URL'),
    'Offline observation forbidden with PostgreSQL/production credentials');
}
function verifySource(proof,challenge,publicPem,pinnedHead) {
  check(exact(challenge,['protocol','nonce','expected'])&&
    challenge.protocol===PG_CHALLENGE&&
    typeof challenge.nonce==='string'&&NONCE.test(challenge.nonce)&&
    equal(challenge.expected,pinnedHead),
    'Challenge must match the independently pinned current head');
  check(exact(proof,['statement','signature'])&&
    typeof proof.signature==='string'&&
    /^[A-Za-z0-9_-]{80,120}$/.test(proof.signature),
    'Missing or malformed source-attestation signature');
  const data=proof.statement;
  check(exact(data,['protocol','audience','challenge','expected','source','projection'])&&
    data.protocol===PG_ATTEST&&data.audience===AUDIENCE&&
    data.challenge===challenge.nonce&&
    equal(data.expected,pinnedHead)&&
    exact(data.source,['database','snapshot'])&&
    data.source.database==='saas_ephemeral_test'&&
    typeof data.source.snapshot==='string'&&
    /^[0-9:,]{3,256}$/.test(data.source.snapshot),
    'Wrong nonce, source, expected head or PostgreSQL snapshot context');
  const projected=canonicalProjection(data.projection);
  check(equal(projected,data.projection),
    'Noncanonical or modified signed PostgreSQL commitments');
  const signature=Buffer.from(proof.signature,'base64url');
  check(signature.length===64&&edVerify(null,Buffer.from(PG_ATTEST+'\n'+
    JSON.stringify(data)),publicPem,signature),
    'Invalid PostgreSQL projector signature or pinned public key');
  return projected;
}
function verifyHighwater(receipt,journalPem,witnessPem,pinnedHead) {
  check(exact(receipt,['data','signature'])&&
    exact(receipt.data,['protocol','witnessFingerprint','head'])&&
    receipt.data.protocol===JW&&
    receipt.data.witnessFingerprint===fingerprint(witnessPem)&&
    equal(receipt.data.head,pinnedHead)&&
    typeof receipt.signature==='string'&&
    /^[A-Za-z0-9_-]{80,120}$/.test(receipt.signature),
    'Journal head, witness identity or receipt schema diverged');
  const sig=Buffer.from(receipt.signature,'base64url');
  check(sig.length===64&&edVerify(null,Buffer.from(JW+'\n'+
    JSON.stringify(receipt.data)),journalPem,sig),
    'High-water public root or signature invalid');
}
function delta(before,after,kind,candidate) {
  const older=canonicalProjection(before);
  const newer=canonicalProjection(after);
  const opposite=kind==='issued'?'producer':'issued';
  check(equal(older[opposite],newer[opposite]),
    'Unrelated immutable UUID registry changed while status UNKNOWN');
  const oldSet=new Set(older[kind]);
  check(older[kind].every(value=>newer[kind].includes(value)),
    'PG source snapshot lost signed historic UUID commitments');
  const added=newer[kind].filter(value=>!oldSet.has(value));
  check(added.length===1&&added[0]===candidate&&
    newer[kind].length===older[kind].length+1,
    'Multi-UUID or wrong-candidate source drift; DENY');
}
function observe(input) {
  const {
    projectorPem,witnessPem,journalPem,challenge,attestation,
    current,prior,journalReceipt,pinnedHead,candidate,
  }=input;
  check(headValid(pinnedHead),'Missing independently pinned latest witness head');
  const source=verifySource(attestation,challenge,projectorPem,pinnedHead);
  const currentPayload=verifyEnvelope(current,witnessPem);
  verifyCheckpoint(current,witnessPem,pinnedHead,source,prior);
  check(equal(headOf(current),pinnedHead),
    'External trusted head not anchored to witness signature');
  verifyHighwater(journalReceipt,journalPem,witnessPem,pinnedHead);
  check(exact(candidate,['protocol','kind','commitment','baselineHead'])&&
    candidate.protocol===CANDIDATE&&
    (candidate.kind==='issued'||candidate.kind==='producer')&&
    typeof candidate.commitment==='string'&&HEX.test(candidate.commitment)&&
    headValid(candidate.baselineHead),
    'Untrusted or malformed prepared candidate commitment');
  const currentProjection=currentPayload.projection;
  const hasInSource=source[candidate.kind].includes(candidate.commitment);
  const hasInWitness=currentProjection[candidate.kind]
    .includes(candidate.commitment);
  const result={
    protocol:TYPE,
    status:'NOT_OBSERVED_IN_ONE_SNAPSHOT_UNKNOWN',
    sourceSnapshotOnly:true,
    locallySignedOnly:true,
    authorizationGranted:false,
    reissuePermitted:false,
    retryPermitted:false,
    deliveryPermitted:false,
    gcPermitted:false,
  };
  // Candidate was prepared against the already pinned head. The only
  // admissible provisional change is exactly ONE candidate committed
  // in the fresh signed PG snapshot, but NOT YET in the witness head.
  if(equal(candidate.baselineHead,pinnedHead)) {
    check(!hasInWitness,
      'Candidate was already committed in its claimed prepared baseline');
    if(hasInSource) {
      delta(currentProjection,source,candidate.kind,candidate.commitment);
      result.status='PG_SNAPSHOT_ONLY_UNWITNESSED';
    } else {
      // No independent COMMIT certificate; a single snapshot cannot
      // prove absence across concurrent transactions or after failover.
      check(equal(source,currentProjection),
        'Unrelated COMMIT detected; prepared outcome UNKNOWN');
    }
    return result;
  }
  // To inspect a direct successor after a lost witness IPC ACK, require
  // BOTH signatures plus the caller's original exact predecessor head.
  check(prior!==null&&
    equal(candidate.baselineHead,headOf(prior))&&
    pinnedHead.sequence===candidate.baselineHead.sequence+1,
    'Prepared UUID predecessor is not this exact signed successor');
  const priorProjection=verifyEnvelope(prior,witnessPem).projection;
  check(!priorProjection[candidate.kind].includes(candidate.commitment),
    'Prepared UUID was already present in trusted predecessor');
  check(hasInSource&&hasInWitness&&equal(source,currentProjection),
    'Signed current witness and fresh signed source do not agree on UUID');
  delta(priorProjection,currentProjection,candidate.kind,candidate.commitment);
  result.status='DUAL_LOCAL_SIGNED_IDENTITY_OBSERVED';
  return result;
}
try {
  offlineGuard();
  const [mode,...args]=process.argv.slice(2);
  check(mode==='verify'&&args.length===11,
    'verify: projectorPub witnessPub journalPub challenge proof latest prevOrDash journalReceipt pinnedHead candidate --no-gc');
  check(args[10]==='--no-gc',
    'No archive/reissue/delivery/GC authorization may be requested');
  const [pgPub,witPub,hiPub,chFile,proofFile,headEnvFile,
    priorFile,journalFile,pinFile,candidateFile]=args;
  const result=observe({
    projectorPem:readPublic(pgPub),
    witnessPem:readPublic(witPub),
    journalPem:readPublic(hiPub),
    challenge:readJson(chFile),
    attestation:readJson(proofFile),
    current:readJson(headEnvFile),
    prior:priorFile==='-'?null:readJson(priorFile),
    journalReceipt:readJson(journalFile),
    pinnedHead:readJson(pinFile),
    candidate:readJson(candidateFile),
  });
  check(result.reissuePermitted===false&&result.retryPermitted===false&&
    result.deliveryPermitted===false&&result.gcPermitted===false&&
    result.authorizationGranted===false,
    'No positive producer/GC authority from local observation');
  process.stdout.write(JSON.stringify(result)+'\n');
}catch(err) {
  process.stderr.write('RECONCILIATION DENIED: '+
    (err?.message||String(err))+'\n');
  process.exitCode=1;
}
