#!/usr/bin/env node
// Stage 2G.4d.7m: offline settlement gate for a synthetic producer
// UNKNOWN-COMMIT outcome. This is NOT a network-facing producer API.
// The attestor never has PG credentials, never issues UUIDs, and cannot
// authorize GC, event delivery, replay, archival or a retry after UNKNOWN.
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  canonicalProjection, verifyEnvelope, envelopeDigest,
} from './archive-witness-protocol.mjs';

const gate=fileURLToPath(new URL('./archive-witness-highwater-gate.mjs',import.meta.url));
const TYPE='saas-synthetic-uuid-unknown-commit-v1';
const HEX=/^[0-9a-f]{64}$/;
const check=(ok,message)=>{if(!ok)throw Error(message);};
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&
  Object.keys(v).sort().join(',')===keys.slice().sort().join(',');
const hash=value=>createHash('sha256').update(value).digest('hex');
function load(path) {
  const raw=readFileSync(path,'utf8');
  check(raw.length>0&&raw.length<3000000,'Missing or oversized settlement evidence');
  return JSON.parse(raw);
}
function inspectDelta(earlier,later,kind,digest) {
  const old=canonicalProjection(earlier);
  const now=canonicalProjection(later);
  const other=kind==='issued'?'producer':'issued';
  check(equal(old[other],now[other]),'Other UUID registry unexpectedly changed');
  const known=new Set(old[kind]);
  const newly=now[kind].filter(x=>!known.has(x));
  check(old[kind].every(x=>now[kind].includes(x)),'Historical UUID missing');
  check(!known.has(digest),'Attempted UUID previously present in baseline');
  check(newly.length===1&&newly[0]===digest,
    'Unknown COMMIT: expected single new UUID not observed');
  check(now[kind].length===old[kind].length+1,
    'Noncanonical post-COMMIT cardinality');
  return {before:old,after:now};
}
function offlineOnly() {
  check(process.env.GITHUB_ACTIONS==='true' &&
    process.env.SAAS_EPHEMERAL_WITNESS_OFFLINE==='true' &&
    !process.env.PGHOST&&!process.env.PGPORT&&!process.env.PGUSER&&
    !process.env.PGPASSWORD&&!process.env.PGDATABASE&&
    !process.env.RAILWAY_ENVIRONMENT&&!process.env.RAILWAY_PROJECT_ID,
    'No PostgreSQL or production credentials permitted for settlement');
}
function verifyLatest(publicPath,historyA,anchorA,historyB,anchorB,journal,currentFile) {
  const args=[gate,'verify',publicPath,historyA,anchorA,
    historyB,anchorB,journal,currentFile];
  const result=spawnSync(process.execPath,args,{
    env:{
      GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
      PATH:process.env.PATH||'/usr/bin:/bin',LANG:'C',
    },
    encoding:'utf8',timeout:15000,maxBuffer:128000,
  });
  check(result.status===0,'Unsigned or divergent witness high-water (DENY)');
  const latest=load(anchorA);
  check(exact(latest,['sequence','digest']) &&
    Number.isSafeInteger(latest.sequence)&&latest.sequence>0&&
    typeof latest.digest==='string'&&HEX.test(latest.digest),
    'Untrusted witness head');
  const file=historyA+'/checkpoints/'+
    String(latest.sequence).padStart(8,'0')+'.json';
  const envelope=load(file);
  check(envelopeDigest(envelope)===latest.digest,
    'Final signed witness digest mismatch');
  return envelope;
}
function reconcile(candidate,baselineSigned,baselineObserved,
  currentObserved,finalEnvelope,publicPem) {
  check(exact(candidate,['protocol','kind','commitment','baselineHead']),
    'Invalid untrusted candidate shape');
  check(candidate.protocol===TYPE &&
    ['issued','producer'].includes(candidate.kind) &&
    typeof candidate.commitment==='string'&&HEX.test(candidate.commitment) &&
    exact(candidate.baselineHead,['sequence','digest']) &&
    Number.isSafeInteger(candidate.baselineHead.sequence) &&
    candidate.baselineHead.sequence>0 &&
    HEX.test(candidate.baselineHead.digest),
    'Invalid local prepared UUID commitment');
  const baseline=verifyEnvelope(baselineSigned,publicPem);
  check(candidate.baselineHead.sequence===baseline.sequence &&
    candidate.baselineHead.digest===envelopeDigest(baselineSigned),
    'Untrusted baseline checkpoint or mismatched prepare');
  const delta=inspectDelta(baselineObserved,currentObserved,
    candidate.kind,candidate.commitment);
  check(equal(delta.before,baseline.projection),
    'Prepared baseline did not match signed authenticated history');
  const final=verifyEnvelope(finalEnvelope,publicPem);
  check(final.sequence===baseline.sequence+1 &&
    final.previous===envelopeDigest(baselineSigned),
    'Unknown COMMIT cannot settle against missing/forked successor');
  check(equal(final.projection,delta.after),
    'Post-COMMIT UUID set is not the signed successor');
  return {status:'LOCALLY_OBSERVED_SIGNED_ONLY',gcPermitted:false};
}
try {
  offlineOnly();
  const args=process.argv.slice(2);
  check(args.length===11,
    'Usage: public historyA anchorA historyB anchorB journal baselineSigned baselineProjection currentProjection candidate unused');
  const [publicPath,historyA,anchorA,historyB,anchorB,journal,
    baselineSignedPath,baselinePath,currentPath,candidatePath] = args;
  // No extra positional arguments and no silent caller-controlled bypass.
  check(args[10]==='--no-gc','Fixed proof-only no-GC marker required');
  const publicPem=readFileSync(publicPath,'utf8');
  check(publicPem.length<16000,'Invalid offline verifier key length');
  const baselineSigned=load(baselineSignedPath);
  const baseline=load(baselinePath);
  const current=load(currentPath);
  const candidate=load(candidatePath);
  // Before trusting a signed successor, verify both distinct witness
  // processes and the third high-water journal against this CURRENT
  // PG projection. If witness publication is pending, FAIL CLOSED.
  const latest=verifyLatest(publicPath,historyA,anchorA,historyB,
    anchorB,journal,currentPath);
  const decision=reconcile(candidate,baselineSigned,baseline,
    current,latest,publicPem);
  check(decision.gcPermitted===false,'GC must always stay prohibited');
  process.stdout.write('PASS: local UNKNOWN-COMMIT identity reconciled after sealed witness successor; no ACK, no GC\n');
}catch(error) {
  process.stderr.write('SETTLEMENT DENIED: '+(error?.message||String(error))+'\n');
  process.exitCode=1;
}
