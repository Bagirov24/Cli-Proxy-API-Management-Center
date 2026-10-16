#!/usr/bin/env node
// Stage 2G.4d.7k: single-runner, disk-fsynced signed witness head.
// Proof-only, never archive, DELETE/TRUNCATE/GC/reuse any UUID.
// Offline CLI may NEVER receive PG credentials or Railway environment.
import {
  mkdirSync, readdirSync, existsSync, readFileSync, writeFileSync,
  openSync, closeSync, fsyncSync, renameSync, unlinkSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  verifyEnvelope, verifyCheckpoint, envelopeDigest, canonicalProjection,
} from './archive-witness-protocol.mjs';

const check = (x,msg) => { if(!x) throw new Error(msg); };
const jsonRead = (path) => {
  const content=readFileSync(path,'utf8');
  check(content.length>0 && content.length<=3_000_000,'Invalid offline witness file size');
  return JSON.parse(content);
};
const plain = (x,keys) => x!==null && typeof x==='object' &&
  !Array.isArray(x) && Object.keys(x).sort().join(',')===keys.slice().sort().join(',');
const headValid = x => plain(x,['sequence','digest']) &&
  Number.isSafeInteger(x.sequence) && x.sequence>0 &&
  typeof x.digest==='string' && /^[0-9a-f]{64}$/.test(x.digest);
const headOf = envelope => ({
  sequence:envelope.payload.sequence, digest:envelopeDigest(envelope),
});
const equal = (x,y) => JSON.stringify(x)===JSON.stringify(y);
function syncDirectory(path) {
  const fd=openSync(path,'r');
  try {fsyncSync(fd);} finally {closeSync(fd);}
}
function writeExclusive(path,data) {
  const fd=openSync(path,'wx',0o600);
  try {
    writeFileSync(fd,typeof data==='string'?data:JSON.stringify(data)+'\n');
    fsyncSync(fd);
  } finally {closeSync(fd);}
  syncDirectory(dirname(path));
}
function atomicJson(path,value) {
  const tmp=join(dirname(path),'.pending-'+randomUUID());
  writeExclusive(tmp,value);
  if(process.env.SAAS_WITNESS_TEST_KILL_BEFORE_HEAD_RENAME==='true' &&
     path.endsWith('/head.json')) {
    process.kill(process.pid,'SIGKILL');
  }
  renameSync(tmp,path);
  syncDirectory(dirname(path));
}
function requireOffline() {
  check(process.env.GITHUB_ACTIONS==='true' &&
    process.env.SAAS_EPHEMERAL_WITNESS_OFFLINE==='true' &&
    !process.env.PGHOST && !process.env.PGPORT &&
    !process.env.PGUSER && !process.env.PGPASSWORD &&
    !process.env.PGDATABASE && !process.env.RAILWAY_ENVIRONMENT &&
    !process.env.RAILWAY_PROJECT_ID,
    'Refusing witness head operation with PostgreSQL/production credentials');
}
function expectedPath(base,index) {
  return join(base,'checkpoints',String(index).padStart(8,'0')+'.json');
}
function readState(base,publicPem) {
  const files=readdirSync(base);
  check(files.length===2 && files.includes('head.json') &&
    files.includes('checkpoints'), 'Incomplete, pending or foreign witness state');
  const dir=join(base,'checkpoints');
  const names=readdirSync(dir).sort();
  check(names.length>0 && names.length<=128,'Invalid witness history length');
  const head=jsonRead(join(base,'head.json'));
  check(headValid(head),'Malformed persisted witness head');
  let previous=null;
  let last=null;
  for(let i=0;i<names.length;i++) {
    check(names[i]===String(i+1).padStart(8,'0')+'.json',
      'Witness history missing, reordered, pending or forked');
    const next=jsonRead(expectedPath(base,i+1));
    const canonical=verifyEnvelope(next,publicPem);
    check(canonical.sequence===i+1,'Unexpected checkpoint history sequence');
    verifyCheckpoint(next,publicPem,headOf(next),canonical.projection,previous);
    previous=next;
    last=next;
  }
  check(head.sequence===last.payload.sequence &&
    equal(head,headOf(last)), 'Persisted head does not match signed history');
  return {head,last,previous:names.length>1?
    jsonRead(expectedPath(base,names.length-1)):null};
}
function requirePinnedAnchor(anchorPath,stateHead) {
  const anchor=jsonRead(anchorPath);
  check(headValid(anchor) && equal(anchor,stateHead),
    'Externally pinned head missing, rolled back or diverged');
}
function trustedCurrent(base,publicPem,anchorPath,observed) {
  const state=readState(base,publicPem);
  requirePinnedAnchor(anchorPath,state.head);
  const status=verifyCheckpoint(state.last,publicPem,state.head,
    observed,state.previous);
  // Restoration gate must not silently accept an uncheckpointed extra UUID.
  // Even exact equality is NOT authorization for physical GC.
  check(equal(canonicalProjection(observed),
    canonicalProjection(state.last.payload.projection)),
    'Restored PostgreSQL projection has unsigned additional UUIDs');
  check(status.gcPermitted===false,'GC cannot be permitted');
  return status;
}
function assertNewEnvelope(candidate,publicPem,prior) {
  const payload=verifyEnvelope(candidate,publicPem);
  check(payload.sequence===(prior?.payload.sequence??0)+1,
    'Checkpoint not next sequence');
  verifyCheckpoint(candidate,publicPem,headOf(candidate),
    payload.projection,prior);
}
function releaseHeadCheckpoint(base,anchorPath,candidate,publicPem,isInit) {
  const old = isInit?null:readState(base,publicPem);
  if (old) requirePinnedAnchor(anchorPath,old.head);
  assertNewEnvelope(candidate,publicPem,old?.last??null);
  if (isInit) {
    check(!existsSync(base) && !existsSync(anchorPath),
      'Cannot overwrite existing witness trust root');
    mkdirSync(join(base,'checkpoints'),{recursive:true,mode:0o700});
  }
  const lock=join(base,'.writer-lock');
  // Fail closed if a crashed publisher left a lock. No automatic repair.
  writeExclusive(lock,String(process.pid)+'\n');
  try {
    writeExclusive(expectedPath(base,candidate.payload.sequence),candidate);
    atomicJson(join(base,'head.json'),headOf(candidate));
    // The anchor lives outside the witness history directory. The two
    // fsync+rename publications are NOT atomic with each other or PG COMMIT:
    // an interruption makes verification fail closed, needing adjudication.
    atomicJson(anchorPath,headOf(candidate));
  } finally {
    // Normal publish removes lock; SIGKILL intentionally leaves it.
    unlinkSync(lock);
    syncDirectory(base);
  }
}

function main() {
  requireOffline();
  const [action,...args]=process.argv.slice(2);
  if(action==='init'||action==='advance') {
    check(args.length===4,'init/advance: publicKey trustDir anchorFile signedCheckpoint');
    const [pubPath,trustDir,anchorPath,checkpointPath]=args;
    const pub=readFileSync(pubPath,'utf8');
    check(pub.length<16000,'Invalid public key size');
    releaseHeadCheckpoint(trustDir,anchorPath,jsonRead(checkpointPath),pub,
      action==='init');
    process.stdout.write('PASS: persisted offline head sequence with fsync; GC FORBIDDEN\n');
  } else if(action==='verify') {
    check(args.length===4,
      'verify: publicKey trustDir anchorFile observedProjection');
    const [pubPath,trustDir,anchorPath,observedPath]=args;
    const status=trustedCurrent(trustDir,readFileSync(pubPath,'utf8'),
      anchorPath,jsonRead(observedPath));
    process.stdout.write('PASS: offline restarted head '+status.sequence+
      ' covers exact restored PG16 UUID set; GC FORBIDDEN\n');
  } else {
    throw new Error('Unsupported proof-only head action');
  }
}
try{main();}catch(err){
  process.stderr.write('HEAD DENIED: '+(err?.message||String(err))+'\n');
  process.exitCode=1;
}
