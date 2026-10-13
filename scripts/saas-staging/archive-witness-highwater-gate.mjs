#!/usr/bin/env node
// Stage 2G.4d.7l: three compartment CI-only witness high-water gate.
// Two independently checked fsynced histories + a separately pinned,
// append-only-in-THIS-TEST high-water journal. NOT cross-host durability.
// NEVER authorize GC, DELETE, archive, UUID reuse or public delivery.
import {
  existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync,
  openSync, closeSync, fsyncSync, unlinkSync,
} from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { envelopeDigest } from './archive-witness-protocol.mjs';

const headCli=fileURLToPath(new URL('./archive-witness-head-store.mjs',import.meta.url));
const assert=(value,why)=>{if(!value)throw new Error(why);};
const HEX=/^[0-9a-f]{64}$/;
const fields=(v,names)=>v&&typeof v==='object'&&!Array.isArray(v)&&
  Object.keys(v).sort().join(',')===names.slice().sort().join(',');
function offlineOnly() {
  assert(process.env.GITHUB_ACTIONS==='true' &&
    process.env.SAAS_EPHEMERAL_WITNESS_OFFLINE==='true' &&
    !process.env.PGHOST&&!process.env.PGPORT&&!process.env.PGUSER&&
    !process.env.PGDATABASE&&!process.env.PGPASSWORD&&
    !process.env.RAILWAY_PROJECT_ID&&!process.env.RAILWAY_ENVIRONMENT,
    'Witness high-water gate must have no PostgreSQL/production credentials');
}
function json(path) {
  const raw=readFileSync(path,'utf8');
  assert(raw.length>0&&raw.length<3_000_000,'Invalid private witness JSON size');
  return JSON.parse(raw);
}
function headValid(v) {
  return fields(v,['sequence','digest'])&&Number.isSafeInteger(v.sequence)&&
    v.sequence>0&&typeof v.digest==='string'&&HEX.test(v.digest);
}
function identical(a,b) {return JSON.stringify(a)===JSON.stringify(b);}
function syncDir(dir) {
  const fd=openSync(dir,'r');
  try{fsyncSync(fd);}finally{closeSync(fd);}
}
function writeNew(path,content) {
  const fd=openSync(path,'wx',0o600);
  try{writeFileSync(fd,content);fsyncSync(fd);}finally{closeSync(fd);}
  syncDir(dirname(path));
}
function pathSafety(historyA,anchorA,historyB,anchorB,journalDir) {
  const paths=[historyA,anchorA,historyB,anchorB,journalDir].map(path=>resolve(path));
  assert(new Set(paths).size===5,'Witness trust compartments must be distinct');
  for(const path of paths.slice(0,4))
    assert(!(path===paths[4]||path.startsWith(paths[4]+'/')||
       paths[4].startsWith(path+'/')),
       'Cannot nest the journal inside a witness compartment');
}
function checkHistory(publicKey,history,anchor,observed) {
  const args=[headCli,'verify',publicKey,history,anchor,observed];
  const result=spawnSync(process.execPath,args,{
    env:{
      GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
      PATH:process.env.PATH||'/usr/bin:/bin',
      LANG:'C',
    },
    encoding:'utf8',timeout:15000,maxBuffer:128*1024,
  });
  assert(result.status===0,'Signed witness replica DENY: '+(result.stderr||''));
  const pinned=json(anchor);
  assert(headValid(pinned),'Malformed pinned witness replica head');
  const latest=json(join(history,'checkpoints',
    String(pinned.sequence).padStart(8,'0')+'.json'));
  assert(envelopeDigest(latest)===pinned.digest,
    'Witness head digest mismatch after signed verification');
  return {head:pinned,latest};
}
function checkTwins(publicKey,historyA,anchorA,historyB,anchorB,observed) {
  const a=checkHistory(publicKey,historyA,anchorA,observed);
  const b=checkHistory(publicKey,historyB,anchorB,observed);
  assert(identical(a.head,b.head),'Signed witness replicas are out of sync');
  assert(identical(a.latest,b.latest),'Signed witness forks with equal head');
  return a;
}
function readJournal(dir) {
  assert(readdirSync(dir).join(',')==='highwater.log',
    'Missing, tampered, locked or uncommitted high-water journal');
  const content=readFileSync(join(dir,'highwater.log'),'utf8');
  assert(content.length>0&&content.length<=20000&&content.endsWith('\n'),
    'Torn or oversized high-water journal');
  const rows=content.trimEnd().split('\n');
  assert(rows.length>0&&rows.length<=128,'Invalid high-water length');
  const parsed=[];
  for(let i=0;i<rows.length;i++) {
    const row=JSON.parse(rows[i]);
    assert(fields(row,['sequence','digest','previous']) &&
      Number.isSafeInteger(row.sequence)&&row.sequence===i+1 &&
      typeof row.digest==='string'&&HEX.test(row.digest)&&
      row.previous===(i===0?null:parsed[i-1].digest) &&
      rows[i]===JSON.stringify(row),
      'Forked, reordered, noncanonical or truncated high-water journal');
    parsed.push(row);
  }
  return parsed;
}
function writerLock(dir) {
  const path=join(dir,'.writer-lock');
  writeNew(path,String(process.pid)+'\n');
  return path;
}
function publishJournal(dir,record,first) {
  if(first) {
    assert(!existsSync(dir),'Cannot overwrite high-water trust root');
    mkdirSync(dir,{mode:0o700});
    syncDir(dirname(dir));
  }
  const lock=writerLock(dir);
  try {
    const name=join(dir,'highwater.log');
    if(first) writeNew(name,JSON.stringify(record)+'\n');
    else {
      const fd=openSync(name,'a',0o600);
      try {
        writeFileSync(fd,JSON.stringify(record)+'\n');
        fsyncSync(fd);
      }finally{closeSync(fd);}
      syncDir(dir);
    }
    // SIGKILL simulates a crash AFTER durable record append but BEFORE
    // releasing the pending writer marker. Reader MUST deny on restart.
    if(process.env.SAAS_WITNESS_TEST_KILL_JOURNAL_AFTER_FSYNC==='true')
      process.kill(process.pid,'SIGKILL');
  }finally {
    unlinkSync(lock);
    syncDir(dir);
  }
}
function verify(publicKey,historyA,anchorA,historyB,anchorB,journalDir,observed) {
  pathSafety(historyA,anchorA,historyB,anchorB,journalDir);
  // Read the journal FIRST: loss of independent high-water is always
  // denial, even when the two witness replicas and restored DB agree.
  const journal=readJournal(journalDir);
  const twin=checkTwins(publicKey,historyA,anchorA,historyB,anchorB,observed);
  const tip=journal.at(-1);
  assert(twin.head.sequence===tip.sequence && twin.head.digest===tip.digest,
    'Rollback of both signed replicas or journal/head divergence');
  return {sequence:tip.sequence,gcPermitted:false};
}
function advance(action,publicKey,historyA,anchorA,historyB,anchorB,journalDir,observed) {
  pathSafety(historyA,anchorA,historyB,anchorB,journalDir);
  let older=null;
  if(action==='append') older=readJournal(journalDir).at(-1);
  else assert(action==='init'&&!existsSync(journalDir),
    'Journal trust root already initialized');
  const twin=checkTwins(publicKey,historyA,anchorA,historyB,anchorB,observed);
  const current=twin.head;
  assert(current.sequence===(older?.sequence??0)+1,
    'Witness cannot skip or reuse a high-water sequence');
  assert(twin.latest.payload.previous===(older?.digest??null),
    'Witness predecessor conflicts with independently pinned high-water');
  publishJournal(journalDir,{
    sequence:current.sequence,digest:current.digest,
    previous:older?.digest??null,
  },action==='init');
  return {sequence:current.sequence,gcPermitted:false};
}
try {
  offlineOnly();
  const [command,...args]=process.argv.slice(2);
  assert(args.length===7 && ['init','append','verify'].includes(command),
    'Expected init|append|verify publicKey historyA anchorA historyB anchorB journalDir observedProjection');
  const [publicKey,historyA,anchorA,historyB,anchorB,journalDir,observed]=args;
  const status=command==='verify'
    ?verify(publicKey,historyA,anchorA,historyB,anchorB,journalDir,observed)
    :advance(command,publicKey,historyA,anchorA,historyB,anchorB,journalDir,observed);
  assert(status.gcPermitted===false,'GC is never permitted');
  process.stdout.write('PASS: local tri-compartment high-water '+
    status.sequence+' verified; GC FORBIDDEN\n');
}catch(error) {
  process.stderr.write('HIGH-WATER DENIED: '+(error?.message||String(error))+'\n');
  process.exitCode=1;
}
