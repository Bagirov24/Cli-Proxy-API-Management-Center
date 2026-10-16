#!/usr/bin/env node
// Stage 2G.4d.7o — ephemeral PG16 projection attestor.
// READ-ONLY limited PostgreSQL role signs its own REPEATABLE READ
// snapshot, not a caller-provided projection. No production/WORM/GC.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash,createPrivateKey,createPublicKey,sign as edSign,
  verify as edVerify} from 'node:crypto';
import {
  canonicalProjection,projectionFromSql,verifyEnvelope,verifyCheckpoint,
  envelopeDigest,
} from './archive-witness-protocol.mjs';

const PROTOCOL='saas-synthetic-pg-projection-attestation-v1';
const CHALLENGE='saas-synthetic-pg-projection-challenge-v1';
const AUDIENCE='ephemeral-pg16-proof-only';
const HEX=/^[0-9a-f]{64}$/;
const NONCE=/^[0-9a-f]{32}$/;
const SEP=PROTOCOL+'\n';
const check=(v,reason)=>{if(!v)throw new Error(reason);};
const exact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&
  Object.keys(v).sort().join(',')===keys.slice().sort().join(',');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const readJson=path=>{
  const raw=readFileSync(path,'utf8');
  check(raw.length>0&&raw.length<3_000_000,'Invalid attestation file size');
  return JSON.parse(raw);
};
const hash=s=>createHash('sha256').update(s).digest('hex');
const head=x=>({sequence:x.payload.sequence,digest:envelopeDigest(x)});
function headValid(v) {
  return v===null||(exact(v,['sequence','digest'])&&
    Number.isSafeInteger(v.sequence)&&v.sequence>0&&
    typeof v.digest==='string'&&HEX.test(v.digest));
}
function challengeValid(v) {
  check(exact(v,['protocol','nonce','expected'])&&
    v.protocol===CHALLENGE&&NONCE.test(v.nonce)&&
    headValid(v.expected),'Malformed pinned witness challenge');
}
function offlineGuard() {
  check(process.env.GITHUB_ACTIONS==='true'&&
    process.env.SAAS_EPHEMERAL_PROJECTOR_PROOF_CI==='true'&&
    !process.env.RAILWAY_ENVIRONMENT&&!process.env.RAILWAY_PROJECT_ID&&
    !process.env.SAAS_PRODUCTION_DATABASE_URL,
    'Refusing projector proof outside disposable GitHub Actions');
}
function signerGuard() {
  offlineGuard();
  check(process.env.PGHOST==='127.0.0.1'&&
    process.env.PGPORT==='5432'&&
    process.env.PGUSER==='saas_witness_projection_7o'&&
    process.env.PGDATABASE==='saas_ephemeral_test'&&
    typeof process.env.PGPASSWORD==='string'&&
    process.env.PGPASSWORD.length>=20,
    'Projector MUST use only least-privileged disposable PG16 role');
}
function projectReadOnlyTransaction() {
  // One repeatable-read transaction binds both registries and metadata.
  // The signer itself, not an untrusted caller, executes the query.
  const sql="BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;"+
    "SELECT 'meta'::text,current_database()::text,"+
      "txid_current_snapshot()::text;"+
    "SELECT kind,operation FROM ("+
      "SELECT 'issued'::text AS kind,operation_id::text AS operation "+
      "FROM saas_rls_private.synthetic_operation_issues UNION ALL "+
      "SELECT 'producer'::text AS kind,operation_id::text AS operation "+
      "FROM saas_rls_private.synthetic_producer_operations) AS identities "+
      "ORDER BY kind,operation; COMMIT;";
  const result=spawnSync('psql',['-X','-q','-A','-t','-F','|',
    '-v','ON_ERROR_STOP=1','--dbname','saas_ephemeral_test','--command',sql],{
    env:{...process.env,PGCONNECT_TIMEOUT:'5',PGOPTIONS:
      '-c statement_timeout=4000 -c default_transaction_read_only=on'},
    encoding:'utf8',timeout:13000,maxBuffer:2000000,
  });
  check(result.status===0,'READ ONLY projection denied or interrupted: '+
    (result.stderr||'').slice(0,120));
  const lines=result.stdout.trim().split('\n');
  check(lines.length>1&&lines[0].startsWith('meta|'),
    'Missing PostgreSQL signed snapshot metadata');
  const meta=lines.shift().split('|');
  check(meta.length===3&&meta[0]==='meta'&&
    meta[1]==='saas_ephemeral_test'&&
    /^[0-9:,]{3,256}$/.test(meta[2]),
    'Malformed database/transaction snapshot identity');
  return {
    database:meta[1],snapshot:meta[2],
    projection:projectionFromSql(lines.join('\n')),
  };
}
function attestationValid(record,publicPem,ch) {
  check(exact(record,['statement','signature'])&&
    typeof record.signature==='string'&&
    /^[A-Za-z0-9_-]{80,120}$/.test(record.signature),
    'Malformed projection attestation signature');
  const s=record.statement;
  check(exact(s,['protocol','audience','challenge','expected','source','projection'])&&
    s.protocol===PROTOCOL&&s.audience===AUDIENCE&&
    s.challenge===ch.nonce&&equal(s.expected,ch.expected)&&
    exact(s.source,['database','snapshot'])&&
    s.source.database==='saas_ephemeral_test'&&
    typeof s.source.snapshot==='string'&&
    /^[0-9:,]{3,256}$/.test(s.source.snapshot),
    'Wrong signed challenge, DB source or witness baseline');
  const projection=canonicalProjection(s.projection);
  check(equal(projection,s.projection),'Noncanonical projection structure');
  const bytes=Buffer.from(record.signature,'base64url');
  check(bytes.length===64&&edVerify(null,
    Buffer.from(SEP+JSON.stringify(s)),publicPem,bytes),
    'Projector signature invalid, wrong key or signed data changed');
  return s;
}
function writeExclusive(path,data) {
  writeFileSync(path,JSON.stringify(data)+'\n',{flag:'wx',mode:0o600});
}
function attest(args) {
  signerGuard();
  check(args.length===4,
    'attest needs privateKey publicKey challengeFile outputFile');
  const [privatePath,publicPath,challengePath,output]=args;
  const ch=readJson(challengePath);
  challengeValid(ch);
  const privatePem=readFileSync(privatePath,'utf8');
  const publicPem=readFileSync(publicPath,'utf8');
  check(privatePem.length<16000&&publicPem.length<16000&&
    createPublicKey(createPrivateKey(privatePem))
      .export({type:'spki',format:'pem'}).toString()===publicPem,
    'Projector signer key pair invalid');
  const {database,snapshot,projection}=projectReadOnlyTransaction();
  const statement={
    protocol:PROTOCOL,audience:AUDIENCE,challenge:ch.nonce,
    expected:ch.expected,source:{database,snapshot},projection,
  };
  const signature=edSign(null,Buffer.from(SEP+JSON.stringify(statement)),
    createPrivateKey(privatePem)).toString('base64url');
  const proof={statement,signature};
  attestationValid(proof,publicPem,ch);
  writeExclusive(output,proof);
  process.stdout.write('PASS: read-only PG16 role signed its own repeatable-read UUID snapshot\n');
}
function verify(args) {
  offlineGuard();
  check(!process.env.PGUSER&&!process.env.PGPASSWORD&&
    !process.env.PGDATABASE&&!process.env.PGHOST,
    'Offline verifier must not receive PostgreSQL credentials');
  check(args.length===7,
    'verify needs projectorPublic witnessPublic challenge proof signedCheckpoint priorOrDash pinnedHead');
  const [attestorPublic,witnessPublic,challengePath,proofPath,
    checkpointPath,priorPath,pinnedHeadPath]=args;
  const ch=readJson(challengePath);challengeValid(ch);
  const projectorPub=readFileSync(attestorPublic,'utf8');
  const witnessPub=readFileSync(witnessPublic,'utf8');
  const statement=attestationValid(readJson(proofPath),projectorPub,ch);
  const envelope=readJson(checkpointPath);
  const expectedHead=readJson(pinnedHeadPath);
  check(headValid(expectedHead)&&expectedHead!==null,
    'Missing trusted witness head');
  const previous=priorPath==='-'?null:readJson(priorPath);
  check(equal(ch.expected,previous?head(previous):null),
    'Wrong signed predecessor for challenge');
  verifyCheckpoint(envelope,witnessPub,expectedHead,
    statement.projection,previous);
  check(equal(head(envelope),expectedHead),
    'Witness head diverged from independently pinned digest');
  check(equal(statement.projection,envelope.payload.projection),
    'Witness signed an un-attested or stale PG16 projection');
  if(previous) {
    const prior=verifyEnvelope(previous,witnessPub).projection;
    let gained=0;
    for(const kind of ['issued','producer']) {
      check(prior[kind].every(x=>statement.projection[kind].includes(x)),
        'Projector lost a historic UUID commitment');
      gained+=statement.projection[kind].length-prior[kind].length;
    }
    check(gained===1,'Only one new committed UUID may enter successor');
  }
  process.stdout.write('PASS: challenge-bound signed read-only PG16 projection matches pinned Ed25519 witness; GC FALSE\n');
}
try {
  const [action,...args]=process.argv.slice(2);
  if(action==='attest')attest(args);
  else if(action==='verify')verify(args);
  else throw Error('Expected attest or verify');
}catch(error) {
  process.stderr.write('PROJECTOR DENIED: '+(error?.message||String(error))+'\n');
  process.exitCode=1;
}
