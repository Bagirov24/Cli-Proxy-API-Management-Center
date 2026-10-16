#!/usr/bin/env node
// Stage 2G.4d.7o — limited-privilege PostgreSQL source attestation.
// Only disposable GitHub Actions; no outside witness/GC authorization.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {randomBytes,generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,chmodSync,readFileSync,writeFileSync,rmSync}
  from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {envelopeDigest,canonicalProjection}
  from './archive-witness-protocol.mjs';

const SOURCE='saas_ephemeral_test';
const ROLE='saas_witness_projection_7o';
const PROTOCOL='saas-synthetic-pg-projection-challenge-v1';
const ci=process.env.GITHUB_ACTIONS==='true'&&
  process.env.SAAS_EPHEMERAL_PROJECTOR_PROOF_CI==='true'&&
  process.env.PGHOST==='127.0.0.1'&&process.env.PGPORT==='5432'&&
  process.env.PGUSER==='postgres'&&process.env.PGDATABASE===SOURCE&&
  !process.env.RAILWAY_ENVIRONMENT&&!process.env.RAILWAY_PROJECT_ID&&
  !process.env.SAAS_PRODUCTION_DATABASE_URL;
if(!ci)throw Error('Refusing projector proof outside disposable PG16 CI');
const work=mkdtempSync(join(tmpdir(),'saas-projector-proof-'));
chmodSync(work,0o700);
const witness=fileURLToPath(new URL('./archive-witness-protocol.mjs',import.meta.url));
const projector=fileURLToPath(new URL('./archive-witness-pg-projection-proof.mjs',import.meta.url));
const adminEnv={...process.env,PGCONNECT_TIMEOUT:'5'};
const password=randomBytes(25).toString('hex');
const readonlyEnv={
  GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_PROJECTOR_PROOF_CI:'true',
  PGHOST:'127.0.0.1',PGPORT:'5432',PGUSER:ROLE,
  PGPASSWORD:password,PGDATABASE:SOURCE,
  PATH:process.env.PATH||'/usr/bin:/bin',LANG:'C',HOME:work,
};
const offlineEnv={
  GITHUB_ACTIONS:'true',SAAS_EPHEMERAL_PROJECTOR_PROOF_CI:'true',
  SAAS_EPHEMERAL_WITNESS_OFFLINE:'true',
  PATH:process.env.PATH||'/usr/bin:/bin',LANG:'C',HOME:work,
};
const attPriv=join(work,'pg-projector-private.pem');
const attPub=join(work,'pg-projector-public.pem');
const witPriv=join(work,'witness-private.pem');
const witPub=join(work,'witness-public.pem');
const cp1=join(work,'checkpoint-1.json'),cp2=join(work,'checkpoint-2.json');
const ISSUE='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa7c01';
let roleCreated=false;
function exec(cmd,args,env,{deny=false,prefix=''}={}) {
  const r=spawnSync(cmd,args,{env,cwd:work,encoding:'utf8',
    timeout:15000,maxBuffer:2000000});
  if(deny) {
    assert.notEqual(r.status,0,'Expected denied command: '+cmd);
    if(prefix)assert.match(r.stderr||'',new RegExp(prefix));
  } else assert.equal(r.status,0,'Unexpected command failure: '+
      (r.stderr||'').slice(0,600));
  return r.stdout.trim();
}
function admin(query) {
  return exec('psql',['-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
    '--dbname',SOURCE,'-c',query],adminEnv);
}
function restricted(query,deny=false) {
  return exec('psql',['-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
    '--dbname',SOURCE,'-c',query],readonlyEnv,{deny});
}
function runAttestor(action,args,deny=false,env=readonlyEnv) {
  return exec(process.execPath,[projector,action,...args],env,{
    deny,prefix:'PROJECTOR DENIED:'});
}
function runWitness(action,args) {
  return exec(process.execPath,[witness,action,...args],{
    ...offlineEnv,SAAS_EPHEMERAL_WITNESS_OFFLINE:'true'});
}
function save(name,value) {
  const file=join(work,name);
  writeFileSync(file,JSON.stringify(value)+'\n',{flag:'wx',mode:0o600});
  return file;
}
const read=file=>JSON.parse(readFileSync(file,'utf8'));
function head(file) {
  const doc=read(file);
  return {sequence:doc.payload.sequence,digest:envelopeDigest(doc)};
}
function challenge(name,expected) {
  return save(name,{protocol:PROTOCOL,
    nonce:randomBytes(16).toString('hex'),expected});
}
function generateProjectorKeypair() {
  const pair=generateKeyPairSync('ed25519');
  writeFileSync(attPriv,pair.privateKey.export({type:'pkcs8',format:'pem'}),
    {flag:'wx',mode:0o600});
  writeFileSync(attPub,pair.publicKey.export({type:'spki',format:'pem'}),
    {flag:'wx',mode:0o600});
}
function attest(challengePath,outputFile) {
  runAttestor('attest',[attPriv,attPub,challengePath,outputFile]);
  const signed=read(outputFile);
  assert.equal(signed.statement.source.database,SOURCE);
  assert.deepEqual(canonicalProjection(signed.statement.projection),
    signed.statement.projection);
  return signed;
}
function verify(challengePath,proofPath,checkpoint,prior,pin,{deny=false,projectorKey=attPub}={}) {
  return runAttestor('verify',[projectorKey,witPub,challengePath,proofPath,
    checkpoint,prior,pin],deny,offlineEnv);
}
function makeWitness(projectionFile,previous,output) {
  runWitness('sign',[witPriv,witPub,projectionFile,previous,output]);
}
try {
  assert.equal(admin('SELECT current_database()'),SOURCE);
  assert.equal(admin("SELECT COUNT(*) FROM pg_roles WHERE rolname='"+ROLE+"'"),
    '0','Read-only test role already exists');
  const beforeAudit=admin('SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox');
  assert.equal(admin("SELECT gc_permitted::text FROM "+
    "saas_rls_private.synthetic_operation_retention_health('demo-north')"),
    'false');
  // One CI-only restricted SQL principal. It is not a production credential.
  admin("CREATE ROLE "+ROLE+" WITH LOGIN NOINHERIT PASSWORD '"+password+"';"+
    "GRANT CONNECT ON DATABASE "+SOURCE+" TO "+ROLE+";"+
    "GRANT USAGE ON SCHEMA saas_rls_private TO "+ROLE+";"+
    "GRANT SELECT (operation_id) ON "+
    "saas_rls_private.synthetic_operation_issues TO "+ROLE+";"+
    "GRANT SELECT (operation_id) ON "+
    "saas_rls_private.synthetic_producer_operations TO "+ROLE+";");
  roleCreated=true;
  assert.equal(admin("SELECT rolcanlogin::text FROM pg_roles WHERE rolname='"+ROLE+"'"),'true');
  restricted('SELECT operation_id FROM saas_rls_private.synthetic_operation_issues LIMIT 1');
  restricted('SELECT operation_id FROM saas_rls_private.synthetic_producer_operations LIMIT 1');
  restricted('SELECT tenant_id FROM saas_rls_private.synthetic_operation_issues',true);
  restricted('SELECT actor_id FROM saas_rls_private.synthetic_producer_operations',true);
  restricted('SELECT secret FROM saas_rls_private.scope_signers',true);
  restricted('UPDATE saas_rls_private.synthetic_operation_issues SET requested_limit=2',true);
  console.info('PASS: disposable PG16 projector role SELECT UUID only; tenant, actor, secrets and writes DENY');

  generateProjectorKeypair();
  runWitness('keygen',[witPriv,witPub]);
  const ch1=challenge('challenge-1.json',null);
  const signed1=join(work,'attestation-1.json');
  const proof1=attest(ch1,signed1);
  const p1=save('projection-1.json',proof1.statement.projection);
  assert.ok(proof1.statement.projection.issuedCount>0);
  assert.ok(proof1.statement.projection.producerCount>0);
  makeWitness(p1,'-',cp1);
  const head1=save('trusted-head-1.json',head(cp1));
  verify(ch1,signed1,cp1,'-',head1);
  console.info('PASS: separate read-only PG16 attestor signs repeatable-read snapshot and witness genesis');

  // A real COMMIT must receive an independently observed attestation.
  assert.equal(admin("SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
    "WHERE operation_id='"+ISSUE+"'::uuid"),'0');
  admin("BEGIN; INSERT INTO saas_rls_private.synthetic_operation_issues "+
    "(operation_id,tenant_id,actor_id,membership_role,collection,"+
    "requested_limit,issued_at,issue_expires_at,recovery_expires_at) VALUES "+
    "('"+ISSUE+"'::uuid,'ci-pg-proof','ci-pg-proof-actor',"+
    "'tenant-viewer','projects',1,clock_timestamp(),"+
    "clock_timestamp()+interval '2 minutes',"+
    "clock_timestamp()+interval '2 hours'); COMMIT;");
  assert.equal(admin("SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues "+
    "WHERE operation_id='"+ISSUE+"'::uuid"),'1');
  const ch2=challenge('challenge-2.json',head(cp1));
  const signed2=join(work,'attestation-2.json');
  const proof2=attest(ch2,signed2);
  assert.equal(proof2.statement.projection.issuedCount,
    proof1.statement.projection.issuedCount+1);
  assert.equal(proof2.statement.projection.producerCount,
    proof1.statement.projection.producerCount);
  verify(ch2,signed2,cp1,'-',head1,{deny:true});
  const p2=save('projection-2.json',proof2.statement.projection);
  makeWitness(p2,cp1,cp2);
  const head2=save('trusted-head-2.json',head(cp2));
  verify(ch2,signed2,cp2,cp1,head2);
  console.info('PASS: real PG16 COMMIT remains unsigned until fresh source attestation and signed witness successor');

  // Client-invented projection cannot forge the attestor signature.
  const tampered=structuredClone(read(signed2));
  tampered.statement.projection.issued.push('f'.repeat(64));
  tampered.statement.projection.issued.sort();
  tampered.statement.projection.issuedCount++;
  const forged=save('forged-client-projection.json',tampered);
  verify(ch2,forged,cp2,cp1,head2,{deny:true});
  const replayed=challenge('replayed-challenge.json',head(cp1));
  verify(replayed,signed2,cp2,cp1,head2,{deny:true});
  const fakeHead=save('tampered-head.json',{sequence:2,digest:'f'.repeat(64)});
  verify(ch2,signed2,cp2,cp1,fakeHead,{deny:true});
  const another=generateKeyPairSync('ed25519');
  const wrongKey=join(work,'wrong-projector-public.pem');
  writeFileSync(wrongKey,another.publicKey.export({type:'spki',format:'pem'}),
    {flag:'wx',mode:0o600});
  verify(ch2,signed2,cp2,cp1,head2,{deny:true,projectorKey:wrongKey});
  verify(ch1,signed1,cp1,'-',head2,{deny:true});
  console.info('PASS: forged client UUID, replayed nonce, swapped key and stale witness head DENY');

  admin("REVOKE SELECT (operation_id) ON "+
    "saas_rls_private.synthetic_operation_issues FROM "+ROLE);
  const afterRevoke=challenge('revoked-role-challenge.json',head(cp2));
  runAttestor('attest',[attPriv,attPub,afterRevoke,
    join(work,'revoked-attestation.json')],true);
  assert.equal(admin('SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox'),
    beforeAudit,'Projector must not create publication intent');
  assert.equal(admin("SELECT gc_permitted::text FROM "+
    "saas_rls_private.synthetic_operation_retention_health('demo-north')"),
    'false');
  assert.ok(!JSON.stringify(proof2).includes(ISSUE)&&
    !JSON.stringify(proof2).includes('ci-pg-proof-actor'));
  console.info('PASS: projector privilege revocation DENY; no 009/013 effects or raw UUID; GC false');
} finally {
  if(roleCreated) {
    try {
      admin("REVOKE SELECT (operation_id) ON saas_rls_private.synthetic_operation_issues FROM "+ROLE+";"+
        "REVOKE SELECT (operation_id) ON saas_rls_private.synthetic_producer_operations FROM "+ROLE+";"+
        "REVOKE ALL ON saas_rls_private.synthetic_operation_issues FROM "+ROLE+";"+
        "REVOKE ALL ON saas_rls_private.synthetic_producer_operations FROM "+ROLE+";"+
        "REVOKE ALL ON SCHEMA saas_rls_private FROM "+ROLE+";"+
        "REVOKE CONNECT ON DATABASE "+SOURCE+" FROM "+ROLE+";"+
        "DROP ROLE "+ROLE+";");
    }catch(err){console.error('CI role cleanup failed: '+err.message);}
  }
  rmSync(work,{recursive:true,force:true});
}
