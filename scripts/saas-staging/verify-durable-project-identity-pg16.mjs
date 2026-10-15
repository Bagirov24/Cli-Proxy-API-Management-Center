/**
 * Backend 04: real non-superuser PostgreSQL16 identity-read role + signed
 * token/session-bound project COMMIT. Disposable GitHub Actions ONLY.
 *
 * CI generates a synthetic RS256 issuer key, but the verifier is the actual
 * operator-pinned JWKS verifier (not a mock). Actor and bearer->session
 * resolution, private token state, current PG25 epoch and SQL026 mandatory
 * project trigger are REAL PostgreSQL rows.
 */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {SQL} from 'bun';
import {createOperatorPinnedOidcAccessVerifier} from
  '../../src/features/saasBlueprint/controlApi/server/operatorPinnedOidcAccessVerifier.ts';
import {createPgDurableIdentitySessionAuthority,PG_IDENTITY_SQL} from
  '../../src/features/saasBlueprint/controlApi/server/pgDurableIdentitySessionAuthority.ts';
import {createPinnedHmacScopeIssuer} from
  '../../src/features/saasBlueprint/controlApi/server/signedSqlBoundary.ts';
import {createTenantProjectsWriteHttpHandler} from
  '../../src/features/saasBlueprint/controlApi/server/tenantProjectsWriteHttpHandler.ts';
import {startWitness,runOffline} from './verify-m1h-precommit-intent.mjs';

const env=process.env;
if(env.GITHUB_ACTIONS!=='true'||env.SAAS_DURABLE_IDENTITY_PG_CI!=='true'||
   env.PGHOST!=='127.0.0.1'||env.PGPORT!=='5432'||
   env.PGDATABASE!=='saas_ephemeral_test'||
   env.NODE_ENV==='production'||env.RAILWAY_PROJECT_ID||
   env.RAILWAY_ENVIRONMENT||env.RAILWAY_SERVICE_ID)
 throw new Error('Only disposable localhost GitHub PostgreSQL16 is allowed');
const identityPwd=env.SAAS_EPHEMERAL_IDENTITY_DB_PASSWORD;
const projectPwd=env.SAAS_EPHEMERAL_DB_PASSWORD;
const scopeKey=env.SAAS_EPHEMERAL_SCOPE_KEY_HEX;
if(!/^[0-9a-f]{48}$/.test(identityPwd??'')||
   !/^[0-9a-f]{48}$/.test(projectPwd??'')||
   !/^[0-9a-f]{64}$/.test(scopeKey??''))
 throw new Error('Missing disposable PostgreSQL16 identity fixtures');
delete env.SAAS_EPHEMERAL_IDENTITY_DB_PASSWORD;
delete env.SAAS_EPHEMERAL_DB_PASSWORD;
delete env.SAAS_EPHEMERAL_SCOPE_KEY_HEX;

const dbOpts={hostname:'127.0.0.1',port:5432,
  database:'saas_ephemeral_test',max:1,connectionTimeout:5,
  idleTimeout:5,prepare:false,tls:false};
const admin=new SQL({...dbOpts,username:'postgres',password:'ci_ephemeral_test_only'});
const identityDb=new SQL({...dbOpts,username:'saas_identity_ci',password:identityPwd});
const projectDb=new SQL({...dbOpts,username:'saas_ci_runner',password:projectPwd});
let identityQuarantined=false;
const ALLOWED=new Set(Object.values(PG_IDENTITY_SQL));
const identityPool={
  quarantine(){identityQuarantined=true;},
  async connect(signal){
    if(identityQuarantined||signal.aborted)throw new Error('Identity pool stopped');
    const reserved=await identityDb.reserve({signal});
    return {
      async query(sql,params){
        if(!ALLOWED.has(sql)||!Array.isArray(params)||
           params.some(x=>typeof x!=='string'))
          throw new Error('Identity SQL outside fixed allowlist');
        return {rows:await reserved.unsafe(sql,params).execute()};
      },
      release(discard){
        reserved.release();
        if(discard){identityQuarantined=true;return identityDb.close({timeout:0});}
      },
    };
  },
};
const authority=createPgDurableIdentitySessionAuthority(identityPool);
const ISSUER='https://issuer.ci-evidence.org/token';
const AUD='urn:saas:operator-ci';
const ACTOR='actor-durable-pg';
const TENANT='demo-north';
const jwtKey=await crypto.subtle.generateKey(
  {name:'RSASSA-PKCS1-v1_5',modulusLength:2048,
   publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},
  true,['sign','verify'],
);
const publicKey=await crypto.subtle.exportKey('jwk',jwtKey.publicKey);
const verifier=await createOperatorPinnedOidcAccessVerifier({
  issuer:ISSUER,audience:AUD,
  pinnedPublicJwksJson:JSON.stringify({keys:[{
    kty:'RSA',kid:'ci-ephemeral-jwks-1',alg:'RS256',use:'sig',
    n:publicKey.n,e:publicKey.e,
  }]}),
});
const b64=s=>Buffer.from(JSON.stringify(s)).toString('base64url');
const currentSec=Math.floor(Date.now()/1000);
const expiry=currentSec+300;
async function mintToken(tokenLabel){
  assert.match(tokenLabel,/^[A-Za-z0-9_-]{1,64}$/);
  const header=b64({alg:'RS256',typ:'at+jwt',kid:'ci-ephemeral-jwks-1'});
  const payload=b64({iss:ISSUER,aud:AUD,sub:'account-one',
    iat:currentSec-5,exp:expiry,jti:tokenLabel});
  const unsigned=header+'.'+payload;
  const sig=new Uint8Array(await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',jwtKey.privateKey,
    new TextEncoder().encode(unsigned),
  ));
  return unsigned+'.'+Buffer.from(sig).toString('base64url');
}
async function scoped(q,args=[]){
  return admin.unsafe(q,args).execute();
}
async function withOperatorRole(role,sql,params=[]){
  assert.ok(['saas_issuer_directory_admin','saas_issuer_provisioner'].includes(role));
  assert.ok([
    'SELECT saas_rls_private.pin_verified_subject($1::text,$2::text,$3::text) AS applied',
    'SELECT saas_rls_private.enroll_verified_token($1::text,$2::text,$3::text,$4::text,$5::timestamptz) AS applied',
    'SELECT saas_rls_private.revoke_verified_token($1::text,$2::text,$3::text) AS applied',
    'SELECT saas_rls_private.revoke_verified_subject($1::text,$2::text) AS applied',
    'SELECT saas_m1_api.pin_project_verified_token_session($1::uuid,$2::text,$3::text,$4::text) AS applied',
  ].includes(sql));
  const c=await admin.reserve();
  try {
    await c.unsafe('BEGIN').execute();
    await c.unsafe('SET LOCAL ROLE '+role).execute();
    const rows=await c.unsafe(sql,params).execute();
    assert.equal(rows.length,1);
    await c.unsafe('COMMIT').execute();
    return rows[0].applied;
  }finally{c.release();}
}
const signBytes=Uint8Array.from(Buffer.from(scopeKey,'hex'));
const key=await crypto.subtle.importKey('raw',signBytes,{
  name:'HMAC',hash:'SHA-256'},false,['sign']);
signBytes.fill(0);
const signer=createPinnedHmacScopeIssuer(key);
const TOKEN=await mintToken('access-token-A');
const TOKEN_B=await mintToken('access-token-B');
const fp=createHash('sha256').update(TOKEN).digest('hex');
const fpB=createHash('sha256').update(TOKEN_B).digest('hex');
assert.notEqual(fp,fpB);
const sessionId=crypto.randomUUID();
const projectId=crypto.randomUUID();
const secondSession=crypto.randomUUID();
assert.match(sessionId,/^[0-9a-f-]{36}$/);
const scope=Object.freeze({actorId:ACTOR,tenantId:TENANT,
  role:'tenant-admin',correlationId:'backend04-ci',tokenFingerprint:fp});
const verified=await verifier.verifyAccessToken(TOKEN);
assert.equal(verified?.issuer,ISSUER);
assert.equal(verified?.subject,'account-one');
assert.ok(await verifier.verifyAccessToken(TOKEN_B),
  'B is also an independently valid, signed OAuth access token');

const V4=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
let witness=null;
async function signedCreate(project,session,revision,fingerprint,expected=false,
                            attemptId=crypto.randomUUID(),name='Durable project boundary',
                            requirePg25SessionSuccess=false){
 assert.match(attemptId,V4,'Every signed PG attempt requires a server UUIDv4');
 const c=await projectDb.reserve();
 let committed=false;
 try {
  await c.unsafe('BEGIN').execute();
  const tx=await c.unsafe('SELECT txid_current()::text AS txid').execute();
  const txid=tx[0].txid;
  const expires=Math.floor(Date.now()/1000)+60;
  const signed=await signer.sign({...scope,tokenFingerprint:fingerprint},
    txid,expires);
  for(const [claim,value] of [
   ['saas.scope_actor',ACTOR],['saas.scope_tenant',TENANT],
   ['saas.scope_txid',txid],['saas.scope_expiry',String(expires)],
   ['saas.scope_mac',signed],
   ['saas.scope_token_fingerprint',fingerprint],
   ['saas.m1_attempt_id',attemptId],
  ])await c.unsafe('SELECT set_config($1::text,$2::text,true)',
      [claim,value]).execute();
  await c.unsafe('SET LOCAL ROLE saas_m1_project_executor').execute();
  const permitted=await c.unsafe(
    'SELECT saas_m1_api.lock_project_session_epoch($1::uuid,$2::bigint,$3::text,$4::text) AS allowed',
    [session,revision,TENANT,ACTOR]).execute();
  if(requirePg25SessionSuccess){
    assert.equal(permitted[0]?.allowed,true,
      'PG25 must accept B bearer + A UUID before SQL026 specifically denies');
  }
  let created=false;
  if(permitted[0]?.allowed){
    const rows=await c.unsafe(
      'SELECT saas_m1_api.create_project($1::text,$2::text,$3::text) AS applied',
      [TENANT,project,name]).execute();
    created=rows[0]?.applied===true;
  }
  if(created&&expected){
    await c.unsafe('COMMIT').execute();
    committed=true;
  }else await c.unsafe('ROLLBACK').execute();
  assert.equal(created,expected,'SQL026 must reject mismatched bearer/session');
  return created;
 } catch(e) {
  if(!committed){
   try{await c.unsafe('ROLLBACK').execute();}catch{}
  }
  throw e;
 }finally{c.release();}
}
try {
  // Privileged actor bootstrap is isolated CI provisioning only. No HTTP
  // user can access it; actor and tenant are fixed test fixture identifiers.
  await scoped(
    "INSERT INTO saas_rls.memberships(actor_id,tenant_id,role,status) "+
    "VALUES($1,$2,'tenant-admin','active') ON CONFLICT DO NOTHING",
    [ACTOR,TENANT]);
  await scoped(
    "INSERT INTO saas_rls_private.actor_session_state(actor_id,status,revision) "+
    "VALUES($1,'active',1) ON CONFLICT DO NOTHING",[ACTOR]);
  await scoped(
    "INSERT INTO saas_m1_private.project_session_epochs "+
    "(session_id,actor_id,tenant_id,revision,status) "+
    "VALUES($1::uuid,$2,$3,1,'active')",
    [sessionId,ACTOR,TENANT]);
  await scoped(
    "INSERT INTO saas_m1_private.project_session_epochs "+
    "(session_id,actor_id,tenant_id,revision,status) "+
    "VALUES($1::uuid,$2,$3,1,'active')",
    [secondSession,ACTOR,TENANT]);

  assert.equal(await withOperatorRole('saas_issuer_directory_admin',
    'SELECT saas_rls_private.pin_verified_subject($1::text,$2::text,$3::text) AS applied',
    [ISSUER,'account-one',ACTOR]),true);
  assert.equal(await withOperatorRole('saas_issuer_provisioner',
    'SELECT saas_rls_private.enroll_verified_token($1::text,$2::text,$3::text,$4::text,$5::timestamptz) AS applied',
    [ISSUER,'account-one',ACTOR,fp,new Date(expiry*1000).toISOString()]),true);
  assert.equal(await withOperatorRole('saas_issuer_provisioner',
    'SELECT saas_m1_api.pin_project_verified_token_session($1::uuid,$2::text,$3::text,$4::text) AS applied',
    [sessionId,ACTOR,TENANT,fp]),true);
  assert.equal(await withOperatorRole('saas_issuer_provisioner',
    'SELECT saas_m1_api.pin_project_verified_token_session($1::uuid,$2::text,$3::text,$4::text) AS applied',
    [sessionId,ACTOR,TENANT,fp]),false,'same UUID/fingerprint cannot reissue');
  assert.equal(await withOperatorRole('saas_issuer_provisioner',
    'SELECT saas_rls_private.enroll_verified_token($1::text,$2::text,$3::text,$4::text,$5::timestamptz) AS applied',
    [ISSUER,'account-one',ACTOR,fpB,new Date(expiry*1000).toISOString()]),true);
  assert.equal(await withOperatorRole('saas_issuer_provisioner',
    'SELECT saas_m1_api.pin_project_verified_token_session($1::uuid,$2::text,$3::text,$4::text) AS applied',
    [secondSession,ACTOR,TENANT,fpB]),true);
  assert.equal(await withOperatorRole('saas_issuer_provisioner',
    'SELECT saas_m1_api.pin_project_verified_token_session($1::uuid,$2::text,$3::text,$4::text) AS applied',
    [sessionId,ACTOR,TENANT,fpB]),false,'B may not borrow A session');

  // Actual separate non-superuser login with NO direct table access:
  // SET LOCAL ROLE saas_m1_identity_resolver, readonly transaction, SQL
  // SECURITY DEFINER projections and server-controlled issuer values.
  assert.equal(await authority.directory.resolveActorId(verified),ACTOR);
  assert.equal(await authority.directory.resolveActorId({
    issuer:ISSUER,subject:'not-provisioned'}),null);
  const active=await authority.sessions.resolve({
    actorId:ACTOR,tenantId:TENANT,tokenFingerprint:fp},
    AbortSignal.timeout(9000));
  assert.deepEqual(active,{sessionId,sessionRevision:1});
  assert.equal(await authority.sessions.resolve({
    actorId:ACTOR,tenantId:'demo-orbit',tokenFingerprint:fp},
    AbortSignal.timeout(9000)),null);
  assert.equal(await authority.sessions.resolve({
    actorId:'actor-orbit',tenantId:TENANT,tokenFingerprint:fp},
    AbortSignal.timeout(9000)),null);
  assert.equal(await authority.sessions.resolve({
    actorId:ACTOR,tenantId:TENANT,tokenFingerprint:'b'.repeat(64)},
    AbortSignal.timeout(9000)),null);

  // B is also valid under SQL011, and PG25 by itself would allow any
  // still-active session for the SAME actor/tenant. The new SQL026 trigger
  // MUST DENY a fully valid B fingerprint used with A session UUID.
  assert.deepEqual(await authority.sessions.resolve({
    actorId:ACTOR,tenantId:TENANT,tokenFingerprint:fpB},
    AbortSignal.timeout(9000)),{sessionId:secondSession,sessionRevision:1});
  const impostor=crypto.randomUUID();
  const impostorAttempt=crypto.randomUUID();
  await signedCreate(impostor,sessionId,1,fpB,false,impostorAttempt,
    'Durable project boundary',true);
  const ghost=await scoped(
    'SELECT (SELECT count(*) FROM saas_m1_private.projects WHERE project_id=$1)::int AS projects,'+
    ' (SELECT count(*) FROM saas_m1_private.project_write_audit_outbox WHERE project_id=$1)::int AS audits,'+
    ' (SELECT count(*) FROM saas_m1_private.project_attempt_bindings WHERE attempt_id=$2::uuid)::int AS attempts',
    [impostor,impostorAttempt]);
  assert.deepEqual({...ghost[0]},{projects:0,audits:0,attempts:0},
    'No project, audit or attempt may survive SQL026 token/session mismatch');
  await signedCreate(projectId,sessionId,1,fp,true);
  const count=await scoped(
    'SELECT count(*)::int AS c FROM saas_m1_private.projects WHERE project_id=$1',
    [projectId]);
  assert.equal(count[0].c,1);
  const proof=await scoped(
    'SELECT count(*)::int AS c FROM saas_m1_private.project_session_proofs '+
    'WHERE session_id=$1::uuid',[sessionId]);
  assert.equal(proof[0].c,1);
  const audit=await scoped(
    'SELECT count(*)::int AS c FROM saas_m1_private.project_write_audit_outbox '+
    'WHERE project_id=$1',[projectId]);
  assert.equal(audit[0].c,1);

  // Actual Request/Response factory (not a public listener) now carries the
  // SHA256 of the TWICE-VERIFIED OAuth bearer from HTTP all the way into
  // the same signed native PostgreSQL16 transaction and SQL026 mandatory
  // project/audit/attempt/session binding. The signer is a separate fsync
  // process without any PostgreSQL credentials, not an in-memory promise.
  const witnessPath='/tmp/saas-backend04-http-'+crypto.randomUUID()+'.jsonl';
  witness=await startWitness(assert,witnessPath);
  const prepared=[];
  const httpsOrigin='https://control.operator-ci.org';
  const http=createTenantProjectsWriteHttpHandler({
    expectedOrigin:httpsOrigin,
    tokens:verifier,
    directory:authority.directory,
    sessions:authority.sessions,
    actors:{
      async lookup(actorId,signal){
        if(signal.aborted||actorId!==ACTOR)return null;
        // CI fixture only; production needs an independent restricted
        // current actor-membership reader, NOT a postgres superuser pool.
        const rows=await scoped(
          'SELECT tenant_id,role,status FROM saas_rls.memberships WHERE actor_id=$1',
          [actorId]);
        return {id:actorId,memberships:rows.map(row=>({
          tenantId:row.tenant_id,role:row.role,status:row.status,
        }))};
      },
    },
    journal:{
      async prepare(entry){
        assert.match(entry.attemptId,V4);
        assert.equal(entry.actorId,ACTOR);
        assert.equal(entry.tenantId,TENANT);
        const ack=await witness.prepare(entry);
        assert.equal(ack.attemptId,entry.attemptId);
        assert.equal(ack.sequence,prepared.length+1);
        prepared.push(entry);
        return ack;
      },
    },
    writer:{
      async execute(input){
        assert.equal(input.operation,'create');
        assert.equal(input.scope.actorId,ACTOR);
        assert.equal(input.scope.tenantId,TENANT);
        assert.equal(input.scope.role,'tenant-admin');
        assert.equal(input.sessionRevision,1);
        assert.equal(input.sessionId,input.tokenFingerprint===fp
          ? sessionId:input.tokenFingerprint===fpB?secondSession:null);
        assert.ok(['Real HTTP verified bearer','Lost ACK no retry'].includes(input.name));
        const applied=await signedCreate(input.projectId,input.sessionId,
          input.sessionRevision,input.tokenFingerprint,true,
          input.attemptId,input.name);
        if(input.name==='Lost ACK no retry'){
          // PG COMMIT has actually ACKed inside signedCreate. Lose the
          // acknowledgment between the trusted writer and the HTTP layer.
          // HTTP must return UNKNOWN 503, with no retry/reissued UUID.
          throw new Error('CI-ONLY LOST POST-COMMIT ACK');
        }
        return applied;
      },
    },
  });
  async function createViaHttp(token,name='Real HTTP verified bearer'){
    const response=await http(new Request(
      httpsOrigin+'/control-api/v1/tenants/demo-north/projects',{
        method:'POST',
        headers:{'Authorization':'Bearer '+token,
          'Content-Type':'application/json'},
        body:JSON.stringify({name}),
      }));
    assert.equal(response.headers.get('Access-Control-Allow-Origin'),null);
    assert.equal(response.headers.get('Set-Cookie'),null);
    assert.match(response.headers.get('Cache-Control')||'',/no-store/);
    const data=await response.json();
    const serialized=JSON.stringify(data);
    assert.equal(serialized.includes('attemptId'),false);
    assert.equal(serialized.includes(ACTOR),false);
    assert.equal(serialized.includes(fp),false);
    assert.equal(serialized.includes(fpB),false);
    return {status:response.status,data};
  }
  async function committedHttpProof(result,position){
    assert.equal(result.status,201);
    assert.match(result.data.projectId,V4);
    const row=await scoped(
      'SELECT p.name,COUNT(DISTINCT a.event_id)::int AS audits,'+
      ' COUNT(DISTINCT b.attempt_id)::int AS attempts FROM saas_m1_private.projects p '+
      'LEFT JOIN saas_m1_private.project_write_audit_outbox a '+
      'ON a.tenant_id=p.tenant_id AND a.project_id=p.project_id '+
      'LEFT JOIN saas_m1_private.project_attempt_bindings b '+
      'ON b.event_id=a.event_id AND b.attempt_id=$2::uuid '+
      'WHERE p.tenant_id=$3 AND p.project_id=$1 GROUP BY p.name',
      [result.data.projectId,prepared[position].attemptId,TENANT]);
    assert.equal(row.length,1);
    assert.deepEqual({...row[0]},{
      name:'Real HTTP verified bearer',audits:1,attempts:1,
    });
    assert.equal(prepared[position].projectId,result.data.projectId);
    assert.equal(prepared[position].attemptId.length,36);
  }
  const firstHttp=await createViaHttp(TOKEN);
  await committedHttpProof(firstHttp,0);
  const secondHttp=await createViaHttp(TOKEN_B);
  await committedHttpProof(secondHttp,1);
  assert.equal(prepared.length,2);

  // One confirmed real PG16 COMMIT followed by a deliberately lost
  // application ACK: exactly one project/audit/UUID/session proof is
  // persisted, but HTTP returns 503. The handler MUST NOT retry this.
  const unknown=await createViaHttp(TOKEN_B,'Lost ACK no retry');
  assert.equal(unknown.status,503);
  assert.equal(prepared.length,3,'No automatic retry after UNKNOWN COMMIT');
  const uncertain=prepared[2];
  assert.match(uncertain.attemptId,V4);
  const persisted=await scoped(
    'SELECT (SELECT count(*) FROM saas_m1_private.projects WHERE project_id=$1)::int AS projects,'+
    ' (SELECT count(*) FROM saas_m1_private.project_write_audit_outbox WHERE project_id=$1)::int AS audits,'+
    ' (SELECT count(*) FROM saas_m1_private.project_attempt_bindings WHERE attempt_id=$2::uuid)::int AS attempts,'+
    ' (SELECT count(*) FROM saas_m1_private.project_session_proofs p '+
    ' JOIN saas_m1_private.project_write_audit_outbox a ON a.pg_txid=p.pg_txid '+
    ' WHERE a.project_id=$1)::int AS proofs',
    [uncertain.projectId,uncertain.attemptId]);
  assert.deepEqual({...persisted[0]},{projects:1,audits:1,attempts:1,proofs:1});

  // Revoke A (the JWT is STILL cryptographically valid) from a separately
  // governed provisioning capability. PG session and subject lookups now
  // fail even though the session_epoch row itself remains active.
  assert.equal(await withOperatorRole('saas_issuer_provisioner',
    'SELECT saas_rls_private.revoke_verified_token($1::text,$2::text,$3::text) AS applied',
    [ISSUER,'account-one',fp]),true);
  assert.ok(await verifier.verifyAccessToken(TOKEN));
  assert.equal(await authority.sessions.resolve({
    actorId:ACTOR,tenantId:TENANT,tokenFingerprint:fp},
    AbortSignal.timeout(9000)),null);
  await signedCreate(crypto.randomUUID(),sessionId,1,fp,false);
  const beforeRevokedHttp=prepared.length;
  assert.equal((await createViaHttp(TOKEN)).status,503);
  assert.equal(prepared.length,beforeRevokedHttp,
    'Revoked bearer cannot mint a durable intent or reserve PG');
  // Independent B retains current subject+token and its own PG25 UUID.
  assert.deepEqual(await authority.sessions.resolve({
    actorId:ACTOR,tenantId:TENANT,tokenFingerprint:fpB},
    AbortSignal.timeout(9000)),{sessionId:secondSession,sessionRevision:1});
  const survivor=crypto.randomUUID();
  await signedCreate(survivor,secondSession,1,fpB,true);
  const thirdHttp=await createViaHttp(TOKEN_B);
  await committedHttpProof(thirdHttp,3);
  assert.equal(prepared.length,4);

  // Issuer-subject terminal revoke independently invalidates directory.
  assert.equal(await withOperatorRole('saas_issuer_directory_admin',
    'SELECT saas_rls_private.revoke_verified_subject($1::text,$2::text) AS applied',
    [ISSUER,'account-one']),true);
  assert.equal(await authority.directory.resolveActorId(verified),null);
  assert.equal(await authority.sessions.resolve({
    actorId:ACTOR,tenantId:TENANT,tokenFingerprint:fpB},
    AbortSignal.timeout(9000)),null);
  await signedCreate(crypto.randomUUID(),secondSession,1,fpB,false);
  const beforeSubjectDenied=prepared.length;
  assert.equal((await createViaHttp(TOKEN_B)).status,401);
  assert.equal(prepared.length,beforeSubjectDenied,
    'Revoked issuer-subject may not mint a PG write attempt');
  await witness.stop();
  assert.deepEqual(runOffline(assert,witnessPath,witness.publicKey,4)?.attempts,
    prepared,'Exactly four server-issued HTTP writes, including UNKNOWN, have one-shot fsync evidence');

  // NOLOGIN runtime role cannot touch raw rows or provision any identity.
  const grants=await scoped(
    "SELECT has_table_privilege('saas_m1_identity_resolver',"+
    "'saas_rls_private.issuer_subject_bindings','SELECT') AS bindings,"+
    "has_table_privilege('saas_m1_identity_resolver',"+
    "'saas_m1_private.project_session_token_links','SELECT') AS sessions,"+
    "has_function_privilege('saas_m1_identity_resolver',"+
    "'saas_m1_api.pin_project_verified_token_session(uuid,text,text,text)',"+
    "'EXECUTE') AS provision");
  assert.deepEqual(grants[0],{bindings:false,sessions:false,provision:false});
  console.info('PASS backend-04: signed HTTPS-origin POST->verified bearer SHA256->durable PG16 UUID->independent fsync intent->SQL026 signed COMMIT, lost ACK returns 503 with persisted 1:1:1:1 no retry; two valid token sessions, crossed A/B denied, A revoke/B survives, subject revoke denies');
} finally {
  if(witness)await witness.stop();
  await identityDb.close({timeout:0});
  await projectDb.close({timeout:0});
  await admin.close({timeout:0});
}
