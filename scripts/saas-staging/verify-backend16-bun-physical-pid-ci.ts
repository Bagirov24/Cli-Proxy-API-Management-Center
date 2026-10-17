/**
 * Backend16.7: real Bun.SQL physical-backend test in disposable GitHub PG16.
 * Called ONLY by verify-backend16-exact-session-pg16.sh BEFORE synthetic revoke.
 * No external host, production, Railway, real credentials or HTTP listener.
 */
import assert from 'node:assert/strict';
import {SQL} from 'bun';
import {createBackend16CiBunPhysicalPgPool}
  from '../../src/features/saasBlueprint/controlApi/server/backend16CiBunPhysicalPgPool.ts';
import {createBackend16StagingDisposableCiPhysicalPgPool}
  from '../../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts';
import {createBackend16ExactSqlReadPort,BACKEND16_EXACT_READ_SQL}
  from '../../src/features/saasBlueprint/controlApi/server/backend16ExactSessionSqlRead.ts';
import type {VerifiedPrincipal}
  from '../../src/features/saasBlueprint/controlApi/server/backend16PrivateTenantProjectRead.ts';

const e=process.env;
const A='saas_b14_person',B='saas_b16_person_b';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const HEX=/^[0-9a-f]{64}$/;
if(e.GITHUB_ACTIONS!=='true'||
   e.SAAS_B16_EPHEMERAL_CI!=='true'||
   e.SAAS_B16_PHYSICAL_CI!=='true'||
   e.PGHOST!=='127.0.0.1'||e.PGPORT!=='5432'||
   e.PGDATABASE!=='saas_ephemeral_test'||
   e.NODE_ENV==='production'||
   e.RAILWAY_PROJECT_ID||e.RAILWAY_ENVIRONMENT_ID||
   e.RAILWAY_SERVICE_ID||e.RAILWAY_ENVIRONMENT ||
   e.PGPASSWORD!=='ci_ephemeral_test_only'||
   !HEX.test(e.SAAS_B16_CI_A_PASSWORD??'')||
   !HEX.test(e.SAAS_B16_CI_B_PASSWORD??'')||
   !HEX.test(e.SAAS_B16_CI_A_SUBJECT_SHA??'')||
   !HEX.test(e.SAAS_B16_CI_B_SUBJECT_SHA??'')||
   ![e.SAAS_B16_CI_A_TENANT,e.SAAS_B16_CI_B_TENANT,
     e.SAAS_B16_CI_A_SESSION,e.SAAS_B16_CI_B_SESSION,
     e.SAAS_B16_CI_A_BINDING,e.SAAS_B16_CI_B_BINDING].every(
       s=>typeof s==='string'&&UUID.test(s))){
  throw Error('B16 physical CI refused unsafe environment');
}
const approved={
  [A]:e.SAAS_B16_CI_A_PASSWORD!,
  [B]:e.SAAS_B16_CI_B_PASSWORD!,
};
function credentials(login:string){
  if(login!==A&&login!==B)throw Error('CI operator credential resolution denied');
  return Promise.resolve({username:login,password:approved[login]});
}
const admin=new SQL({
  adapter:'postgres',hostname:'127.0.0.1',port:5432,
  username:'postgres',database:'saas_staging_ci',
  password:'ci_ephemeral_test_only',max:3,prepare:false,
  connectionTimeout:4,idleTimeout:0,
});
const scalar=async(sql:string,params:string[]=[]):Promise<unknown>=>{
  const rows=await admin.unsafe(sql,params);
  assert.equal(rows.length,1);
  return Object.values(rows[0])[0];
};
async function gone(pid:number) {
  for(let i=0;i<35;i++){
    const n=await scalar(
      'SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid=$1',[String(pid)]);
    if(n===0)return;
    await Bun.sleep(60);
  }
  throw Error('Backend16 physical backend PID survived close');
}
function principal(login:string):VerifiedPrincipal{
  const suffix=login===A?'A':'B';
  return Object.freeze({
    kind:'verified-server-session',
    issuer:'https://ci-b16-idp.invalid',
    pgLogin:login,
    subjectFingerprintSha256:e['SAAS_B16_CI_'+suffix+'_SUBJECT_SHA']!,
    sessionId:e['SAAS_B16_CI_'+suffix+'_SESSION']!,
    bindingId:e['SAAS_B16_CI_'+suffix+'_BINDING']!,
    sessionExpiresAtMs:Date.now()+180_000,
  });
}
const a=principal(A),b=principal(B);
const ta=e.SAAS_B16_CI_A_TENANT!,tb=e.SAAS_B16_CI_B_TENANT!;
const pool=createBackend16CiBunPhysicalPgPool((login)=>credentials(login));
const read=createBackend16ExactSqlReadPort({pool,expectedDatabase:'saas_staging_ci'});
const fresh=()=>new AbortController().signal;
let blocker:Awaited<ReturnType<typeof admin.reserve>>|undefined;
try{
  // Real two LOGINs and distinct independent physical PostgreSQL PIDs.
  console.info('B16_CI_PHASE_01_ACQUIRE_LEGACY');
  const ca=await pool.acquirePrincipal(A,fresh());
  console.info('B16_CI_PHASE_02_ACQUIRE_SECOND');
  const cb=await pool.acquirePrincipal(B,fresh());
  const aRole=await ca.query(BACKEND16_EXACT_READ_SQL.identity,[],fresh());
  const bRole=await cb.query(BACKEND16_EXACT_READ_SQL.identity,[],fresh());
  const pa=aRole.rows[0].backend_pid,pb=bRole.rows[0].backend_pid;
  assert.equal(aRole.rows[0].session_login,A);
  assert.equal(bRole.rows[0].session_login,B);
  assert.equal(aRole.rows[0].staging_only,'true');
  assert.equal(bRole.rows[0].staging_only,'true');
  assert.ok(Number.isSafeInteger(pa)&&Number.isSafeInteger(pb));
  assert.notEqual(pa,pb);
  assert.equal(await scalar(
    'SELECT count(*)::int FROM pg_stat_activity WHERE pid=$1 AND usename=$2',
    [String(pa),A]),1);
  assert.equal(await scalar(
    'SELECT count(*)::int FROM pg_stat_activity WHERE pid=$1 AND usename=$2',
    [String(pb),B]),1);
  console.info('B16_CI_PHASE_03_RELEASE_LEGACY');
  await ca.release(false);
  await cb.release(false);
  await gone(pa as number);
  await gone(pb as number);

  // The REAL Bun.SQL driver now executes the typed exact read adapter,
  // including SQL0008, SQL0007 FORCE RLS and acknowledged COMMIT.
  console.info('B16_CI_PHASE_04_LEGACY_EXACT_READ');
  const ra=await read(a,ta,fresh());
  const rb=await read(b,tb,fresh());
  assert.equal(ra.kind,'authorized');
  assert.equal(rb.kind,'authorized');
  assert.ok(ra.kind==='authorized'&&ra.projectIds.every(x=>UUID.test(x)));
  assert.ok(rb.kind==='authorized'&&rb.projectIds.every(x=>UUID.test(x)));
  assert.deepEqual(await read(a,tb,fresh()),{kind:'denied'});
  assert.deepEqual(await read(b,ta,fresh()),{kind:'denied'});
  for(const login of [A,B]){
    assert.equal(await scalar(
      'SELECT count(*)::int FROM pg_stat_activity WHERE datname=$1 AND usename=$2',
      ['saas_staging_ci',login]),0,'Bun.SQL release must not pool physical backend');
  }

  // Real PG16 lock contention: revoke writer takes FOR UPDATE on A ACL.
  // SQL0008's FOR SHARE must block. Abort the request and verify a real
  // backend PID disappears, while a different LOGIN remains authorized.
  console.info('B16_CI_PHASE_05_LEGACY_REVOKE_RACE');
  blocker=await admin.reserve();
  await blocker.unsafe('BEGIN').execute();
  const locked=await blocker.unsafe(
    'SELECT access_revision FROM saas_acl.principal_tenants '+
    'WHERE principal_name=$1 AND tenant_id=$2 FOR UPDATE',[A,ta]).execute();
  assert.equal(locked.length,1,'synthetic A grant needed for lock race');
  const abort=new AbortController();
  const waiting=read(a,ta,abort.signal);
  let pid:number|undefined;
  for(let i=0;i<30;i++){
    const row=await admin.unsafe(
      "SELECT pid::int AS pid FROM pg_stat_activity WHERE datname=$1 "+
      "AND usename=$2 AND wait_event_type='Lock' LIMIT 1",
      ['saas_staging_ci',A]);
    if(row.length===1&&Number.isSafeInteger(row[0].pid)){
      pid=row[0].pid as number;break;
    }
    await Bun.sleep(30);
  }
  assert.ok(pid!==undefined,'FOR SHARE must wait behind CI-only writer lock');
  abort.abort();
  await assert.rejects(waiting,/Backend16 exact SQL data source unavailable/);
  await gone(pid);
  await blocker.unsafe('ROLLBACK').execute();
  blocker.release();blocker=undefined;
  // The first pool is globally quarantined after an uncertain query.
  await assert.rejects(read(b,tb,fresh()));
  console.info('B16_CI_PHASE_06_LEGACY_CLEAN_POOL');
  const second=createBackend16CiBunPhysicalPgPool((login)=>credentials(login));
  try{
    const nextRead=createBackend16ExactSqlReadPort({
      pool:second,expectedDatabase:'saas_staging_ci',
    });
    assert.equal((await nextRead(b,tb,fresh())).kind,'authorized');
  }finally{await second.shutdown();}

  // Never use a mismatched operator credential to impersonate another LOGIN.
  console.info('B16_CI_PHASE_07_FORGED_DENY');
  const forged=createBackend16CiBunPhysicalPgPool(async()=>
    ({username:B,password:approved[B]}));
  const rejected=createBackend16ExactSqlReadPort({
    pool:forged,expectedDatabase:'saas_staging_ci',
  });
  try{
    await assert.rejects(rejected(a,ta,fresh()),
      /Backend16 exact SQL data source unavailable/);
  }finally{await forged.shutdown();}
  // Backend16.9: exercise THE SAME physical/query/discard core that staging
  // uses, but under the separate local-only CI profile on disposable PG16.
  // Host/database/TLS cannot be supplied by users, HTTP or test assertions.
  console.info('B16_CI_PHASE_08_STAGE_CREATE');
  const stagingPool=createBackend16StagingDisposableCiPhysicalPgPool({
    readPrincipal:(login)=>credentials(login),
  });
  const stagingRead=createBackend16ExactSqlReadPort({
    pool:stagingPool,expectedDatabase:'saas_staging_ci',
  });
  try{
    // A real native backend is physically killed even if its transaction
    // never reaches COMMIT, and no leaked PID survives.
    console.info('B16_CI_PHASE_09_STAGE_ACQUIRE');
    const stageConn=await stagingPool.acquirePrincipal(A,fresh());
    for(const sql of [
      BACKEND16_EXACT_READ_SQL.begin,
      BACKEND16_EXACT_READ_SQL.statementTimeout,
      BACKEND16_EXACT_READ_SQL.lockTimeout,
    ])await stageConn.query(sql,[],fresh());
    const identity=await stageConn.query(
      BACKEND16_EXACT_READ_SQL.identity,[],fresh());
    const stagePid=identity.rows[0].backend_pid;
    assert.equal(identity.rows[0].session_login,A);
    assert.equal(identity.rows[0].database_name,'saas_staging_ci');
    assert.ok(Number.isSafeInteger(stagePid));
    console.info('B16_CI_PHASE_10_STAGE_DISCARD');
    await assert.rejects(async()=>{await stageConn.release(true);},/discarded/);
    await gone(stagePid as number);

    console.info('B16_CI_PHASE_11_STAGE_EXACT_READ');
    assert.equal((await stagingRead(a,ta,fresh())).kind,'authorized');
    assert.equal((await stagingRead(b,tb,fresh())).kind,'authorized');
    assert.deepEqual(await stagingRead(a,tb,fresh()),{kind:'denied'});
    assert.deepEqual(await stagingRead(b,ta,fresh()),{kind:'denied'});
    for(const login of [A,B])assert.equal(await scalar(
      'SELECT count(*)::int FROM pg_stat_activity WHERE datname=$1 AND usename=$2',
      ['saas_staging_ci',login]),0);

    console.info('B16_CI_PHASE_12_STAGE_REVOKE_RACE');
    // Real PG16 FOR SHARE cancellation on an independently locked A grant.
    blocker=await admin.reserve();
    await blocker.unsafe('BEGIN').execute();
    await blocker.unsafe(
      'SELECT access_revision FROM saas_acl.principal_tenants '+
      'WHERE principal_name=$1 AND tenant_id=$2 FOR UPDATE',[A,ta]).execute();
    const cancelStage=new AbortController();
    const inflight=stagingRead(a,ta,cancelStage.signal);
    let waitingPid:number|undefined;
    for(let i=0;i<30;i++){
      const v=await admin.unsafe(
        "SELECT pid::int AS pid FROM pg_stat_activity WHERE datname=$1 "+
        "AND usename=$2 AND wait_event_type='Lock' LIMIT 1",
        ['saas_staging_ci',A]);
      if(v.length===1&&Number.isSafeInteger(v[0].pid)){
        waitingPid=v[0].pid as number;break;
      }
      await Bun.sleep(30);
    }
    assert.ok(waitingPid!==undefined,'Backend16.9 FOR SHARE lock must block');
    cancelStage.abort();
    await assert.rejects(inflight,
      /Backend16 exact SQL data source unavailable/);
    await gone(waitingPid);
    await blocker.unsafe('ROLLBACK').execute();
    blocker.release();blocker=undefined;
    await assert.rejects(stagingRead(b,tb,fresh()),/unavailable/);
  }finally{await stagingPool.shutdown();}
  console.info('B16_CI_PHASE_13_STAGE_FRESH_POOL');
  const cleanStaging=createBackend16StagingDisposableCiPhysicalPgPool({
    readPrincipal:(login)=>credentials(login),
  });
  try{
    const resumed=createBackend16ExactSqlReadPort({
      pool:cleanStaging,expectedDatabase:'saas_staging_ci',
    });
    assert.equal((await resumed(b,tb,fresh())).kind,'authorized');
  }finally{await cleanStaging.shutdown();}

  // A compromised/blocked external vault can ignore cancellation forever.
  // The staging physical core must settle promptly on caller abort, poison
  // future acquisitions synchronously and never contact any PG backend.
  console.info('B16_CI_PHASE_14_STAGE_HUNG_VAULT');
  const hungVaultPool=createBackend16StagingDisposableCiPhysicalPgPool({
    readPrincipal:()=>new Promise<{username:string,password:string}>(()=>{}),
  });
  try{
    const abortVault=new AbortController();
    const stalled=hungVaultPool.acquirePrincipal(A,abortVault.signal);
    abortVault.abort();
    await assert.rejects(stalled,/Backend16 staging physical acquisition failed/);
    await assert.rejects(hungVaultPool.acquirePrincipal(B,fresh()),
      /Backend16 staging physical LOGIN refused/);
    assert.equal(await scalar(
      'SELECT count(*)::int FROM pg_stat_activity WHERE datname=$1 AND usename=$2',
      ['saas_staging_ci',A]),0);
  }finally{await hungVaultPool.shutdown();}

  console.info('PASS Backend16.9: staging Bun.SQL core real PG16 physical LOGIN, locked exact session, cross-tenant deny, cancel/PID death and no retry');

  console.info('PASS Backend16.7: real Bun.SQL two distinct PG16 LOGIN backend PIDs, exact bound read, physical discard, forced cancellation, no credential spoof');
}finally{
  if(blocker){
    try{await blocker.unsafe('ROLLBACK').execute();}catch{/* synthetic CI only */}
    try{blocker.release();}catch{/* synthetic CI only */}
  }
  await pool.shutdown();
  await admin.close({timeout:0});
}
