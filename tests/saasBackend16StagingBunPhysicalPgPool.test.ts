import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  createBackend16StagingBunPhysicalPgPool,
  createBackend16StagingSqlSequence,
  createBackend16StagingDisposableCiPhysicalPgPool,
  createBackend16StagingDisposableCiTlsPhysicalPgPool,
} from '../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts';
import {BACKEND16_EXACT_READ_SQL as SQL}
  from '../src/features/saasBlueprint/controlApi/server/backend16ExactSessionSqlRead.ts';

const source=readFileSync(new URL(
  '../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts',
  import.meta.url),'utf8');
const vault={
  async readPrincipal(login:string){
    return {username:login,password:'k'.repeat(64)};
  },
};
test('staging physical driver refuses construction without exact Railway gates',()=>{
  assert.throws(()=>createBackend16StagingBunPhysicalPgPool(vault,null as never),
    /release gates not met/);
});
test('only strictly sequenced readAuthorized SQL; negative exact decision skips data',()=>{
  const seq=createBackend16StagingSqlSequence();
  assert.throws(()=>seq.check(SQL.exact,[
    'a','b','c','d',
  ]),/protocol refused/);
  for(const command of [
    SQL.begin,SQL.statementTimeout,SQL.lockTimeout,SQL.identity,
  ]){
    seq.check(command,[]);
    seq.completed(command,[]);
  }
  seq.check(SQL.exact,['a','b','c','d']);
  seq.completed(SQL.exact,[{allowed:false}]);
  assert.throws(()=>seq.check(SQL.tenant,['a']),/protocol refused/);
  seq.check(SQL.commit,[]);
  seq.completed(SQL.commit,[]);
  assert.equal(seq.finished(),true);
  assert.throws(()=>seq.check(SQL.begin,[]),/protocol refused/);
});
test('positive exact decision requires tenant/projects then COMMIT',()=>{
  const seq=createBackend16StagingSqlSequence();
  for(const command of [
    SQL.begin,SQL.statementTimeout,SQL.lockTimeout,SQL.identity,
  ]){
    seq.check(command,[]);
    seq.completed(command,[]);
  }
  seq.check(SQL.exact,['1','2','3','4']);
  assert.throws(()=>seq.completed(SQL.exact,[{allowed:'true'}]),
    /exact gate refused/);
  seq.completed(SQL.exact,[{allowed:true}]);
  assert.throws(()=>seq.check(SQL.commit,[]),/protocol refused/);
  for(const sql of [SQL.tenant,SQL.projects]){
    seq.check(sql,['a']);
    seq.completed(sql,[]);
  }
  seq.check(SQL.commit,[]);
  seq.completed(SQL.commit,[]);
  assert.equal(seq.finished(),true);
});
test('no production login, arbitrary SQL, HTTP, retry or migration capability',()=>{
  for(const value of [
    'RAILWAY_PROJECT_ID','RAILWAY_ENVIRONMENT_ID',
    'RAILWAY_ENVIRONMENT_NAME','RAILWAY_SERVICE_ID',
    'SAAS_B16_STAGING_0008_INDEPENDENT_READBACK',
    'SAAS_B16_STAGING_PRIVATE_ONLY',
    "const HOST='postgres.railway.internal'",
    "const DATABASE='saas_staging'",
    'backend16IsApprovedStagingPgTlsTrust',"max:1,connectionTimeout:4",
    'vault.readPrincipal(login,signal)',
    'credentials.username!==login',
    'quarantine(','stopped=true','AbortSignal.timeout(6000)',
    'query creation failed',
    "query.cancel()","db.close({timeout:0})",
  ])assert.ok(source.includes(value),value);
  assert.doesNotMatch(source,/Bun\.serve|createServer|\.listen\(|DATABASE_PUBLIC_URL/);
  const executable=source.replace(/\/\*[\s\S]*?\*\//g,'').replace(/\/\/[^\n]*/g,'');
  assert.doesNotMatch(executable,/\b(?:SET ROLE|CREATE ROLE|ALTER ROLE|DROP ROLE|pg_terminate_backend)\b/i);
  assert.doesNotMatch(source,/retry\s*\(/);
});

test('CI entrypoint refuses all non-disposable environments',()=>{
  assert.throws(()=>createBackend16StagingDisposableCiPhysicalPgPool(vault),
    /limited to disposable GitHub PG16/);
  assert.throws(()=>createBackend16StagingDisposableCiTlsPhysicalPgPool(
    vault,null as never),/native TLS limited to disposable GitHub PG16/);
});
test('shared physical core has no public host/profile injection and pins local CI',()=>{
  assert.match(source,/const DISPOSABLE_CI_PROFILE:Backend16BunPgProfile/);
  assert.match(source,/hostname:'127\.0\.0\.1',database:'saas_staging_ci'/);
  assert.match(source,/const STAGING_PROFILE:Backend16BunPgProfile/);
  assert.match(source,/hostname:HOST,database:DATABASE/);
  assert.match(source,/Object.freeze\(\{\.\.\.STAGING_PROFILE,tls:tlsTrust\}\)/);
  assert.match(source,/!backend16IsApprovedStagingPgTlsTrust\(tlsTrust\)/);
  assert.match(source,/profile\.tls\?\{tls:profile\.tls\}:\{\}/);
  assert.ok(source.includes("env.SAAS_B16_PHYSICAL_TLS_CI!=='true'"));
  assert.ok(source.includes('Object.freeze({...DISPOSABLE_CI_PROFILE,tls:tlsTrust})'));
  assert.doesNotMatch(source,/database:'saas_staging_ci',tls:/);
  assert.match(source,/env\.GITHUB_ACTIONS!=='true'/);
  assert.match(source,/env\.PGPASSWORD!=='ci_ephemeral_test_only'/);
  assert.match(source,/return buildBackend16StagingPhysicalPgPool\(vault,DISPOSABLE_CI_PROFILE\)/);
  assert.doesNotMatch(source,/export function buildBackend16StagingPhysicalPgPool/);
  assert.match(source,/ci\.GITHUB_ACTIONS==='true'&&ci\.SAAS_B16_EPHEMERAL_CI==='true'/);
  assert.match(source,/staging disposable CI stopped at '\+acquirePhase/);
  assert.match(source,/throw new Error\('Backend16 staging physical acquisition failed'\)/);

});

test('real disposable PG16 runner enforces staging core and PID quarantine',()=>{
  const e2e=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-bun-physical-pid-ci.ts',
    import.meta.url),'utf8');
  const script=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-exact-session-pg16.sh',
    import.meta.url),'utf8');
  for(const marker of [
    'createBackend16StagingDisposableCiPhysicalPgPool',
    'stagingPool.acquirePrincipal(A,fresh())',
    'stagingRead(a,ta,fresh())','stagingRead(b,tb,fresh())',
    'stagingRead(a,tb,fresh())','stagingRead(b,ta,fresh())',
    'await gone(stagePid','await gone(waitingPid)',
    'cancelStage.abort()','wait_event_type=',
    'PASS Backend16.9:',"await assert.rejects(stagingRead(b,tb,fresh())",
  ])assert.ok(e2e.includes(marker),marker);
  assert.ok(script.includes(
    'bun scripts/saas-staging/verify-backend16-bun-physical-pid-ci.ts'));
});

test('hung vault cannot hang physical acquisition after abort',()=>{
  for(const marker of [
    'function rejectOnAbort<T>',
    'signal.addEventListener(\'abort\',onAbort',
    'if(signal.aborted)onAbort()',
    'rejectOnAbort(vault.readPrincipal(login,signal),signal)',
    'rejectOnAbort(native.reserve({signal}),signal)',
    'rejectOnAbort(query.execute(),signal)',
  ])assert.ok(source.includes(marker),marker);
  const pgRunner=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-bun-physical-pid-ci.ts',
    import.meta.url),'utf8');
  for(const marker of [
    'hungVaultPool','abortVault.abort()',
    'await assert.rejects(stalled,',
    'await hungVaultPool.shutdown()',
  ])assert.ok(pgRunner.includes(marker),marker);
});

test('discard releases exclusively owned reservation before closing native PG pool',()=>{
  const discard=source.slice(
    source.indexOf('if(discard||stopped){'),
    source.indexOf('}else{',source.indexOf('if(discard||stopped){')),
  );
  assert.match(discard,/connection\.release\(\)/);
  assert.match(discard,/await db\.close\(\{timeout:0\}\)/);
  assert.ok(discard.indexOf('connection.release()')<
    discard.indexOf('await db.close({timeout:0})'),
    'Bun.SQL close must not await an unreleased reserved physical client');
  assert.ok(source.includes('if(reserved){try{reserved.release();}'));
  const e2e=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-bun-physical-pid-ci.ts',
    import.meta.url),'utf8');
  const shell=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-exact-session-pg16.sh',
    import.meta.url),'utf8');
  assert.ok(e2e.includes('B16_CI_PHASE_10_STAGE_DISCARD'));
  assert.ok(e2e.includes('await gone(stagePid as number)'));
  assert.ok(e2e.includes("stagingRead(a,ta,fresh())"),
    'discard must not poison otherwise healthy independent requests');
  assert.match(shell,/timeout --signal=TERM --kill-after=3s 110s/);
});

test('native TLS GitHub runner is isolated and proves real PostgreSQL SSL PID',()=>{
  const runner=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-native-pg-tls-ci.ts',
    import.meta.url),'utf8');
  const shell=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-exact-session-pg16.sh',
    import.meta.url),'utf8');
  const workflow=readFileSync(new URL(
    '../.github/workflows/saas-staging-rls-ci.yml',
    import.meta.url),'utf8');
  for(const marker of [
    "env.GITHUB_ACTIONS!=='true'",
    "env.SAAS_B16_PHYSICAL_TLS_CI!=='true'",
    "env.PGHOST!=='127.0.0.1'",
    "env.RAILWAY_PROJECT_ID",
    "command('docker',['inspect'",
    "'postgres:16.6'",
    "createBackend16StagingDisposableCiTlsPhysicalPgPool",
    "pg_stat_ssl WHERE pid=$1",
    "assert.equal(pgSsl[0].ssl,true",
    "createBackend16ExactSqlReadPort",
    "read(a,tb,fresh())","read(b,ta,fresh())",
    "B16_NATIVE_SQL_TLS_CA_SIGNED_WILDCARD_DENIED",
    "await gone(LOGIN_A)",
    "PASS Backend16 native Bun.SQL TLS to real disposable PG16",
  ])assert.ok(runner.includes(marker),marker);
  assert.ok(shell.includes('verify-backend16-native-pg-tls-ci.ts'));
  assert.ok(workflow.includes('SAAS_B16_CI_PG_CONTAINER: ${{ job.services.postgres.id }}'));
  assert.doesNotMatch(runner,/DATABASE_PUBLIC_URL|Bun\.serve|\/data\/auths/);
});
