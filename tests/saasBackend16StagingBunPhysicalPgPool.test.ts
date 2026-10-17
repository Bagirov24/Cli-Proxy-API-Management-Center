import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  createBackend16StagingBunPhysicalPgPool,
  createBackend16StagingSqlSequence,
  createBackend16StagingDisposableCiPhysicalPgPool,
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
  assert.throws(()=>createBackend16StagingBunPhysicalPgPool(vault),
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
    "tls:'verify-full'","max:1,connectionTimeout:4",
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
});
test('shared physical core has no public host/profile injection and pins local CI',()=>{
  assert.match(source,/const DISPOSABLE_CI_PROFILE:Backend16BunPgProfile/);
  assert.match(source,/hostname:'127\.0\.0\.1',database:'saas_staging_ci'/);
  assert.match(source,/const STAGING_PROFILE:Backend16BunPgProfile/);
  assert.match(source,/hostname:HOST,database:DATABASE,tls:'verify-full'/);
  assert.match(source,/profile\.tls\?\{tls:profile\.tls\}:\{\}/);
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
