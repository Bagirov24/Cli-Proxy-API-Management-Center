import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  createBackend16StagingBunPhysicalPgPool,
  createBackend16StagingSqlSequence,
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
