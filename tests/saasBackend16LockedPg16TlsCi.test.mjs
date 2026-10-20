import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  enforceLockedPg16CiEnvironment,exactLockedPg16ServerIdentity,
} from '../scripts/saas-staging/verify-backend16-nodepg-locked-pg16-tls-ci.mjs';

const CI={GITHUB_ACTIONS:'true',CI:'true',SAAS_B16_LOCKED_PG16_CI:'true',
  PGHOST:'127.0.0.1',PGPORT:'5432',PGDATABASE:'saas_ephemeral_test',
  PGUSER:'postgres',PGPASSWORD:'ci_ephemeral_test_only',
  SAAS_B16_NODEPG_PG16_CONTAINER:'a'.repeat(64)};
const refuse=fn=>assert.throws(fn,/locked NodePG physical TLS CI refused/);

test('locked PG16 physical smoke has a strict, throwaway GH Node24 gate',()=>{
  assert.doesNotThrow(()=>enforceLockedPg16CiEnvironment(CI,24));
  for(const n of [18,20,22,23,25])refuse(()=>
    enforceLockedPg16CiEnvironment(CI,n));
  for(const bad of [
    {GITHUB_ACTIONS:'false'},{CI:'false'},
    {SAAS_B16_LOCKED_PG16_CI:'false'},
    {PGHOST:'railway.internal'},{PGPORT:'5433'},
    {PGDATABASE:'postgres'},{PGUSER:'other'},
    {PGPASSWORD:''},{SAAS_B16_NODEPG_PG16_CONTAINER:'docker-prod'},
    {NODE_TLS_REJECT_UNAUTHORIZED:'0'}, {NODE_ENV:'production'},
    {RAILWAY_PROJECT_ID:'p'},{RAILWAY_ENVIRONMENT_ID:'e'},
    {RAILWAY_SERVICE_ID:'s'},{RAILWAY_ENVIRONMENT:'production'},
    {RAILWAY_PROJECT_NAME:'p'},{RAILWAY_ENVIRONMENT_NAME:'staging'},
  ])refuse(()=>enforceLockedPg16CiEnvironment({...CI,...bad},24));
});
test('locked PG16 exact SAN callback fails closed on missing peer DER',()=>{
  for(const bad of [
    undefined,{},null,{raw:Buffer.alloc(32)},
    {raw:Buffer.alloc(400)},
  ])assert.ok(
    exactLockedPg16ServerIdentity('postgres.railway.internal',bad) instanceof Error);
  assert.ok(
    exactLockedPg16ServerIdentity('other.railway.internal',{}) instanceof Error);
});
test('real physical TLS acceptance uses only the externally verified installs',()=>{
  const source=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-nodepg-locked-pg16-tls-ci.mjs',
    import.meta.url),'utf8');
  const parent=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-nodepg-real-lock-ci.mjs',
    import.meta.url),'utf8');
  assert.ok(source.includes("metadata.version!==EXPECTED_PG_VERSION"));
  assert.ok(source.includes("createRequire(pathToFileURL(join(dir,'package.json')))"));
  assert.ok(source.includes('new X509Certificate(raw)'));
  assert.ok(source.includes("wildcards:false"));
  assert.ok(source.includes('row.login!==LOGIN||row.tls!==SSL_TRUE'));
  assert.ok(source.includes('expectRefused(clients[0],wrong,false)'));
  assert.ok(source.includes('expectRefused(clients[1],root,true)'));
  assert.ok(source.includes('B16_LOCKED_NODEPG_PG16_TLS_TWO_PHYSICAL_PIDS_PASS'));
  assert.ok(parent.includes('B16_REAL_LOCK_CI_OBSERVED_GRAPH_MATCH_PASS'));
  assert.ok(parent.includes('SAAS_B16_LOCKED_PG16_CI'));
  assert.ok(parent.includes("await runLockedPg16PhysicalTlsCi(receipts.map(r=>r.dir))"));
  assert.doesNotMatch(source,/Bun\.serve|DATABASE_PUBLIC_URL|CREATE EXTENSION|SQL0008/);
});
