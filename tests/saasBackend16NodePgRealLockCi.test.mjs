import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,readFileSync} from 'node:fs';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  LOCK_ARGS,CLEAN_INSTALL_ARGS,
  createBackend16GenuineLockCiManifest,
  enforceBackend16GenuineLockCiEnvironment,safeNpmFailureCode,
} from '../scripts/saas-staging/verify-backend16-nodepg-real-lock-ci.mjs';
import {
  EXPECTED_NAME,EXPECTED_PG_VERSION,
} from '../scripts/saas-staging/verify-backend16-nodepg-runtime-lock.mjs';
const ROOT=fileURLToPath(new URL('../',import.meta.url));
const goodEnv=()=>({GITHUB_ACTIONS:'true',CI:'true'});
const refused=fn=>assert.throws(fn,/Backend16 genuine NodePG CI lock refused/);

test('genuine lock experiment is limited to GitHub Actions Node24',()=>{
  assert.doesNotThrow(()=>enforceBackend16GenuineLockCiEnvironment(goodEnv(),24));
  for(const major of [0,18,20,22,23,25]){
    refused(()=>enforceBackend16GenuineLockCiEnvironment(goodEnv(),major));
  }
  for(const invalid of [
    {GITHUB_ACTIONS:'false'},{CI:'false'},{NODE_ENV:'production'},
    {NODE_TLS_REJECT_UNAUTHORIZED:'0'},
    {RAILWAY_PROJECT_ID:'p'}, {RAILWAY_ENVIRONMENT_ID:'e'},
    {RAILWAY_SERVICE_ID:'s'}, {RAILWAY_ENVIRONMENT:'production'},
    {RAILWAY_ENVIRONMENT_NAME:'staging'}, {RAILWAY_PROJECT_NAME:'prod'},
  ])refused(()=>enforceBackend16GenuineLockCiEnvironment(
    {...goodEnv(),...invalid},24));
});
test('candidate manifest is Node24 private, isolated and version-pinned',()=>{
  const p=createBackend16GenuineLockCiManifest();
  assert.deepEqual(p,{
    name:EXPECTED_NAME,version:'0.0.0',private:true,type:'module',
    engines:{node:'24.x'},dependencies:{pg:EXPECTED_PG_VERSION},
  });
  assert.deepEqual(Object.keys(p.dependencies),['pg']);
  assert.equal(p.scripts,undefined);
  assert.equal(p.devDependencies,undefined);
});
test('genuine registry resolution and frozen install disable every lifecycle script',()=>{
  assert.equal(LOCK_ARGS[0],'install');
  assert.equal(CLEAN_INSTALL_ARGS[0],'ci');
  assert.ok(LOCK_ARGS.includes('--package-lock-only'));
  for(const args of [LOCK_ARGS,CLEAN_INSTALL_ARGS]){
    for(const required of [
      '--ignore-scripts','--omit=dev','--no-audit','--no-fund',
      '--registry=https://registry.npmjs.org',
    ])assert.ok(args.includes(required),required);
    assert.equal(args.some(x=>x.startsWith('--force')),false);
    assert.equal(Object.isFrozen(args),true);
  }
});
test('frontend root remains Bun-only and free of node-postgres',()=>{
  const frontend=JSON.parse(readFileSync(join(ROOT,'package.json'),'utf8'));
  assert.equal(frontend.packageManager,'bun@1.3.14');
  assert.equal(existsSync(join(ROOT,'bun.lock')),true);
  assert.equal(existsSync(join(ROOT,'package-lock.json')),false);
  for(const field of ['dependencies','devDependencies','optionalDependencies']){
    assert.equal(Object.hasOwn(frontend[field]||{},'pg'),false);
    assert.equal(Object.hasOwn(frontend[field]||{},'pg-native'),false);
  }
});
test('genuine lock acceptance is CI-only, never a release or migration',()=>{
  const source=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-nodepg-real-lock-ci.mjs',
    import.meta.url),'utf8');
  assert.ok(source.includes("verifyBackend16NodePgRuntimePackage(pkg,lock,frontend)"));
  assert.ok(source.includes("createHash('sha256').update(after)"));
  assert.ok(source.includes('npm_config_ignore_scripts'));
  assert.ok(source.includes("rmSync(dir,{recursive:true,force:true})"));
  assert.ok(source.includes('NO RELEASE AUTHORIZATION'));
  assert.doesNotMatch(source,/Bun\.serve|CREATE ROLE|ALTER ROLE|SQL0008|DATABASE_PUBLIC_URL/);
});

test('npm errors are reduced to finite, nonsecret diagnostics',()=>{
  assert.equal(safeNpmFailureCode(
    'npm error code ENOTFOUND\nsecret=should-never-print'), 'ENOTFOUND');
  assert.equal(safeNpmFailureCode(
    'npm error code E404\nrequest https://example/token/123'), 'E404');
  assert.equal(safeNpmFailureCode(
    'Bearer abcdef and arbitrary package text'), 'UNCLASSIFIED');
  assert.equal(safeNpmFailureCode('',{code:'EACCES'}), 'EACCES');
});
