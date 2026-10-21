import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {
  chmodSync,copyFileSync,mkdirSync,mkdtempSync,readFileSync,rmSync,
  symlinkSync,writeFileSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  inspectBackend16NativeSourceCrossRunnerReceipt,
  enforceBackend16NativeSourceCrossRunnerEnvironment,
  assertMatchingBackend16NativeSourceCrossRunnerProofs,
} from '../scripts/saas-staging/verify-backend16-native-source-cross-runner-ci.mjs';

const ROOT=fileURLToPath(new URL('../',import.meta.url));
const SERVER='src/features/saasBlueprint/controlApi/server';
const read=path=>readFileSync(new URL(path,import.meta.url),'utf8');
const MODULES=JSON.parse(read(
  '../scripts/saas-staging/backend16-native-server-source-closure.v1.json')).modules;
const SOURCE='9a0e30c78d1c2d07ee3b4695cdfa1d570f5c8f0e2f75f2371b010a8edad5687c';
const CYCLONEDX='c8617a1c461757f3325909435693471df8253fde2044a313af6953c46ef199e3';
const PLAN='df2aeac8f92113fb8896a099abd0d389e1674229a7ed71262e24bc68a8552186';
const HEAD='a'.repeat(40),EVENT='b'.repeat(40);
const E={
  CI:'true',GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'pull_request',
  GITHUB_REPOSITORY:'Bagirov24/Cli-Proxy-API-Management-Center',
  GITHUB_REF:'refs/pull/101/merge',GITHUB_SHA:EVENT,
  B16_PR_HEAD_SHA:HEAD,RUNNER_OS:'Linux',RUNNER_ARCH:'X64',
  RUNNER_TEMP:'/tmp/b16-repro',
  GITHUB_OUTPUT:'/tmp/b16-repro/_runner_file_commands/set_output_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  GITHUB_JOB:'proof_a',B16_NATIVE_REPRO_SLOT:'A',
};
const evidence=()=>({
  source:SOURCE,cyclonedx:CYCLONEDX,plan:PLAN,state:'BLOCKED_RELEASE',
});
const a=()=>({slot:'A',head:HEAD,event:EVENT,checkout:HEAD,...evidence()});
const b=()=>({...a(),slot:'B'});
const refuse=fn=>assert.throws(fn,
  /Backend16 Native (?:source cross-runner CI|server artifact evidence contract|source CycloneDX offline verification|Bun server source closure CI|source CycloneDX CI) refused/);

function inMirror(fn){
  const root=mkdtempSync(join(tmpdir(),'b16-native-repro-test-'));
  const server=join(root,SERVER);
  try{
    mkdirSync(server,{recursive:true});
    for(const entry of MODULES)
      copyFileSync(join(ROOT,SERVER,entry.file),join(server,entry.file));
    return fn(root,server);
  }finally{rmSync(root,{recursive:true,force:true});}
}

test('source inventory, CycloneDX and blocked artifact plan reproduce identically',()=>{
  const original=inspectBackend16NativeSourceCrossRunnerReceipt(ROOT);
  assert.deepEqual(original,evidence());
  assert.equal(Object.isFrozen(original),true);
  inMirror(root=>{
    const independent=inspectBackend16NativeSourceCrossRunnerReceipt(root);
    assert.deepEqual(independent,original);
    assert.notEqual(independent,original);
  });
});

test('altered reviewed inputs, unsafe permissions or symlinks refuse receipts',()=>{
  inMirror((root,server)=>{
    const path=join(server,MODULES[0].file);
    const bytes=readFileSync(path);
    const corrupt=Buffer.from(bytes);
    corrupt[30]^=1;
    writeFileSync(path,corrupt);
    refuse(()=>inspectBackend16NativeSourceCrossRunnerReceipt(root));
    writeFileSync(path,bytes);
    chmodSync(path,0o666);
    refuse(()=>inspectBackend16NativeSourceCrossRunnerReceipt(root));
    chmodSync(path,0o644);
    rmSync(path);
    symlinkSync(MODULES[1].file,path);
    refuse(()=>inspectBackend16NativeSourceCrossRunnerReceipt(root));
  });
  refuse(()=>inspectBackend16NativeSourceCrossRunnerReceipt('relative'));
});

test('CI-only record and comparison must bind exact PR checkout and event',()=>{
  assert.equal(enforceBackend16NativeSourceCrossRunnerEnvironment(
    E,24,'record',HEAD),true);
  const compare={...E,GITHUB_JOB:'compare'};
  delete compare.B16_NATIVE_REPRO_SLOT;
  assert.equal(enforceBackend16NativeSourceCrossRunnerEnvironment(
    compare,24,'compare',HEAD),true);
  for(const [k,v] of Object.entries({
    CI:'false',GITHUB_ACTIONS:'false',GITHUB_EVENT_NAME:'workflow_dispatch',
    GITHUB_REPOSITORY:'another/repo',GITHUB_REF:'refs/heads/main',
    GITHUB_SHA:'bad',B16_PR_HEAD_SHA:'bad',
    RUNNER_OS:'Windows',RUNNER_ARCH:'ARM64',NODE_ENV:'production',
    NODE_TLS_REJECT_UNAUTHORIZED:'0',PGHOST:'db.internal',
    PGUSER:'staging_user',PGPASSWORD:'secret',DATABASE_URL:'postgres://foo',
    RAILWAY_ENVIRONMENT:'production',SAAS_B16_NATIVE_BUN_BIN:'/bin/bun',
  }))refuse(()=>enforceBackend16NativeSourceCrossRunnerEnvironment(
    {...E,[k]:v},24,'record',HEAD));
  refuse(()=>enforceBackend16NativeSourceCrossRunnerEnvironment(E,23,'record',HEAD));
  refuse(()=>enforceBackend16NativeSourceCrossRunnerEnvironment(E,24,'record',EVENT));
  refuse(()=>enforceBackend16NativeSourceCrossRunnerEnvironment(E,24,'other',HEAD));
  refuse(()=>enforceBackend16NativeSourceCrossRunnerEnvironment(null,24,'record',HEAD));
});

test('refuse spoofed slots, GitHub output outside runner temp and release vars',()=>{
  for(const override of [
    {B16_NATIVE_REPRO_SLOT:'B'},
    {B16_NATIVE_REPRO_SLOT:'C'},
    {GITHUB_JOB:'compare'},
    {RUNNER_TEMP:'relative/path'},
    {GITHUB_OUTPUT:'/tmp/outside'},
    {GITHUB_OUTPUT:'/tmp/b16-repro/../outside'},
    {GITHUB_OUTPUT:'/tmp/b16-repro/other.txt'},
    {SAAS_B16_EXPERIMENTAL_TLS_CI:'true'},
    {SAAS_B16_LOCKED_FULL_CHAIN_CI:'true'},
  ])refuse(()=>enforceBackend16NativeSourceCrossRunnerEnvironment(
    {...E,...override},24,'record',HEAD));
  refuse(()=>enforceBackend16NativeSourceCrossRunnerEnvironment(
    {...E,GITHUB_JOB:'compare'},24,'compare',HEAD));
});

test('two independently bound receipts must have exact graph hashes and hard stop',()=>{
  assert.equal(assertMatchingBackend16NativeSourceCrossRunnerProofs(
    a(),b(),HEAD,EVENT,HEAD),
    'B16_NATIVE_SOURCE_CROSS_RUNNER_EXACT_HEAD_MATCH_PASS');
  for(const key of Object.keys(a())){
    const candidate=b();
    candidate[key]=key==='slot'?'A':
      key==='state'?'RELEASE_APPROVED':
      key==='head'||key==='checkout'?EVENT:
      key==='event'?HEAD:'f'.repeat(64);
    refuse(()=>assertMatchingBackend16NativeSourceCrossRunnerProofs(
      a(),candidate,HEAD,EVENT,HEAD));
  }
  for(const override of [
    {source:'0'.repeat(64)}, {cyclonedx:'0'.repeat(64)},
    {plan:'0'.repeat(64)}, {state:'STAGING_APPROVED'},
    {slot:'C'}, {head:'bad'}, {event:'bad'}, {checkout:'bad'},
    {unknown:'extra'},
  ])refuse(()=>assertMatchingBackend16NativeSourceCrossRunnerProofs(
    {...a(),...override},b(),HEAD,EVENT,HEAD));
  const missing=a();
  delete missing.source;
  refuse(()=>assertMatchingBackend16NativeSourceCrossRunnerProofs(
    missing,b(),HEAD,EVENT,HEAD));
  refuse(()=>assertMatchingBackend16NativeSourceCrossRunnerProofs(
    a(),a(),HEAD,EVENT,HEAD));
  refuse(()=>assertMatchingBackend16NativeSourceCrossRunnerProofs(
    a(),b(),EVENT,EVENT,HEAD));
  refuse(()=>assertMatchingBackend16NativeSourceCrossRunnerProofs(
    a(),b(),HEAD,HEAD,HEAD));
});

test('untrusted local CLI invocation cannot produce receipt or release success',()=>{
  const executable=fileURLToPath(new URL(
    '../scripts/saas-staging/verify-backend16-native-source-cross-runner-ci.mjs',
    import.meta.url));
  for(const mode of ['record','compare','wrong']){
    const p=spawnSync(process.execPath,[executable,mode],{
      env:{...process.env,CI:'false',GITHUB_ACTIONS:'false'},
      encoding:'utf8',timeout:5_000,
    });
    assert.equal(p.status,1);
    assert.equal(p.stdout,'');
    assert.match(p.stderr,/STOP Backend16 Native source cross-runner CI refused/);
  }
  const script=read(
    '../scripts/saas-staging/verify-backend16-native-source-cross-runner-ci.mjs');
  assert.doesNotMatch(script,/\bfetch\s*\(|\bnpm\s+(?:ci|install)\b/);
  assert.doesNotMatch(script,/NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=true/);
});

test('dedicated hosted workflow uses three independent exact-head Node24 jobs',()=>{
  const path='../.github/workflows/saas-backend16-native-source-repro-ci.yml';
  const yml=read(path);
  assert.ok(yml.includes('on:\n  pull_request:'));
  assert.ok(yml.includes('permissions:\n  contents: read'));
  for(const job of ['proof_a','proof_b','compare']){
    assert.ok(yml.includes('\n  '+job+':'),job);
  }
  assert.ok(yml.includes('needs: [proof_a, proof_b]'));
  assert.equal(yml.split('runs-on: ubuntu-24.04').length-1,3);
  assert.equal(yml.split("node-version: '24'").length-1,3);
  assert.equal(yml.split('persist-credentials: false').length-1,3);
  assert.equal(yml.split('ref: $'+'{{ github.event.pull_request.head.sha }}').length-1,3);
  assert.equal(yml.split('run: node scripts/saas-staging/verify-backend16-native-source-cross-runner-ci.mjs').length-1,3);
  assert.ok(yml.includes('B16_PROOF_A_PLAN')); // Changed if output labels renamed
  assert.doesNotMatch(yml,/continue-on-error:|expected-failure:/);
  assert.doesNotMatch(yml,/\brailway up\b|bun install|npm ci/);
});

test('Native TLS and physical PG16 workflow retain actual acceptance triggers',()=>{
  const newPaths=[
    '.github/workflows/saas-backend16-native-source-repro-ci.yml',
    'scripts/saas-staging/verify-backend16-native-source-cross-runner-ci.mjs',
    'tests/saasBackend16NativeSourceCrossRunnerCi.test.mjs',
    'docs/saas/BACKEND_16_P2_NATIVE_SOURCE_CROSS_RUNNER.md',
  ];
  const independent=read('../.github/workflows/saas-backend16-native-source-repro-ci.yml');
  const native=read('../.github/workflows/saas-backend16-native-tls-experiment.yml');
  const physical=read('../.github/workflows/saas-staging-rls-ci.yml');
  for(const f of [independent,native,physical]){
    for(const p of newPaths)assert.ok(f.includes("      - '"+p+"'"),p);
  }
  assert.ok(native.includes('node --test tests/saasBackend16NativeSourceCrossRunnerCi.test.mjs'));
  assert.ok(native.includes('verify-backend16-native-tls-version-probe-ci.ts'));
  assert.ok(physical.includes('postgres:16.6'));
  assert.equal(JSON.parse(read('../package.json')).packageManager,'bun@1.3.14');
  assert.ok(read('../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts')
    .includes('const NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false;'));
});
