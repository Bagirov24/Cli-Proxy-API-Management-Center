import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {
  extractBackend16PullRequestPaths,
  assertBackend16NativeTlsSourceTriggerCoverage,
} from '../scripts/saas-staging/verify-backend16-native-tls-trigger-coverage-ci.mjs';

const read=path=>readFileSync(new URL(path,import.meta.url),'utf8');
const paths={
  native:'../.github/workflows/saas-backend16-native-tls-experiment.yml',
  physical:'../.github/workflows/saas-staging-rls-ci.yml',
  cross:'../.github/workflows/saas-backend16-native-source-repro-ci.yml',
};
const native=read(paths.native);
const physical=read(paths.physical);
const cross=read(paths.cross);
const policy=JSON.parse(read(
  '../scripts/saas-staging/backend16-native-server-source-closure.v1.json'));
const SERVER='src/features/saasBlueprint/controlApi/server/';
const modulePaths=policy.modules.map(item=>SERVER+item.file);
const refuse=fn=>assert.throws(fn,
  /Backend16 Native TLS source trigger coverage refused/);
const check=(n=native,p=physical,c=cross,m=policy)=>
  assertBackend16NativeTlsSourceTriggerCoverage(n,p,c,m);
const trigger=p=>"      - '"+p+"'\n";
const without=(yaml,path)=>yaml.replace(trigger(path),'');
const newPaths=[
  'scripts/saas-staging/verify-backend16-native-tls-trigger-coverage-ci.mjs',
  'tests/saasBackend16NativeTlsTriggerCoverageCi.test.mjs',
  'docs/saas/BACKEND_16_P2_NATIVE_TLS_TRIGGER_COVERAGE.md',
];

test('reviewed seven native modules trigger all three independent CI boundaries',()=>{
  assert.equal(modulePaths.length,7);
  for(const yaml of [native,physical]){
    const list=extractBackend16PullRequestPaths(yaml);
    assert.ok(Object.isFrozen(list));
    for(const file of modulePaths)assert.ok(list.includes(file),file);
  }
  assert.ok(extractBackend16PullRequestPaths(cross).includes(
    SERVER+'backend16*.ts'));
  assert.deepEqual(check(),{
    result:'B16_NATIVE_TLS_SOURCE_TRIGGER_COVERAGE_CI_PASS',
    moduleCount:7,
    independentNativeTlsTriggered:true,
    physicalPg16Triggered:true,
    crossRunnerTriggered:true,
    stableRuntimeApproved:false,
    stagingAuthorized:false,
    productionAuthorized:false,
  });
  assert.ok(Object.isFrozen(check()));
});

test('omission of ANY reviewed source path denies separate Native TLS coverage',()=>{
  for(const file of modulePaths){
    assert.ok(native.includes(trigger(file)),file);
    refuse(()=>check(without(native,file)));
  }
});

test('omission of ANY reviewed source path denies physical PostgreSQL16 coverage',()=>{
  for(const file of modulePaths){
    assert.ok(physical.includes(trigger(file)),file);
    refuse(()=>check(native,without(physical,file)));
  }
});

test('physical Native test harness and PR/repro triggers cannot disappear',()=>{
  for(const file of [
    'scripts/saas-staging/verify-backend16-native-pg-tls-ci.ts',
    'scripts/saas-staging/verify-backend16-native-tls-version-probe-ci.ts',
    '.github/workflows/saas-backend16-native-tls-experiment.yml',
  ])refuse(()=>check(without(native,file)));
  refuse(()=>check(native,physical,without(cross,SERVER+'backend16*.ts')));
  refuse(()=>check(native,without(physical,'scripts/saas-staging/**')));
  refuse(()=>check(native,physical,without(cross,
    '.github/workflows/saas-backend16-native-source-repro-ci.yml')));
  refuse(()=>check(native,without(physical,
    '.github/workflows/saas-staging-rls-ci.yml')));
});

test('every new guard file needs three triggers, not just its own CI',()=>{
  for(const file of newPaths){
    assert.ok(native.includes(trigger(file)));
    assert.ok(physical.includes(trigger(file)));
    assert.ok(cross.includes(trigger(file)));
    refuse(()=>check(without(native,file)));
    refuse(()=>check(native,without(physical,file)));
    refuse(()=>check(native,physical,without(cross,file)));
  }
});

test('strict parser refuses commented, duplicated, moved or malformed PR paths',()=>{
  const path=modulePaths[0];
  const line=trigger(path);
  refuse(()=>check(native.replace(line,'      # - \''+path+'\'\n')));
  refuse(()=>check(native.replace(line,'    - \''+path+'\'\n')));
  refuse(()=>check(native.replace(line,'      - "'+path+'"\n')));
  refuse(()=>check(native.replace(line,"      - '"+path+"' # fake\n")));
  refuse(()=>check(native.replace(line,"      - '"+path.toUpperCase()+"'\n")));
  refuse(()=>check(native.replace(line,line+line)));
  refuse(()=>check(native.replace('on:\n  pull_request:\n    paths:',
    'on:\n  pull_request:\n    paths-ignore:')));
  refuse(()=>check(native.replace('  workflow_dispatch:',
    '    paths-ignore:\n      - \'**\'')));
  // Merely mentioning a missing trigger later in a shell command is insufficient.
  refuse(()=>check(without(native,path)+
    '\n#      - \''+path+'\'\n'));
  refuse(()=>extractBackend16PullRequestPaths('garbage'));
});

test('source policy drift, fake claims or unexpected imports never become triggers',()=>{
  const mutated=structuredClone(policy);
  mutated.modules[0].file='backend16Unreviewed.ts';
  refuse(()=>check(native,physical,cross,mutated));
  const altered=structuredClone(policy);
  altered.productionAuthorized=true;
  refuse(()=>check(native,physical,cross,altered));
  const other=structuredClone(policy);
  other.modules[0].imports.push({kind:'value',specifier:'pg'});
  refuse(()=>check(native,physical,cross,other));
  refuse(()=>check(native,physical,cross,{}));
});

test('offline guard executes before pinned canary and real negative TLS acceptance',()=>{
  const cmd='          node --test tests/saasBackend16NativeTlsTriggerCoverageCi.test.mjs';
  refuse(()=>check(native.replace(cmd,'          # removed offline guard')));
  refuse(()=>check(native.replace(
    '          '+ 'node --test tests/saasBackend16NativeSourceCrossRunnerCi.test.mjs',
    '          '+ 'node --test tests/saasBackend16NativeSourceCrossRunnerCi.test.mjs\n'+
    '        run: node scripts/saas-staging/install-backend16-native-bun-ci.mjs'
  )));
  refuse(()=>check(native.replace(
    'run: node scripts/saas-staging/install-backend16-native-bun-ci.mjs',
    'run: echo disabled')));
  refuse(()=>check(native.replace(
    'node-version: \'24\'','node-version: \'23\'')));
  refuse(()=>check(native.replace(
    'image: postgres:16.6','image: postgres:latest')));
  refuse(()=>check(native+'\ncontinue-on-error: true\n'));
  refuse(()=>check(native+'\nexpected-failure: true\n'));
  refuse(()=>check(native+'\nNATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=true\n'));
  refuse(()=>check(native,physical+'\ncontinue-on-error: true\n'));
  refuse(()=>check(native,physical,cross+'\nexpected-failure: true\n'));
  const missingCrossTest=cross.replace(
    '          node --test tests/saasBackend16NativeTlsTriggerCoverageCi.test.mjs','');
  refuse(()=>check(native,physical,missingCrossTest));
});

test('direct CLI denied outside CI; existing release hard stops stay unchanged',()=>{
  const executable=fileURLToPath(new URL(
    '../scripts/saas-staging/verify-backend16-native-tls-trigger-coverage-ci.mjs',
    import.meta.url));
  const result=spawnSync(process.execPath,[executable],{
    encoding:'utf8',timeout:5_000,
    env:{...process.env,CI:'false',GITHUB_ACTIONS:'false'},
  });
  assert.equal(result.status,1);
  assert.equal(result.stdout,'');
  assert.match(result.stderr,/STOP Backend16 Native TLS source trigger coverage refused/);
  const code=read(
    '../scripts/saas-staging/verify-backend16-native-tls-trigger-coverage-ci.mjs');
  assert.doesNotMatch(code,/\bfetch\s*\(|\bexecFileSync\s*\(/);
  assert.equal(JSON.parse(read('../package.json')).packageManager,'bun@1.3.14');
  assert.ok(read(
    '../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts'
  ).includes('const NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false;'));
});
