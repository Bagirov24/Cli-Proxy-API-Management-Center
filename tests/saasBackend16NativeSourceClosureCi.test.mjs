import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,copyFileSync,mkdirSync,mkdtempSync,readFileSync,rmSync,
  renameSync,symlinkSync,writeFileSync,
} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {
  assertBackend16NativeSourceClosurePolicy,
  inspectBackend16NativeSourceClosure,
} from '../scripts/saas-staging/verify-backend16-native-source-closure-ci.mjs';

const ROOT=fileURLToPath(new URL('../',import.meta.url));
const SERVER='src/features/saasBlueprint/controlApi/server';
const MANIFEST='../scripts/saas-staging/backend16-native-server-source-closure.v1.json';
const MODULE='../scripts/saas-staging/verify-backend16-native-source-closure-ci.mjs';
const read=path=>readFileSync(new URL(path,import.meta.url),'utf8');
const policy=()=>JSON.parse(read(MANIFEST));
const refuse=fn=>assert.throws(fn,/Backend16 Native Bun server source closure CI refused/);

function withMirror(fn){
  const root=mkdtempSync(join(tmpdir(),'b16-native-source-inventory-test-'));
  const server=join(root,SERVER);
  try{
    mkdirSync(server,{recursive:true});
    for(const entry of policy().modules){
      copyFileSync(join(ROOT,SERVER,entry.file),join(server,entry.file));
    }
    return fn(root,server);
  }finally{rmSync(root,{recursive:true,force:true});}
}

test('actual Native Bun transport/broker source closure matches reviewed git blobs',()=>{
  const manifest=policy();
  assert.equal(assertBackend16NativeSourceClosurePolicy(manifest),true);
  const proof=inspectBackend16NativeSourceClosure(ROOT);
  assert.deepEqual(proof,{
    result:'B16_NATIVE_BUN_SOURCE_CLOSURE_CI_PASS',
    sourceInventorySha256:proof.sourceInventorySha256,
    fileCount:7,
    externalPackageCount:0,
    serverArtifactBuilt:false,
    stableRuntimeApproved:false,
    productionAuthorized:false,
  });
  assert.match(proof.sourceInventorySha256,/^[0-9a-f]{64}$/);
  assert.ok(Object.isFrozen(proof));
  assert.equal(manifest.modules.length,7);
  assert.deepEqual(manifest.allowedBuiltins,['node:crypto','node:https','node:tls']);
  assert.equal(manifest.entrypoints.length,4);
  assert.equal(manifest.modules.some(m=>m.file.includes('NodePg')),false);
  assert.equal(manifest.modules.some(m=>m.file.includes('.tsx')),false);
});

test('another isolated copy has same deterministic source inventory receipt',()=>{
  const original=inspectBackend16NativeSourceClosure(ROOT);
  withMirror(root=>{
    const independent=inspectBackend16NativeSourceClosure(root);
    assert.equal(independent.sourceInventorySha256,original.sourceInventorySha256);
    assert.notEqual(independent,original);
  });
});

test('one changed byte in native pool, SQL, TLS, broker or handler refuses',()=>{
  withMirror((root,server)=>{
    for(const file of [
      'backend16StagingBunPhysicalPgPool.ts',
      'backend16ExactSessionSqlRead.ts',
      'backend16StagingPgTlsTrust.ts',
      'backend16PrivateMtlsVersionedSecretReader.ts',
      'backend16PrivateTenantProjectRead.ts',
    ]){
      const path=join(server,file);
      const original=readFileSync(path);
      const altered=Buffer.from(original);
      altered[Math.min(260,altered.length-1)]^=1;
      writeFileSync(path,altered);
      refuse(()=>inspectBackend16NativeSourceClosure(root));
      writeFileSync(path,original);
    }
    assert.equal(inspectBackend16NativeSourceClosure(root).fileCount,7);
  });
});

test('unexpected imports, Node pg or a network listener cannot enter source closure',()=>{
  withMirror((root,server)=>{
    const path=join(server,'backend16StagingBunPhysicalPgPool.ts');
    const original=readFileSync(path,'utf8');
    for(const injected of [
      "import pg from 'pg';",
      "import {useState} from 'react';",
      "import root from '../../../../../../src/App';",
      "const load=import('./hidden-module.ts');",
      "const unsafe=require('node:child_process');",
      'Bun.serve({port:443,fetch:()=>new Response()});',
    ]){
      writeFileSync(path,original+'\n'+injected+'\n');
      refuse(()=>inspectBackend16NativeSourceClosure(root));
    }
    writeFileSync(path,original);
  });
});

test('symlink, group-writable, missing and renamed source file fail closed',()=>{
  withMirror((root,server)=>{
    const name='backend16StagingPgTlsTrust.ts';
    const path=join(server,name);
    chmodSync(path,0o666);
    refuse(()=>inspectBackend16NativeSourceClosure(root));
    chmodSync(path,0o644);
    rmSync(path);
    symlinkSync('backend16ExactSessionSqlRead.ts',path);
    refuse(()=>inspectBackend16NativeSourceClosure(root));
    rmSync(path);
    refuse(()=>inspectBackend16NativeSourceClosure(root));
  });
  withMirror((root,server)=>{
    const moved=server+'-actual';
    renameSync(server,moved);
    symlinkSync(moved,server,'dir');
    refuse(()=>inspectBackend16NativeSourceClosure(root));
  });
  refuse(()=>inspectBackend16NativeSourceClosure('relative/path'));
});

test('unreviewed manifest expansion, fake origin and release statuses refuse',()=>{
  const base=policy();
  for(const change of [
    {schema:'backend16-native-server-source-closure-v2'},
    {root:'src/features/saasBlueprint'},
    {scope:'PRODUCTION_RELEASE_APPROVED'},
    {serverArtifactBuilt:true},
    {stableRuntimeApproved:true},
    {productionAuthorized:true},
    {allowedBuiltins:[...base.allowedBuiltins,'node:child_process']},
    {entrypoints:base.entrypoints.slice(1)},
    {modules:base.modules.slice(1)},
    {unexpected:'extra'},
  ])refuse(()=>assertBackend16NativeSourceClosurePolicy(
    {...base,...change}));
  refuse(()=>assertBackend16NativeSourceClosurePolicy(null));
  refuse(()=>assertBackend16NativeSourceClosurePolicy(
    Object.create(base)));
  const clones=JSON.parse(JSON.stringify(base));
  clones.modules[0].imports.push({kind:'value',specifier:'pg'});
  refuse(()=>assertBackend16NativeSourceClosurePolicy(clones));
  const clones2=JSON.parse(JSON.stringify(base));
  clones2.modules[0].imports.push({kind:'value',specifier:'../App'});
  refuse(()=>assertBackend16NativeSourceClosurePolicy(clones2));
  const clones3=JSON.parse(JSON.stringify(base));
  clones3.modules[0].imports.push({kind:'value',specifier:'./unreviewed'});
  refuse(()=>assertBackend16NativeSourceClosurePolicy(clones3));
});

test('no disconnected production-ready SBOM, Bun package or signer is claimed',()=>{
  const manifest=policy();
  const files=manifest.modules.map(m=>m.file);
  assert.deepEqual(files,[...files].sort());
  assert.deepEqual(manifest.allowedBuiltins,[...manifest.allowedBuiltins].sort());
  assert.ok(files.every(n=>n.startsWith('backend16')&&n.endsWith('.ts')));
  assert.equal(manifest.productionAuthorized,false);
  assert.equal(manifest.stableRuntimeApproved,false);
  assert.equal(manifest.serverArtifactBuilt,false);
  assert.ok(read('../docs/saas/BACKEND_16_P2_NATIVE_SOURCE_CLOSURE.md')
    .includes('NOT_A_PRODUCTION_SBOM'));
  const pkg=JSON.parse(read('../package.json'));
  assert.equal(pkg.packageManager,'bun@1.3.14');
  assert.ok(read('../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts')
    .includes('const NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false;'));
});

test('direct CLI does not run outside authorized disposable CI context',()=>{
  const out=spawnSync(process.execPath,[fileURLToPath(new URL(MODULE,import.meta.url))],{
    encoding:'utf8',timeout:5000,
    env:{...process.env,CI:'false',GITHUB_ACTIONS:'false'},
  });
  assert.equal(out.status,1);
  assert.match(out.stderr,/STOP Backend16 Native Bun source closure CI refused/);
  assert.equal(out.stdout,'');
});

test('Native probe and physical PG16 workflows are triggered by closure changes',()=>{
  const native=read('../.github/workflows/saas-backend16-native-tls-experiment.yml');
  const physical=read('../.github/workflows/saas-staging-rls-ci.yml');
  const paths=[
    'scripts/saas-staging/verify-backend16-native-source-closure-ci.mjs',
    'scripts/saas-staging/backend16-native-server-source-closure.v1.json',
    'tests/saasBackend16NativeSourceClosureCi.test.mjs',
    'docs/saas/BACKEND_16_P2_NATIVE_SOURCE_CLOSURE.md',
  ];
  for(const target of [native,physical]){
    for(const p of paths)assert.ok(target.includes("      - '"+p+"'"),
      'missing mandatory physical CI trigger '+p);
  }
  assert.ok(native.includes(
    'node --test tests/saasBackend16NativeSourceClosureCi.test.mjs'));
  assert.ok(native.includes(
    'node scripts/saas-staging/verify-backend16-native-source-closure-ci.mjs'));
  assert.ok(native.includes(
    'scripts/saas-staging/verify-backend16-native-tls-version-probe-ci.ts'));
  assert.doesNotMatch(native,/continue-on-error:|expected-failure:/);
  assert.ok(physical.includes('postgres:16.6'));
  assert.ok(physical.includes('Backend16'));
});
