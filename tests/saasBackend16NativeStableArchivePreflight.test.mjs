import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {
  BACKEND16_NATIVE_STABLE_PREFLIGHT_SCHEMA,
  assertBackend16StableNativeBunDescriptor,
  inspectBackend16StableNativeBunArchive,
} from '../scripts/saas-staging/verify-backend16-native-stable-archive-preflight.mjs';

const codePath=new URL(
  '../scripts/saas-staging/verify-backend16-native-stable-archive-preflight.mjs',
  import.meta.url,
);
const read=path=>readFileSync(new URL(path,import.meta.url),'utf8');
const refused=fn=>assert.throws(fn,/Backend16 stable Native Bun archive preflight refused/);
const bytes=()=>Buffer.alloc(1_000_001,0x53);
const revision='a'.repeat(40);

// Fictional version and bytes are a parser fixture only, NOT a published
// stable release, a registry integrity receipt or acceptable native runtime.
function fixture(data=bytes()){
  const version='1.4.4';
  return {
    schema:BACKEND16_NATIVE_STABLE_PREFLIGHT_SCHEMA,
    npmPackage:'@oven/bun-linux-x64',
    version,
    platform:'linux',
    architecture:'x64',
    registryURL:'https://registry.npmjs.org/@oven/bun-linux-x64/-/bun-linux-x64-'+
      version+'.tgz',
    archiveByteLength:data.length,
    archiveSha512:createHash('sha512').update(data).digest('base64'),
    sourceRevision:revision,
    cliRevision:version+'+'+revision.slice(0,9),
  };
}
const replaceVersion=(d,version)=>({
  ...d,
  version,
  registryURL:'https://registry.npmjs.org/@oven/bun-linux-x64/-/bun-linux-x64-'+
    version+'.tgz',
  cliRevision:version+'+'+revision.slice(0,9),
});

test('fictional exact stable descriptor + byte digest only prove offline integrity',()=>{
  const archive=bytes();
  const desc=fixture(archive);
  assert.equal(assertBackend16StableNativeBunDescriptor(desc),true);
  const proof=inspectBackend16StableNativeBunArchive(desc,archive);
  assert.deepEqual(proof,{
    result:'ARCHIVE_INTEGRITY_ONLY_NOT_APPROVED',
    stableRuntimeApproved:false,
    stagingAuthorized:false,
    productionAuthorized:false,
  });
  assert.ok(Object.isFrozen(proof));
  assert.equal(Object.hasOwn(proof,'approvedVersion'),false);
});

test('known failing stable versions and all prerelease/floating canary tags deny',()=>{
  const d=fixture();
  for(const version of [
    '1.3.14','1.4.3','1.4.2','0.9.9','1.4.4-canary.1',
    '1.4.3-canary.20261019.1','1.4.4-rc.1','stable','canary',
    'latest','1.4.04','01.4.4','1.4.4+build','1.4.4\n',
    '1.4.4/../../other','2.0.0-nightly',
  ])refused(()=>assertBackend16StableNativeBunDescriptor(
    replaceVersion(d,version)));
  // Newer syntactically stable versions are not automatically approved.
  assert.doesNotThrow(()=>assertBackend16StableNativeBunDescriptor(
    replaceVersion(d,'1.4.5')));
  assert.doesNotThrow(()=>assertBackend16StableNativeBunDescriptor(
    replaceVersion(d,'2.0.0')));
});

test('unreviewed registry sources, platforms, metadata and CLI/source pins deny',()=>{
  const d=fixture();
  for(const override of [
    {schema:'unreviewed'},
    {npmPackage:'bun'}, {npmPackage:'@oven/bun-linux-arm64'},
    {platform:'darwin'}, {architecture:'arm64'},
    {registryURL:'https://registry.npmjs.org.evil.test/fake.tgz'},
    {registryURL:d.registryURL+'?download=1'},
    {registryURL:'http://registry.npmjs.org/@oven/bun-linux-x64/-/fake.tgz'},
    {archiveByteLength:100}, {archiveByteLength:150_000_001},
    {archiveByteLength:1.2},{archiveByteLength:NaN},
    {archiveSha512:'0'.repeat(88)}, {archiveSha512:'sha512-'+d.archiveSha512},
    {sourceRevision:'0'.repeat(40)}, {sourceRevision:'xyz'},
    {cliRevision:'1.4.4-canary.1+aaaaaaaaa'},
    {cliRevision:'1.4.4+bbbbbbbbb'},
    {productionAuthorized:true},
  ])refused(()=>assertBackend16StableNativeBunDescriptor({...d,...override}));
  refused(()=>assertBackend16StableNativeBunDescriptor(null));
  refused(()=>assertBackend16StableNativeBunDescriptor([]));
  refused(()=>assertBackend16StableNativeBunDescriptor(
    Object.create({schema:d.schema})));
});

test('actual bytes and declared length must match; mutated archives fail closed',()=>{
  const original=bytes();
  const desc=fixture(original);
  const tampered=Buffer.from(original);
  tampered[4500]^=0x01;
  refused(()=>inspectBackend16StableNativeBunArchive(desc,tampered));
  refused(()=>inspectBackend16StableNativeBunArchive(desc,new Uint8Array(0)));
  refused(()=>inspectBackend16StableNativeBunArchive(desc,original.subarray(1)));
  refused(()=>inspectBackend16StableNativeBunArchive(desc,undefined));
  refused(()=>inspectBackend16StableNativeBunArchive(
    {...desc,archiveSha512:'A'.repeat(86)+'=='},original));
});

test('direct CLI invocation never reports success or invokes a candidate runtime',()=>{
  const result=spawnSync(process.execPath,[fileURLToPath(codePath)],{
    encoding:'utf8',timeout:5_000,
  });
  assert.equal(result.status,1);
  assert.match(result.stderr,/NOT PINNED OR APPROVED/);
  assert.equal(result.stdout,'');
  const source=read(
    '../scripts/saas-staging/verify-backend16-native-stable-archive-preflight.mjs');
  assert.doesNotMatch(source,/\bfetch\s*\(|\bexecFileSync\s*\(|\bspawnSync\s*\(/);
  assert.doesNotMatch(source,/rejectUnauthorized\s*:\s*false/);
});

test('source decision and CI-only canary remain separate with physical TLS gates',()=>{
  const adr=read('../docs/saas/BACKEND_16_P1_NATIVE_BUN_SQL_ADR.ru.md');
  const nativeFactory=read(
    '../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts');
  const canary=read('../scripts/saas-staging/install-backend16-native-bun-ci.mjs');
  const workflow=read('../.github/workflows/saas-backend16-native-tls-experiment.yml');
  const physical=read('../scripts/saas-staging/verify-backend16-native-pg-tls-ci.ts');
  const pkg=JSON.parse(read('../package.json'));
  assert.equal(pkg.packageManager,'bun@1.3.14');
  assert.ok(nativeFactory.includes(
    'const NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false;'));
  assert.ok(adr.includes('ARCHITECTURE_SELECTED_RELEASE_BLOCKED'));
  assert.ok(adr.includes('CI_ONLY_COMPARATOR_NOT_PRODUCTION_FALLBACK'));
  assert.ok(canary.includes("version:'1.4.3-canary.20261019.1'"));
  for(const path of [
    'scripts/saas-staging/verify-backend16-native-stable-archive-preflight.mjs',
    'tests/saasBackend16NativeStableArchivePreflight.test.mjs',
    'docs/saas/BACKEND_16_P1_NATIVE_STABLE_PREFLIGHT.md',
  ])assert.ok(workflow.includes("      - '"+path+"'"),
    'Native TLS workflow must run when '+path+' changes');
  assert.ok(workflow.includes(
    'node --test tests/saasBackend16NativeStableArchivePreflight.test.mjs'));
  assert.ok(workflow.includes(
    'scripts/saas-staging/verify-backend16-native-tls-version-probe-ci.ts'));
  assert.doesNotMatch(workflow,/continue-on-error:|expected-failure:/);
  for(const marker of [
    'B16_NATIVE_SQL_TLS_ALWAYS_DENY_CALLBACK_',
    'B16_NATIVE_SQL_TLS_WRONG_ROOT_',
    'B16_NATIVE_SQL_TLS_CA_SIGNED_WILDCARD_',
  ])assert.ok(physical.includes(marker));
});
