import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {
  chmodSync,copyFileSync,mkdirSync,mkdtempSync,readFileSync,rmSync,
  symlinkSync,writeFileSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  buildBackend16NativeSourceCycloneDx,
} from '../scripts/saas-staging/build-backend16-native-source-cyclonedx-ci.mjs';
import {
  inspectBackend16NativeSourceClosure,
} from '../scripts/saas-staging/verify-backend16-native-source-closure-ci.mjs';

const ROOT=fileURLToPath(new URL('../',import.meta.url));
const SERVER='src/features/saasBlueprint/controlApi/server';
const read=path=>readFileSync(new URL(path,import.meta.url),'utf8');
const policy=JSON.parse(read(
  '../scripts/saas-staging/backend16-native-server-source-closure.v1.json'));
const refuse=fn=>assert.throws(fn,
  /Backend16 Native (?:Bun server source closure|source CycloneDX) CI refused/);

function inMirror(fn){
  const root=mkdtempSync(join(tmpdir(),'b16-cyclonedx-source-test-'));
  const server=join(root,SERVER);
  try{
    mkdirSync(server,{recursive:true});
    for(const item of policy.modules)
      copyFileSync(join(ROOT,SERVER,item.file),join(server,item.file));
    return fn(root,server);
  }finally{
    rmSync(root,{recursive:true,force:true});
  }
}

test('actual reviewed Native source yields a bounded CycloneDX 1.6 file BOM',()=>{
  const result=buildBackend16NativeSourceCycloneDx(ROOT);
  const bom=JSON.parse(result.bomJson);
  assert.equal(result.result,'B16_NATIVE_BUN_SOURCE_CYCLONEDX_CI_PASS');
  assert.equal(result.sourceInventorySha256,
    inspectBackend16NativeSourceClosure(ROOT).sourceInventorySha256);
  assert.deepEqual([
    bom.bomFormat,bom.specVersion,bom.version,
  ],['CycloneDX','1.6',1]);
  assert.equal(Object.hasOwn(bom,'serialNumber'),false);
  assert.equal(Object.hasOwn(bom.metadata,'timestamp'),false);
  assert.equal(result.fileCount,7);
  assert.equal(bom.components.length,7);
  assert.equal(bom.dependencies.length,7);
  assert.equal(new Set(bom.components.map(c=>c['bom-ref'])).size,7);
  assert.ok(bom.components.every(c=>
    c.type==='file'&&c.hashes.length===1&&
    c.hashes[0].alg==='SHA-256'&&/^[a-f0-9]{64}$/.test(c.hashes[0].content)));
  assert.equal(result.bomSha256,
    createHash('sha256').update(result.bomJson).digest('hex'));
  assert.ok(Object.isFrozen(result));
});

test('source type/value edges are traceable but never called runtime dependencies',()=>{
  const {bomJson}=buildBackend16NativeSourceCycloneDx(ROOT);
  const bom=JSON.parse(bomJson);
  const base='backend16-native-source:'+SERVER+'/';
  const actualNames=bom.components.map(c=>c.name);
  assert.deepEqual(actualNames,policy.modules.map(m=>SERVER+'/'+m.file));
  for(const entry of policy.modules){
    const dependency=bom.dependencies.find(d=>d.ref===base+entry.file);
    assert.ok(dependency,'missing source-only dependency: '+entry.file);
    const expected=[...new Set(entry.imports
      .filter(i=>i.specifier.startsWith('./'))
      .map(i=>base+i.specifier.slice(2).replace(/\.ts$/,'')+'.ts'))].sort();
    assert.deepEqual(dependency.dependsOn,expected);
  }
  const props=Object.fromEntries(bom.metadata.properties.map(p=>[p.name,p.value]));
  assert.equal(props['backend16:sourceEdgesIncludeTypeImports'],'true');
  assert.equal(props['backend16:sourceScope'],
    'UNMOUNTED_NATIVE_TRANSPORT_AND_SECRET_CLIENTS_ONLY');
  assert.equal(props['backend16:NOT_A_PRODUCTION_SBOM'],'true');
  assert.equal(props['backend16:serverArtifactBuilt'],'false');
  assert.equal(props['backend16:stableRuntimeApproved'],'false');
  assert.equal(props['backend16:productionAuthorized'],'false');
  assert.equal(props['backend16:sourceInventorySha256'],
    inspectBackend16NativeSourceClosure(ROOT).sourceInventorySha256);
  assert.equal(Object.hasOwn(bom,'metadata')&&Object.hasOwn(bom.metadata,'component'),false);
});

test('independent copied source inputs produce byte-identical deterministic BOM',()=>{
  const first=buildBackend16NativeSourceCycloneDx(ROOT);
  inMirror(root=>{
    const second=buildBackend16NativeSourceCycloneDx(root);
    assert.notEqual(first,second);
    assert.equal(first.bomJson,second.bomJson);
    assert.equal(first.bomSha256,second.bomSha256);
    assert.equal(first.sourceInventorySha256,second.sourceInventorySha256);
  });
});

test('changed bytes of every reviewed module fail, not auto-regenerate hashes',()=>{
  inMirror((root,server)=>{
    for(const entry of policy.modules){
      const path=join(server,entry.file);
      const old=readFileSync(path);
      const modified=Buffer.from(old);
      modified[Math.min(450,modified.length-1)]^=0x1;
      writeFileSync(path,modified);
      refuse(()=>buildBackend16NativeSourceCycloneDx(root));
      writeFileSync(path,old);
    }
    assert.equal(buildBackend16NativeSourceCycloneDx(root).fileCount,7);
  });
});

test('symlink, absent file and group-writable source deny BOM issuance',()=>{
  inMirror((root,server)=>{
    const path=join(server,policy.modules[0].file);
    chmodSync(path,0o666);
    refuse(()=>buildBackend16NativeSourceCycloneDx(root));
    chmodSync(path,0o644);
    rmSync(path);
    symlinkSync(policy.modules[1].file,path);
    refuse(()=>buildBackend16NativeSourceCycloneDx(root));
    rmSync(path);
    refuse(()=>buildBackend16NativeSourceCycloneDx(root));
  });
  refuse(()=>buildBackend16NativeSourceCycloneDx('relative/root'));
});

test('direct execution never exposes BOM or implies release outside guarded CI',()=>{
  const executable=fileURLToPath(new URL(
    '../scripts/saas-staging/build-backend16-native-source-cyclonedx-ci.mjs',
    import.meta.url));
  const rejected=spawnSync(process.execPath,[executable],{
    encoding:'utf8',timeout:5_000,
    env:{...process.env,CI:'false',GITHUB_ACTIONS:'false'},
  });
  assert.equal(rejected.status,1);
  assert.equal(rejected.stdout,'');
  assert.match(rejected.stderr,/STOP Backend16 Native source CycloneDX CI refused/);
  const source=read(
    '../scripts/saas-staging/build-backend16-native-source-cyclonedx-ci.mjs');
  assert.doesNotMatch(source,/\bfetch\s*\(|\bexecFileSync\s*\(/);
  assert.doesNotMatch(source,/NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=true/);
});

test('release invariants, Native TLS and full PG16 workflows cover BOM changes',()=>{
  const pkg=JSON.parse(read('../package.json'));
  const factory=read(
    '../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts');
  const native=read('../.github/workflows/saas-backend16-native-tls-experiment.yml');
  const physical=read('../.github/workflows/saas-staging-rls-ci.yml');
  const paths=[
    'scripts/saas-staging/build-backend16-native-source-cyclonedx-ci.mjs',
    'tests/saasBackend16NativeSourceCycloneDxCi.test.mjs',
    'docs/saas/BACKEND_16_P2_NATIVE_SOURCE_CYCLONEDX.md',
  ];
  assert.equal(pkg.packageManager,'bun@1.3.14');
  assert.ok(factory.includes(
    'const NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false;'));
  for(const flow of [native,physical]){
    for(const path of paths)assert.ok(flow.includes("      - '"+path+"'"),
      'required CI trigger missing for '+path);
  }
  assert.ok(native.includes(
    'node --test tests/saasBackend16NativeSourceCycloneDxCi.test.mjs'));
  assert.ok(native.includes(
    'node scripts/saas-staging/build-backend16-native-source-cyclonedx-ci.mjs'));
  assert.ok(native.includes('verify-backend16-native-tls-version-probe-ci.ts'));
  assert.ok(physical.includes('postgres:16.6'));
  assert.doesNotMatch(native,/continue-on-error:|expected-failure:/);
});
