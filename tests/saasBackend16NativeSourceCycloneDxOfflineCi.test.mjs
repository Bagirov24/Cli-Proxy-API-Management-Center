import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {buildBackend16NativeSourceCycloneDx} from '../scripts/saas-staging/build-backend16-native-source-cyclonedx-ci.mjs';
import {verifyBackend16NativeSourceCycloneDxOffline} from '../scripts/saas-staging/verify-backend16-native-source-cyclonedx-offline-ci.mjs';

const ROOT=fileURLToPath(new URL('../',import.meta.url));
const digest=s=>createHash('sha256').update(s).digest('hex');
const refuse=(s,checksum=digest(s))=>assert.throws(
  ()=>verifyBackend16NativeSourceCycloneDxOffline(ROOT,s,checksum),
  /Backend16 Native source CycloneDX offline verification refused/);
const mutate=(fn)=>{
  const output=buildBackend16NativeSourceCycloneDx(ROOT);
  const parsed=JSON.parse(output.bomJson);
  fn(parsed);
  refuse(JSON.stringify(parsed));
};
const read=path=>readFileSync(new URL(path,import.meta.url),'utf8');

test('independent verifier accepts reviewed source-only BOM but denies release',()=>{
  const bom=buildBackend16NativeSourceCycloneDx(ROOT);
  const result=verifyBackend16NativeSourceCycloneDxOffline(
    ROOT,bom.bomJson,bom.bomSha256);
  assert.equal(result.result,'B16_NATIVE_BUN_SOURCE_CYCLONEDX_OFFLINE_VERIFIED');
  assert.equal(result.sourceInventorySha256,bom.sourceInventorySha256);
  assert.equal(result.bomSha256,bom.bomSha256);
  assert.equal(result.fileCount,7);
  assert.equal(result.upstreamSchemaValidated,false);
  assert.equal(result.serverArtifactBuilt,false);
  assert.equal(result.stableRuntimeApproved,false);
  assert.equal(result.productionAuthorized,false);
  assert.ok(Object.isFrozen(result));
});

test('checksum and canonical JSON are strict, no embedded duplicate keys',()=>{
  const bom=buildBackend16NativeSourceCycloneDx(ROOT);
  refuse(bom.bomJson,'0'.repeat(64));
  refuse(bom.bomJson+'\n');
  refuse(bom.bomJson.replace('"version":1,','"version":1,"version":1,'));
  refuse(bom.bomJson.slice(0,200));
  refuse('{"__proto__":{}}');
  refuse('[]');
  refuse('x'.repeat(65_537));
  assert.throws(()=>verifyBackend16NativeSourceCycloneDxOffline(
    'relative',bom.bomJson,bom.bomSha256));
});

test('reject unknown or spoofed CycloneDX metadata and release flags',()=>{
  mutate(b=>{b.specVersion='1.5';});
  mutate(b=>{b.metadata.properties[3].value='false';});
  mutate(b=>{b.metadata.properties[5].value='true';});
  mutate(b=>{b.metadata.properties[1].value='0'.repeat(64);});
  mutate(b=>{b.metadata.component={type:'application',name:'server'};});
  mutate(b=>{b.serialNumber='urn:uuid:fake';});
  mutate(b=>{b.components[0].type='application';});
  mutate(b=>{b.components[0].properties.push({name:'release',value:'approved'});});
});

test('reject missing, duplicated or dangling refs and unreviewed graph edges',()=>{
  mutate(b=>{b.components.pop();});
  mutate(b=>{b.components[1]['bom-ref']=b.components[0]['bom-ref'];});
  mutate(b=>{b.components[2].name=b.components[0].name;});
  mutate(b=>{b.dependencies[0].ref=b.dependencies[1].ref;});
  mutate(b=>{b.dependencies[0].dependsOn.push('missing:module');});
  mutate(b=>{b.dependencies[0].dependsOn=[];});
  mutate(b=>{b.dependencies[0].dependsOn.reverse();});
  mutate(b=>{b.dependencies[1].dependsOn.push(b.dependencies[1].ref);});
  mutate(b=>{b.dependencies.pop();});
  mutate(b=>{b.dependencies[0].extra='unreviewed';});
});

test('reject altered source digests, byte lengths and reordered components',()=>{
  mutate(b=>{b.components[0].hashes[0].content='f'.repeat(64);});
  mutate(b=>{b.components[0].hashes[0].alg='SHA-1';});
  mutate(b=>{b.components[0].properties[0].value='a'.repeat(40);});
  mutate(b=>{b.components[0].properties[1].value='999';});
  mutate(b=>{b.components.reverse();});
  mutate(b=>{b.dependencies.reverse();});
  mutate(b=>{b.components[0].hashes.push(b.components[0].hashes[0]);});
});

test('direct invocation fails closed, no release or network operations',()=>{
  const file=fileURLToPath(new URL(
    '../scripts/saas-staging/verify-backend16-native-source-cyclonedx-offline-ci.mjs',
    import.meta.url));
  const run=spawnSync(process.execPath,[file],{encoding:'utf8',timeout:5000});
  assert.equal(run.status,1);
  assert.equal(run.stdout,'');
  assert.match(run.stderr,/STOP Backend16 Native source CycloneDX/);
  const src=read('../scripts/saas-staging/verify-backend16-native-source-cyclonedx-offline-ci.mjs');
  assert.doesNotMatch(src,/\bfetch\s*\(|\bexecFileSync\s*\(/);
  assert.doesNotMatch(src,/NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=true/);
});

test('both security workflows trigger on verifier, tests and documentation',()=>{
  const paths=[
    'scripts/saas-staging/verify-backend16-native-source-cyclonedx-offline-ci.mjs',
    'tests/saasBackend16NativeSourceCycloneDxOfflineCi.test.mjs',
    'docs/saas/BACKEND_16_P2_NATIVE_SOURCE_CYCLONEDX_OFFLINE.md',
  ];
  for(const workflow of [
    read('../.github/workflows/saas-backend16-native-tls-experiment.yml'),
    read('../.github/workflows/saas-staging-rls-ci.yml'),
  ]){
    for(const path of paths)assert.ok(workflow.includes("      - '"+path+"'"),path);
    assert.doesNotMatch(workflow,/continue-on-error:|expected-failure:/);
  }
  const native=read('../.github/workflows/saas-backend16-native-tls-experiment.yml');
  assert.ok(native.includes('node --test tests/saasBackend16NativeSourceCycloneDxOfflineCi.test.mjs'));
  assert.ok(native.includes('verify-backend16-native-tls-version-probe-ci.ts'));
  assert.equal(JSON.parse(read('../package.json')).packageManager,'bun@1.3.14');
  assert.ok(read('../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts')
    .includes('const NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false;'));
});
