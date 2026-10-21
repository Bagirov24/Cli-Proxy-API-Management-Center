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
  assertBackend16NativeServerArtifactEvidencePolicy,
  inspectBackend16NativeServerArtifactEvidenceContract,
} from '../scripts/saas-staging/verify-backend16-native-server-artifact-evidence-contract-ci.mjs';
import {buildBackend16NativeSourceCycloneDx} from
  '../scripts/saas-staging/build-backend16-native-source-cyclonedx-ci.mjs';

const ROOT=fileURLToPath(new URL('../',import.meta.url));
const SERVER='src/features/saasBlueprint/controlApi/server';
const read=path=>readFileSync(new URL(path,import.meta.url),'utf8');
const plan=JSON.parse(read(
  '../scripts/saas-staging/backend16-native-server-artifact-evidence-contract.v1.json'));
const sources=JSON.parse(read(
  '../scripts/saas-staging/backend16-native-server-source-closure.v1.json')).modules;
const refused=fn=>assert.throws(fn,
  /Backend16 Native (?:server artifact evidence contract|source CycloneDX|Bun server source closure) (?:CI )?refused/);
const mutate=fn=>{
  const draft=structuredClone(plan);
  fn(draft);
  refused(()=>assertBackend16NativeServerArtifactEvidencePolicy(draft));
};
function inMirror(fn){
  const root=mkdtempSync(join(tmpdir(),'b16-artifact-plan-test-'));
  const server=join(root,SERVER);
  try{
    mkdirSync(server,{recursive:true});
    for(const entry of sources)
      copyFileSync(join(ROOT,SERVER,entry.file),join(server,entry.file));
    return fn(root,server);
  }finally{
    rmSync(root,{recursive:true,force:true});
  }
}

test('frozen seven-file inputs yield deterministic release-blocked contract',()=>{
  const result=inspectBackend16NativeServerArtifactEvidenceContract(ROOT);
  const inventory=buildBackend16NativeSourceCycloneDx(ROOT);
  assert.equal(result.result,'B16_NATIVE_SERVER_ARTIFACT_EVIDENCE_CONTRACT_CI_PASS');
  assert.equal(result.sourceInventorySha256,inventory.sourceInventorySha256);
  assert.equal(result.sourceCycloneDxSha256,inventory.bomSha256);
  assert.equal(result.contractSha256,
    createHash('sha256').update(JSON.stringify(plan)).digest('hex'));
  assert.equal(result.missingEvidenceCount,17);
  assert.equal(result.missingEvidence.length,17);
  assert.equal(new Set(result.missingEvidence).size,17);
  assert.deepEqual(result.missingEvidence,Object.keys(plan.requiredEvidence));
  assert.ok(result.missingEvidence.every(k=>plan.requiredEvidence[k]===null));
  assert.equal(result.releaseState,'BLOCKED_RELEASE');
  assert.equal(result.serverArtifactBuilt,false);
  assert.equal(result.stableRuntimeApproved,false);
  assert.equal(result.stagingAuthorized,false);
  assert.equal(result.productionAuthorized,false);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.missingEvidence));
  inMirror(root=>{
    assert.deepEqual(
      inspectBackend16NativeServerArtifactEvidenceContract(root),result);
  });
});

test('stable runtime pins, server build, lock, SBOM and provenance remain missing',()=>{
  assert.equal(assertBackend16NativeServerArtifactEvidencePolicy(plan),true);
  for(const name of Object.keys(plan.requiredEvidence))
    mutate(p=>{p.requiredEvidence[name]='a'.repeat(64);});
  mutate(p=>{delete p.requiredEvidence.officialStableBunReleaseTag;});
  mutate(p=>{p.requiredEvidence.unknownField=null;});
  mutate(p=>{p.requiredEvidence.signedBuildProvenanceSha256='unsigned';});
  mutate(p=>{p.requiredEvidence.completeRuntimeSbomSha256='incomplete';});
  mutate(p=>{p.requiredEvidence.serverOnlyLockfileSha256=0;});
});

test('reject fabricated approval, stable runtime, executable or listener claims',()=>{
  mutate(p=>{p.productionAuthorized=true;});
  mutate(p=>{p.stagingAuthorized=true;});
  mutate(p=>{p.stableRuntimeApproved=true;});
  mutate(p=>{p.serverArtifactBuilt=true;});
  mutate(p=>{p.releaseState='APPROVED';});
  mutate(p=>{p.target.serverEntrypointBuilt=true;});
  mutate(p=>{p.target.productionNodePgFallback=true;});
  mutate(p=>{p.target.frontendBundleIncluded=true;});
  mutate(p=>{p.target.platform='darwin';});
  mutate(p=>{p.target.architecture='arm64';});
  mutate(p=>{p.target.transport='Node24 pg';});
  mutate(p=>{p.target.publicListener=true;});
  mutate(p=>{p.operatorSignature='fake';});
});

test('refuse wrong graph, altered source policy and cyclic/unknown inventory',()=>{
  mutate(p=>{p.sourceClosure.fileCount=8;});
  mutate(p=>{p.sourceClosure.sourceInventorySha256='0'.repeat(64);});
  mutate(p=>{p.sourceClosure.sourceCycloneDxSha256='f'.repeat(64);});
  mutate(p=>{p.sourceClosure.typeImportsIncluded=false;});
  mutate(p=>{p.sourceClosure.scope='FULL_PRODUCTION_SBOM';});
  mutate(p=>{p.sourceClosure.lockSha256='0'.repeat(64);});
  mutate(p=>{p.schema='backend16-native-server-artifact-evidence-contract-v2';});
  mutate(p=>{p.scope='PRODUCTION_RELEASE';});
  refused(()=>assertBackend16NativeServerArtifactEvidencePolicy(null));
  refused(()=>assertBackend16NativeServerArtifactEvidencePolicy(
    Object.assign(Object.create({schema:plan.schema}),plan)));
});

test('changed source bytes and symlinks deny contract even with matching plan',()=>{
  inMirror((root,server)=>{
    const path=join(server,sources[0].file);
    const original=readFileSync(path);
    const modified=Buffer.from(original);
    modified[25]^=1;
    writeFileSync(path,modified);
    refused(()=>inspectBackend16NativeServerArtifactEvidenceContract(root));
    writeFileSync(path,original);
    chmodSync(path,0o666);
    refused(()=>inspectBackend16NativeServerArtifactEvidenceContract(root));
    chmodSync(path,0o644);
    rmSync(path);
    symlinkSync(sources[1].file,path);
    refused(()=>inspectBackend16NativeServerArtifactEvidenceContract(root));
  });
  refused(()=>inspectBackend16NativeServerArtifactEvidenceContract('relative'));
});

test('unauthorized execution cannot certify a Bun server release',()=>{
  const code=fileURLToPath(new URL(
    '../scripts/saas-staging/verify-backend16-native-server-artifact-evidence-contract-ci.mjs',
    import.meta.url));
  const cmd=spawnSync(process.execPath,[code],{
    encoding:'utf8',timeout:5000,
    env:{...process.env,CI:'false',GITHUB_ACTIONS:'false'},
  });
  assert.equal(cmd.status,1);
  assert.equal(cmd.stdout,'');
  assert.match(cmd.stderr,/STOP Backend16 Native server artifact evidence contract refused/);
  const src=read(
    '../scripts/saas-staging/verify-backend16-native-server-artifact-evidence-contract-ci.mjs');
  assert.doesNotMatch(src,/\bfetch\s*\(|\bexecFileSync\s*\(|\bspawnSync\s*\(/);
  assert.doesNotMatch(src,/NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=true/);
});

test('Native TLS and physical PG16 workflows trigger all artifact-contract edits',()=>{
  const paths=[
    'scripts/saas-staging/backend16-native-server-artifact-evidence-contract.v1.json',
    'scripts/saas-staging/verify-backend16-native-server-artifact-evidence-contract-ci.mjs',
    'tests/saasBackend16NativeServerArtifactEvidenceContractCi.test.mjs',
    'docs/saas/BACKEND_16_P2_NATIVE_SERVER_ARTIFACT_CONTRACT.md',
  ];
  const native=read('../.github/workflows/saas-backend16-native-tls-experiment.yml');
  const physical=read('../.github/workflows/saas-staging-rls-ci.yml');
  for(const flow of [native,physical]){
    for(const path of paths)assert.ok(flow.includes("      - '"+path+"'"),path);
    assert.doesNotMatch(flow,/continue-on-error:|expected-failure:/);
  }
  assert.ok(native.includes('node --test tests/saasBackend16NativeServerArtifactEvidenceContractCi.test.mjs'));
  assert.ok(native.includes('CI=true node scripts/saas-staging/verify-backend16-native-server-artifact-evidence-contract-ci.mjs'));
  assert.ok(native.includes('verify-backend16-native-tls-version-probe-ci.ts'));
  assert.ok(physical.includes('postgres:16.6'));
  assert.equal(JSON.parse(read('../package.json')).packageManager,'bun@1.3.14');
  assert.ok(read('../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts')
    .includes('const NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false;'));
});
