/**
 * Backend16 P2 CI-only deterministic contract for a FUTURE Native Bun.SQL
 * server-only artifact. This is an unbuilt evidence plan, NOT a package,
 * executable, complete SBOM, upstream schema check or release authorization.
 * Missing evidence is an explicit blocker; self-asserted approvals are denied.
 */
import {createHash} from 'node:crypto';
import {
  closeSync,constants,fstatSync,lstatSync,openSync,readFileSync,
} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {
  buildBackend16NativeSourceCycloneDx,
} from './build-backend16-native-source-cyclonedx-ci.mjs';
import {
  verifyBackend16NativeSourceCycloneDxOffline,
} from './verify-backend16-native-source-cyclonedx-offline-ci.mjs';

const DENIED='Backend16 Native server artifact evidence contract refused';
const SCHEMA='backend16-native-server-artifact-evidence-contract-v1';
const SCOPE='P2_UNBUILT_SERVER_ARTIFACT_CONTRACT_ONLY';
const SOURCE_SCOPE='UNMOUNTED_NATIVE_TRANSPORT_AND_SECRET_CLIENTS_ONLY';
const SOURCE_INVENTORY='9a0e30c78d1c2d07ee3b4695cdfa1d570f5c8f0e2f75f2371b010a8edad5687c';
const SOURCE_CYCLONEDX='c8617a1c461757f3325909435693471df8253fde2044a313af6953c46ef199e3';
const MAX_POLICY_BYTES=4_096;
const EVIDENCE=Object.freeze([
  'officialStableBunReleaseTag',
  'stableBunFullSourceRevision',
  'stableBunArchiveSha512',
  'stableBunArchiveByteLength',
  'nativePeerIdentityPhysicalPg16ReceiptSha256',
  'serverOnlyPackageManifestSha256',
  'serverOnlyLockfileSha256',
  'reproducibleRuntimeDependencyGraphSha256',
  'serverEntrypointSha256',
  'oidcSessionAuthorityCompositionSha256',
  'offHostAuditBindingSha256',
  'reproducibleBuildRecipeSha256',
  'immutableServerExecutableSha256',
  'completeRuntimeSbomSha256',
  'signedBuildProvenanceSha256',
  'independentSecurityApprovalSha256',
  'independentOperationsApprovalSha256',
]);
const TARGET=Object.freeze({
  transport:'Native Bun.SQL',
  platform:'linux',
  architecture:'x64',
  productionNodePgFallback:false,
  frontendBundleIncluded:false,
  serverEntrypointBuilt:false,
});
const SOURCE=Object.freeze({
  scope:SOURCE_SCOPE,
  fileCount:7,
  sourceInventorySha256:SOURCE_INVENTORY,
  sourceCycloneDxSha256:SOURCE_CYCLONEDX,
  typeImportsIncluded:true,
});
const refuse=()=>{throw new Error(DENIED);};
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);

function exactRecord(obj,keys){
  if(!obj||typeof obj!=='object'||Array.isArray(obj)||
     Object.getPrototypeOf(obj)!==Object.prototype)refuse();
  const props=Object.getOwnPropertyDescriptors(obj);
  if(Object.keys(props).sort().join(',')!==[...keys].sort().join(',')||
     Object.values(props).some(d=>!('value' in d)))refuse();
}

/**
 * Checked-in v1 can ONLY describe missing evidence. Any claims of approved
 * runtime, complete package, signed provenance, or live release are refused.
 * Upgrading this schema requires a separately reviewed implementation and
 * out-of-band trust anchors, not writing an arbitrary checksum to the plan.
 */
export function assertBackend16NativeServerArtifactEvidencePolicy(policy){
  exactRecord(policy,[
    'schema','scope','target','sourceClosure','requiredEvidence',
    'releaseState','serverArtifactBuilt','stableRuntimeApproved',
    'stagingAuthorized','productionAuthorized',
  ]);
  exactRecord(policy.target,Object.keys(TARGET));
  exactRecord(policy.sourceClosure,Object.keys(SOURCE));
  exactRecord(policy.requiredEvidence,EVIDENCE);
  if(policy.schema!==SCHEMA||policy.scope!==SCOPE||
     !equal(policy.target,TARGET)||!equal(policy.sourceClosure,SOURCE)||
     policy.releaseState!=='BLOCKED_RELEASE'||
     policy.serverArtifactBuilt!==false||
     policy.stableRuntimeApproved!==false||
     policy.stagingAuthorized!==false||
     policy.productionAuthorized!==false||
     EVIDENCE.some(key=>policy.requiredEvidence[key]!==null))
    refuse();
  return true; // policy structure only; never release acceptance
}

function readPolicy(){
  const path=fileURLToPath(new URL(
    './backend16-native-server-artifact-evidence-contract.v1.json',
    import.meta.url));
  let fd,stat,opened,bytes;
  try{
    stat=lstatSync(path);
    if(!stat.isFile()||stat.isSymbolicLink()||(stat.mode&0o022)||
       stat.size<100||stat.size>MAX_POLICY_BYTES)refuse();
    fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
    opened=fstatSync(fd);
    if(!opened.isFile()||opened.dev!==stat.dev||
       opened.ino!==stat.ino||opened.size!==stat.size)refuse();
    bytes=readFileSync(fd);
    if(bytes.length!==stat.size)refuse();
  }catch{refuse();}
  finally{if(fd!==undefined)try{closeSync(fd);}catch{refuse();}}
  let policy;
  try{policy=JSON.parse(bytes.toString('utf8'));}catch{refuse();}
  // Fixed formatting makes policy drift visible, including duplicate keys.
  if(Buffer.from(JSON.stringify(policy,null,2)+'\n').compare(bytes)!==0)
    refuse();
  assertBackend16NativeServerArtifactEvidencePolicy(policy);
  return policy;
}

export function inspectBackend16NativeServerArtifactEvidenceContract(repoRoot){
  // Independently check the frozen seven-source input graph first. The two
  // verified source hashes are manually reviewed pins, not refreshed values.
  const bom=buildBackend16NativeSourceCycloneDx(repoRoot);
  const checked=verifyBackend16NativeSourceCycloneDxOffline(
    repoRoot,bom.bomJson,bom.bomSha256);
  if(bom.sourceInventorySha256!==SOURCE_INVENTORY||
     bom.bomSha256!==SOURCE_CYCLONEDX||
     checked.sourceInventorySha256!==SOURCE_INVENTORY||
     checked.bomSha256!==SOURCE_CYCLONEDX||
     checked.fileCount!==7||checked.productionAuthorized!==false)
    refuse();
  const policy=readPolicy();
  if(policy.sourceClosure.sourceInventorySha256!==bom.sourceInventorySha256||
     policy.sourceClosure.sourceCycloneDxSha256!==bom.bomSha256)
    refuse();

  // Hash only the reviewed structural proposal. No runtime, artifact, SBOM,
  // dependency install or signature has been produced or authenticated.
  return Object.freeze({
    result:'B16_NATIVE_SERVER_ARTIFACT_EVIDENCE_CONTRACT_CI_PASS',
    contractSha256:hash(JSON.stringify(policy)),
    sourceInventorySha256:bom.sourceInventorySha256,
    sourceCycloneDxSha256:bom.bomSha256,
    missingEvidence:Object.freeze([...EVIDENCE]),
    missingEvidenceCount:EVIDENCE.length,
    releaseState:'BLOCKED_RELEASE',
    serverArtifactBuilt:false,
    stableRuntimeApproved:false,
    stagingAuthorized:false,
    productionAuthorized:false,
  });
}

// No executable builder or release path. Strictly disposable Node24 CI;
// an ordinary direct run fails closed without a "success" marker.
if(process.argv[1]&&
   import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try{
    const e=process.env;
    if(process.argv.length!==2||e.CI!=='true'||
       e.GITHUB_ACTIONS!=='true'||
       process.versions.node.split('.')[0]!=='24'||
       process.platform!=='linux'||process.arch!=='x64'||
       e.NODE_ENV==='production'||e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
       Object.keys(e).some(k=>k.startsWith('RAILWAY_')&&e[k]))
      refuse();
    const receipt=inspectBackend16NativeServerArtifactEvidenceContract(
      fileURLToPath(new URL('../../',import.meta.url)));
    console.info(receipt.result);
    console.info('B16_NATIVE_SERVER_ARTIFACT_EVIDENCE_CONTRACT_SHA256='+
      receipt.contractSha256);
    console.info('B16_NATIVE_SERVER_ARTIFACT_MISSING_EVIDENCE_COUNT='+
      receipt.missingEvidenceCount);
    console.info('B16_NATIVE_SERVER_ARTIFACT_BLOCKED_RELEASE');
    console.info('NO RELEASE AUTHORIZATION');
  }catch{
    console.error('STOP Backend16 Native server artifact evidence contract refused');
    process.exitCode=1;
  }
}
