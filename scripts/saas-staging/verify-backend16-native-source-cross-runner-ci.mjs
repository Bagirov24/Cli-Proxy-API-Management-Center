/**
 * Backend16 P2: independent GitHub-hosted runners must reproduce the same
 * REVIEWED, UNMOUNTED source-only evidence on the exact PR HEAD.
 *
 * No Bun runtime, packages, build, executable, real DB, signatures,
 * full SBOM, live evidence, production or staging authorization.
 */
import {spawnSync} from 'node:child_process';
import {appendFileSync,lstatSync} from 'node:fs';
import {isAbsolute,relative,resolve,sep} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {
  inspectBackend16NativeServerArtifactEvidenceContract,
} from './verify-backend16-native-server-artifact-evidence-contract-ci.mjs';

const DENIED='Backend16 Native source cross-runner CI refused';
const REPO='Bagirov24/Cli-Proxy-API-Management-Center';
const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const SOURCE='9a0e30c78d1c2d07ee3b4695cdfa1d570f5c8f0e2f75f2371b010a8edad5687c';
const CYCLONEDX='c8617a1c461757f3325909435693471df8253fde2044a313af6953c46ef199e3';
const PLAN='df2aeac8f92113fb8896a099abd0d389e1674229a7ed71262e24bc68a8552186';
const HEX40=/^[0-9a-f]{40}$/;
const refuse=()=>{throw new Error(DENIED);};
const FIELD_NAMES=Object.freeze([
  'slot','head','event','checkout','source','cyclonedx','plan','state',
]);
const exactKeys=(x,keys)=>
  x&&typeof x==='object'&&!Array.isArray(x)&&
  (Object.getPrototypeOf(x)===Object.prototype||
   Object.getPrototypeOf(x)===null)&&
  Object.keys(x).sort().join(',')===[...keys].sort().join(',');

/** Reuse the independently reviewed source/BOM/contract verifiers. */
export function inspectBackend16NativeSourceCrossRunnerReceipt(repoRoot){
  const result=inspectBackend16NativeServerArtifactEvidenceContract(repoRoot);
  if(result.result!=='B16_NATIVE_SERVER_ARTIFACT_EVIDENCE_CONTRACT_CI_PASS'||
     result.sourceInventorySha256!==SOURCE||
     result.sourceCycloneDxSha256!==CYCLONEDX||
     result.contractSha256!==PLAN||
     result.missingEvidenceCount!==17||
     result.releaseState!=='BLOCKED_RELEASE'||
     result.stableRuntimeApproved!==false||
     result.serverArtifactBuilt!==false||
     result.stagingAuthorized!==false||
     result.productionAuthorized!==false)refuse();
  return Object.freeze({
    source:SOURCE,cyclonedx:CYCLONEDX,plan:PLAN,state:'BLOCKED_RELEASE',
  });
}

/** Check the actual hosted-job context, not a caller-selected repository. */
export function enforceBackend16NativeSourceCrossRunnerEnvironment(
  e,major,mode,checkout
){
  if(!e||typeof e!=='object'||!['record','compare'].includes(mode)||
     major!==24||e.CI!=='true'||e.GITHUB_ACTIONS!=='true'||
     e.GITHUB_EVENT_NAME!=='pull_request'||
     e.GITHUB_REPOSITORY!==REPO||
     e.RUNNER_OS!=='Linux'||e.RUNNER_ARCH!=='X64'||
     !/^refs\/pull\/[1-9]\d*\/merge$/.test(e.GITHUB_REF??'')||
     !HEX40.test(e.GITHUB_SHA??'')||
     !HEX40.test(e.B16_PR_HEAD_SHA??'')||
     !HEX40.test(checkout??'')||
     checkout!==e.B16_PR_HEAD_SHA||
     e.NODE_ENV==='production'||e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
     ['PGHOST','PGPASSWORD','PGUSER','DATABASE_URL','SAAS_B16_NATIVE_BUN_BIN',
      'SAAS_B16_EXPERIMENTAL_TLS_CI','SAAS_B16_LOCKED_FULL_CHAIN_CI']
       .some(k=>e[k]!==undefined&&e[k]!=='')||
     Object.keys(e).some(k=>k.startsWith('RAILWAY_')&&e[k]))
    refuse();
  if(mode==='record'){
    const slot=e.B16_NATIVE_REPRO_SLOT;
    if(!['A','B'].includes(slot)||
       e.GITHUB_JOB!==(slot==='A'?'proof_a':'proof_b')||
       !isAbsolute(e.RUNNER_TEMP??'')||
       !isAbsolute(e.GITHUB_OUTPUT??''))refuse();
    const rel=relative(e.RUNNER_TEMP,e.GITHUB_OUTPUT);
    if(!/^_runner_file_commands\/set_output_[0-9a-fA-F-]{8,}$/.test(
       rel.split(sep).join('/')))refuse();
  }else if(e.GITHUB_JOB!=='compare'||
           e.B16_NATIVE_REPRO_SLOT!==undefined)refuse();
  return true;
}

export function assertMatchingBackend16NativeSourceCrossRunnerProofs(
  a,b,head,event,checkout
){
  const valid=x=>exactKeys(x,FIELD_NAMES)&&
    ['A','B'].includes(x.slot)&&
    HEX40.test(x.head??'')&&HEX40.test(x.event??'')&&
    HEX40.test(x.checkout??'')&&
    x.source===SOURCE&&x.cyclonedx===CYCLONEDX&&x.plan===PLAN&&
    x.state==='BLOCKED_RELEASE';
  if(!valid(a)||!valid(b)||a===b||a.slot!=='A'||b.slot!=='B'||
     !HEX40.test(head??'')||!HEX40.test(event??'')||
     !HEX40.test(checkout??'')||
     a.head!==head||b.head!==head||
     a.event!==event||b.event!==event||
     a.checkout!==checkout||b.checkout!==checkout)
    refuse();
  return 'B16_NATIVE_SOURCE_CROSS_RUNNER_EXACT_HEAD_MATCH_PASS';
}

function checkoutSha(){
  const result=spawnSync('git',['rev-parse','HEAD'],{
    cwd:ROOT,encoding:'utf8',stdio:['ignore','pipe','pipe'],
    timeout:5_000,maxBuffer:2_048,
  });
  if(result.error||result.signal||result.status!==0||
     typeof result.stdout!=='string'||
     !HEX40.test(result.stdout.trim())||
     result.stderr!=='')refuse();
  return result.stdout.trim();
}
function record(){
  const e=process.env;
  const checkout=checkoutSha();
  enforceBackend16NativeSourceCrossRunnerEnvironment(
    e,Number(process.versions.node.split('.')[0]),'record',checkout);
  // Exclude arbitrary source paths, package installs, and unreviewed hashes.
  const evidence=inspectBackend16NativeSourceCrossRunnerReceipt(ROOT);
  const output={
    slot:e.B16_NATIVE_REPRO_SLOT,
    head:e.B16_PR_HEAD_SHA,
    event:e.GITHUB_SHA,
    checkout,
    ...evidence,
  };
  // The one GitHub-owned per-step file must not be a symlink.
  const st=lstatSync(e.GITHUB_OUTPUT);
  if(!st.isFile()||st.isSymbolicLink())refuse();
  appendFileSync(e.GITHUB_OUTPUT,
    Object.entries(output).map(([k,v])=>k+'='+v+'\n').join(''),
    {encoding:'utf8',flag:'a'});
  console.info('B16_NATIVE_SOURCE_CROSS_RUNNER_'+output.slot+
    '_SOURCE_ONLY_PASS');
  console.info('NO RELEASE AUTHORIZATION');
}
function compare(){
  const e=process.env;
  const checkout=checkoutSha();
  enforceBackend16NativeSourceCrossRunnerEnvironment(
    e,Number(process.versions.node.split('.')[0]),'compare',checkout);
  const proof=prefix=>Object.fromEntries(FIELD_NAMES.map(key=>
    [key,e[prefix+key.toUpperCase()]]));
  const marker=assertMatchingBackend16NativeSourceCrossRunnerProofs(
    proof('B16_PROOF_A_'),proof('B16_PROOF_B_'),
    e.B16_PR_HEAD_SHA,e.GITHUB_SHA,checkout,
  );
  const again=inspectBackend16NativeSourceCrossRunnerReceipt(ROOT);
  for(const [key,value] of Object.entries(again))
    if(proof('B16_PROOF_A_')[key]!==value)refuse();
  console.info(marker);
  console.info('B16_NATIVE_SOURCE_CROSS_RUNNER_SOURCE_SHA256='+again.source);
  console.info('B16_NATIVE_SOURCE_CROSS_RUNNER_CYCLONEDX_SHA256='+again.cyclonedx);
  console.info('B16_NATIVE_SOURCE_CROSS_RUNNER_CONTRACT_SHA256='+again.plan);
  console.info('B16_NATIVE_SOURCE_CROSS_RUNNER_BLOCKED_RELEASE');
  console.info('NO RELEASE AUTHORIZATION');
}
if(process.argv[1]&&
   import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try{
    if(process.argv.length!==3)refuse();
    if(process.argv[2]==='record')record();
    else if(process.argv[2]==='compare')compare();
    else refuse();
  }catch{
    console.error('STOP Backend16 Native source cross-runner CI refused');
    process.exitCode=1;
  }
}
