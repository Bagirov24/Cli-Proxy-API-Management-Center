/**
 * Backend16 fail-closed CI guard: every pinned Native Bun.SQL source module
 * must trigger the independent Native TLS acceptance, the complete physical
 * PG16/RLS acceptance, and source-only cross-runner reproducibility.
 *
 * This inspects workflow routing only. It is NOT a runtime, package,
 * full SBOM, signed provenance, production authorization or live receipt.
 */
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {
  assertBackend16NativeSourceClosurePolicy,
} from './verify-backend16-native-source-closure-ci.mjs';

const DENIED='Backend16 Native TLS source trigger coverage refused';
const SERVER='src/features/saasBlueprint/controlApi/server/';
const PHYSICAL_PROBE='scripts/saas-staging/verify-backend16-native-pg-tls-ci.ts';
const NATIVE_PROBE='scripts/saas-staging/verify-backend16-native-tls-version-probe-ci.ts';
const INSTALL='        run: node scripts/saas-staging/install-backend16-native-bun-ci.mjs';
const TEST='node --test tests/saasBackend16NativeTlsTriggerCoverageCi.test.mjs';
const NEW_FILES=Object.freeze([
  'scripts/saas-staging/verify-backend16-native-tls-trigger-coverage-ci.mjs',
  'tests/saasBackend16NativeTlsTriggerCoverageCi.test.mjs',
  'docs/saas/BACKEND_16_P2_NATIVE_TLS_TRIGGER_COVERAGE.md',
]);
const refuse=()=>{throw new Error(DENIED);};

/**
 * Narrow, strict parser for the actual Actions on.pull_request.paths block.
 * A path in a comment or in a run script must never count as a trigger.
 * Reject unsupported shapes rather than assuming YAML glob semantics.
 */
export function extractBackend16PullRequestPaths(source){
  if(typeof source!=='string'||source.length<100||
     source.length>180_000||source.includes('\r'))refuse();
  const anchor='on:\n  pull_request:\n    paths:\n';
  const offset=source.indexOf(anchor);
  if(offset<0||source.indexOf(anchor,offset+anchor.length)>=0)refuse();
  const entries=[];
  let closed=false;
  for(const line of source.slice(offset+anchor.length).split('\n')){
    if(line===''||/^ {6}#/.test(line))continue;
    // A sibling trigger or the next root-level YAML section ends paths.
    if(/^(?: {2})?[A-Za-z][A-Za-z0-9_-]*:/.test(line)){
      closed=true;
      break;
    }
    // Another pull_request setting cannot silently disable path routing.
    if(/^ {4}[A-Za-z][A-Za-z0-9_-]*:/.test(line))refuse();
    const item=/^ {6}- '([^']+)'$/.exec(line);
    if(!item||!/[A-Za-z]/.test(item[1])||
       !/^[A-Za-z0-9_./*-]+$/.test(item[1])||
       item[1].startsWith('/')||item[1].includes('..'))refuse();
    entries.push(item[1]);
  }
  if(!closed||entries.length<1||
     new Set(entries).size!==entries.length)refuse();
  return Object.freeze(entries);
}

/** Pure deterministic workflow + reviewed-closure policy assertion. */
export function assertBackend16NativeTlsSourceTriggerCoverage(
  native,physical,cross,policy
){
  try{assertBackend16NativeSourceClosurePolicy(policy);}catch{refuse();}
  const pNative=extractBackend16PullRequestPaths(native);
  const pPhysical=extractBackend16PullRequestPaths(physical);
  const pCross=extractBackend16PullRequestPaths(cross);
  const modules=policy.modules.map(entry=>SERVER+entry.file);
  if(modules.length!==7||policy.root!==SERVER.slice(0,-1)||
     modules.some(file=>!pNative.includes(file)||!pPhysical.includes(file))||
     !pCross.includes(SERVER+'backend16*.ts')||
     !modules.every(file=>/^src\/features\/saasBlueprint\/controlApi\/server\/backend16[A-Za-z0-9]+\.ts$/.test(file)))
    refuse();

  // The physical probe exercises the actual Native Bun.SQL source closure,
  // even though the independent Native probe has a narrower SQL smoke test.
  if(!pNative.includes(PHYSICAL_PROBE)||
     !pNative.includes(NATIVE_PROBE)||
     !pPhysical.includes('scripts/saas-staging/**')||
     !pNative.includes('.github/workflows/saas-backend16-native-tls-experiment.yml')||
     !pPhysical.includes('.github/workflows/saas-staging-rls-ci.yml')||
     !pCross.includes('.github/workflows/saas-backend16-native-source-repro-ci.yml'))
    refuse();
  for(const path of NEW_FILES){
    if(!pNative.includes(path)||!pPhysical.includes(path)||
       !pCross.includes(path))refuse();
  }

  // The new offline guard must run before the unchanged SHA512-pinned canary,
  // followed by the actual PostgreSQL16 negative TLS probe. No skip switches.
  const testAt=native.indexOf('          '+TEST);
  const installAt=native.indexOf(INSTALL);
  const probeAt=native.lastIndexOf(' scripts/saas-staging/verify-backend16-native-tls-version-probe-ci.ts');
  if(testAt<0||installAt<0||probeAt<0||
     !(testAt<installAt&&installAt<probeAt)||
     !native.includes('node --test tests/saasBackend16NativeSourceClosureCi.test.mjs')||
     !native.includes('CI=true node scripts/saas-staging/verify-backend16-native-server-artifact-evidence-contract-ci.mjs')||
     !native.includes('uses: actions/setup-node@v4')||
     !native.includes("node-version: '24'")||
     !native.includes('runs-on: ubuntu-24.04')||
     !native.includes('image: postgres:16.6')||
     !physical.includes('image: postgres:16.6')||
     !native.includes('permissions:\n  contents: read')||
     !cross.includes('permissions:\n  contents: read')||
     cross.split('          '+TEST).length!==4||
     [native,physical,cross].some(yml=>
       /continue-on-error:|expected-failure:|NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=true/.test(yml)))
    refuse();

  return Object.freeze({
    result:'B16_NATIVE_TLS_SOURCE_TRIGGER_COVERAGE_CI_PASS',
    moduleCount:modules.length,
    independentNativeTlsTriggered:true,
    physicalPg16Triggered:true,
    crossRunnerTriggered:true,
    stableRuntimeApproved:false,
    stagingAuthorized:false,
    productionAuthorized:false,
  });
}

if(process.argv[1]&&
   import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try{
    const e=process.env;
    if(process.argv.length!==2||e.CI!=='true'||
       e.GITHUB_ACTIONS!=='true'||process.versions.node.split('.')[0]!=='24'||
       process.platform!=='linux'||process.arch!=='x64'||
       e.NODE_ENV==='production'||e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
       Object.keys(e).some(k=>k.startsWith('RAILWAY_')&&e[k]))
      refuse();
    const fromRoot=file=>readFileSync(
      new URL('../../'+file,import.meta.url),'utf8');
    const sourcePolicy=JSON.parse(fromRoot(
      'scripts/saas-staging/backend16-native-server-source-closure.v1.json'));
    const result=assertBackend16NativeTlsSourceTriggerCoverage(
      fromRoot('.github/workflows/saas-backend16-native-tls-experiment.yml'),
      fromRoot('.github/workflows/saas-staging-rls-ci.yml'),
      fromRoot('.github/workflows/saas-backend16-native-source-repro-ci.yml'),
      sourcePolicy);
    console.info(result.result);
    console.info('B16_NATIVE_TLS_SOURCE_TRIGGER_MODULE_COUNT='+result.moduleCount);
    console.info('B16_NATIVE_TLS_SOURCE_TRIGGER_BLOCKED_RELEASE');
    console.info('NO RELEASE AUTHORIZATION');
  }catch{
    console.error('STOP Backend16 Native TLS source trigger coverage refused');
    process.exitCode=1;
  }
}
