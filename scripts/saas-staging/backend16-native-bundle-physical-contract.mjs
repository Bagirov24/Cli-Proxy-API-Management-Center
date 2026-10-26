/** Disposable emitted-library proof only. Nothing here authorizes a release. */
import {isAbsolute, resolve} from 'node:path';
import {isDeepStrictEqual} from 'node:util';
import {
  gitBlob, sha256, isolatedEnvironment, SOURCE_INVENTORY_SHA256,
} from './backend16-native-package-contract.mjs';
import {
  COMBINED_REVISION, assertCombinedEnvironment, combinedChildEnvironment,
} from './backend16-stable-144-combined-contract.mjs';

// Independently inspected PR107 A/B bytes. Never refresh these from a build result.
export const BUNDLE_SHA256='21ae8f82c05ff2b8a3ae2e096f7d1262107fd5e924bf3212ad3c354ebea9cd56';
export const BUNDLE_BYTES=59771;
export const RUNTIME_SHA256='10702245766b225e70bbf6235fd6b47214fd94b4760d00ffaed8ab0df57ac235';
export const INPUT_SHA256='df6943ecb1da2d395f362d44d988a18fc7afd7bde371916d93de9f0e68250379';
export const CHILD_BLOB='d51205e37bf0c07827e448f469e78b850821f8a9';
export const ORIGINAL_SUPERVISOR_BLOB='7c36338dbc96557d4df991acd5739a34a46ba542';
export const BUILD=Object.freeze(['build','./index.ts','--target=bun','--format=esm',
  '--packages=bundle','--outfile=./dist/transport.js']);
export const BUNDLE_MARKERS=Object.freeze([
  'B16_EMITTED_BUNDLE_MTLS_TWO_TENANT_TLS_RLS_PID_PASS',
  'B16_EMITTED_BUNDLE_WRONG_VERSION_EXPIRED_PREAUTH_DENY',
  'B16_EMITTED_BUNDLE_REVOKED_IN_FLIGHT_PREAUTH_DENY',
  'B16_EMITTED_BUNDLE_LOCK_ABORT_PID_DEATH_QUARANTINE_PASS',
  'B16_EMITTED_BUNDLE_WRONG_PG_ROOT_DENIED',
  'B16_EMITTED_BUNDLE_12_FRESH_BROKER_READS_PASS',
  'B16_EMITTED_BUNDLE_SOURCE_REMOVED_BEFORE_EXECUTION_PASS',
  'B16_EMITTED_BUNDLE_BLOCKED_RELEASE',
]);
export const SUPERVISOR_ADDITION=[
  '    // Extra emitted-only proof; original source scenario and assertions stay mandatory.',
  "    const {runBundledPhysicalCi}=await import('./verify-backend16-native-bundle-physical-ci.mjs');",
  '    await runBundledPhysicalCi(root,e);',
].join('\n')+'\n';
export const stop=()=>{throw Error('Backend16 emitted bundle physical CI refused');};

export function assertBundleEnvironment(e,major,platform,arch,head){
  assertCombinedEnvironment(e,major,head);
  if(platform!=='linux'||arch!=='x64'||
     !/^[1-9][0-9]{0,19}$/.test(e.GITHUB_RUN_ID??'')||
     !/^[1-9][0-9]{0,5}$/.test(e.GITHUB_RUN_ATTEMPT??'')||
     !isAbsolute(e.RUNNER_TEMP??'')||resolve(e.RUNNER_TEMP)!==e.RUNNER_TEMP||
     ['NODE_OPTIONS','NODE_PATH','BUN_OPTIONS','BUN_PRELOAD','LD_PRELOAD','LD_LIBRARY_PATH',
       'NODE_EXTRA_CA_CERTS','SSL_CERT_FILE','SSL_CERT_DIR'].some(k=>e[k]))stop();
  return true;
}
export function bundleChildEnvironment(e,stage){
  return Object.freeze({...combinedChildEnvironment(e),...isolatedEnvironment(stage)});
}

/** Only import bindings change; EVERY byte from let phase onward is retained. */
export function emittedHarness(bytes){
  if(!Buffer.isBuffer(bytes)||gitBlob(bytes)!==CHILD_BLOB)stop();
  const original=bytes.toString('utf8');
  let text=original;
  const replace=(before,after)=>{
    if(text.split(before).length!==2)stop();
    text=text.replace(before,after);
  };
  replace("import {COMBINED_REVISION} from './backend16-stable-144-combined-contract.mjs';",
    "import {transport} from './transport.js';\nconst COMBINED_REVISION='"+COMBINED_REVISION+"';");
  const prefix='../../src/features/saasBlueprint/controlApi/server/';
  for(const [symbol,file,space] of [
    ['createBackend16DisposableCiMtlsSecretReader','backend16PrivateMtlsVersionedSecretReader.ts','secretReader'],
    ['createBackend16StagingVersionedPrincipalVault','backend16StagingVersionedPrincipalVault.ts','vault'],
    ['createBackend16StagingDisposableCiTlsPhysicalPgPool','backend16StagingBunPhysicalPgPool.ts','physicalPool'],
    ['createBackend16StagingPgTlsTrust','backend16StagingPgTlsTrust.ts','tlsTrust'],
  ])replace('import {'+symbol+"}\n  from '"+prefix+file+"';",
    'const {'+symbol+'}=transport.'+space+';');
  replace("import {createBackend16ExactSqlReadPort,BACKEND16_EXACT_READ_SQL as Q}\n  from '"+
    prefix+"backend16ExactSessionSqlRead.ts';",
    'const {createBackend16ExactSqlReadPort,BACKEND16_EXACT_READ_SQL:Q}=transport.exactRead;');
  replace("import type {VerifiedPrincipal}\n  from '"+prefix+"backend16PrivateTenantProjectRead.ts';",
    'type VerifiedPrincipal=Parameters<ReturnType<typeof createBackend16ExactSqlReadPort>>[0];');
  const start="let phase='ENVIRONMENT';";
  if(original.split(start).length!==2||text.split(start).length!==2||
     original.slice(original.indexOf(start))!==text.slice(text.indexOf(start))||
     text.includes('../../src/')||text.includes('combined-contract.mjs'))stop();
  const imports=[...text.matchAll(/\bfrom ['"]([^'"]+)['"]/g)].map(x=>x[1]);
  if(!isDeepStrictEqual(imports,['node:assert/strict','node:child_process','node:crypto',
    'node:fs','node:os','node:path','node:readline','bun','./transport.js']))stop();
  return Buffer.from(text);
}
export function assertBuiltBundle(bytes){
  if(!Buffer.isBuffer(bytes)||bytes.length!==BUNDLE_BYTES||sha256(bytes)!==BUNDLE_SHA256)stop();
  return true;
}
export function assertRuntimeBytes(bytes){
  if(!Buffer.isBuffer(bytes)||bytes.length<20_000_000||bytes.length>240_000_000||
     sha256(bytes)!==RUNTIME_SHA256)stop();
  return true;
}
const FIXED_RECEIPT={
  schema:'backend16-emitted-library-physical-ci-v1',
  sourceInventorySha256:SOURCE_INVENTORY_SHA256,
  inputSha256:INPUT_SHA256,runtimeRevision:COMBINED_REVISION,runtimeSha256:RUNTIME_SHA256,
  bundleSha256:BUNDLE_SHA256,bundleBytes:BUNDLE_BYTES,harnessSourceGitBlob:CHILD_BLOB,
  brokerRequests:12,brokerRequestsA:8,brokerRequestsB:4,credentialReleases:9,
  sourceRemovedBeforeExecution:true,physicalBundleIntegrationPassed:true,
  packageManagerLockVerified:false,serverEntrypointBuilt:false,
  stableRuntimeApproved:false,productionAuthorized:false,releaseState:'BLOCKED_RELEASE',
};
export function makeBundleReceipt(headSha,runId,runAttempt,harnessSha256,recipeSha256){
  const value={...FIXED_RECEIPT,headSha,runId,runAttempt,harnessSha256,recipeSha256};
  assertBundleReceipt(value,{headSha,runId,runAttempt});
  return Object.freeze(value);
}
export function assertBundleReceipt(value,expected){
  if(!value||Object.getPrototypeOf(value)!==Object.prototype||
     Reflect.ownKeys(value).some(k=>typeof k!=='string')||
     Object.values(Object.getOwnPropertyDescriptors(value)).some(d=>!('value' in d)))stop();
  const keys=[...Object.keys(FIXED_RECEIPT),'headSha','runId','runAttempt','harnessSha256','recipeSha256'];
  if(!isDeepStrictEqual(Object.keys(value).sort(),keys.sort()))stop();
  for(const [k,v] of Object.entries(FIXED_RECEIPT))if(value[k]!==v)stop();
  for(const k of ['headSha','runId','runAttempt'])if(value[k]!==expected[k])stop();
  if(!/^[a-f0-9]{40}$/.test(value.headSha)||
     !/^[1-9][0-9]{0,19}$/.test(value.runId)||!/^[1-9][0-9]{0,5}$/.test(value.runAttempt))stop();
  for(const k of ['harnessSha256','recipeSha256'])
    if(!/^[a-f0-9]{64}$/.test(value[k])||value[k]==='0'.repeat(64))stop();
  return true;
}

/** Select only bounded, canonical, current-run evidence; never echo raw logs. */
export function parseBundleLog(text,expected){
  if(typeof text!=='string'||Buffer.byteLength(text)>65536)stop();
  const lines=text.split('\n');
  for(const marker of BUNDLE_MARKERS)if(lines.filter(x=>x===marker).length!==1)stop();
  const prefix='B16_EMITTED_BUNDLE_RECEIPT=';
  const records=lines.filter(x=>x.startsWith(prefix));
  if(records.length!==1||records[0].length>4096)stop();
  const raw=records[0].slice(prefix.length);
  let value;try{value=JSON.parse(raw);}catch{stop();}
  if(JSON.stringify(value)!==raw)stop();
  assertBundleReceipt(value,expected);
  return Object.freeze(value);
}
