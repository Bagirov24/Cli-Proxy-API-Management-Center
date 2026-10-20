/**
 * Backend16 Node24 CI-only supply-chain acceptance:
 *  - obtain a genuine npm v3 dependency lock in a disposable temp directory;
 *  - verify pinned dependency graph against our offline security contract;
 *  - npm ci from that generated lock with ALL lifecycle scripts disabled;
 *  - delete all generated manifests, tarballs and npm lock from the runner.
 *
 * This never installs to the repository, adds a runtime driver or approves
 * the use of npm as a production package manager. NOT a release gate.
 */
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {
  EXPECTED_NAME,EXPECTED_PG_VERSION,verifyBackend16NodePgRuntimePackage,
} from './verify-backend16-nodepg-runtime-lock.mjs';

const REGISTRY='https://registry.npmjs.org';
const DENIED='Backend16 genuine NodePG CI lock refused';
/**
 * Observed, unsigned CI-only historical graph from Draft PR #84.
 * Receipt: https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39422435534
 * No security approval or artifact signature is conferred by this hash.
 * Any registry drift must block until independently investigated.
 */
export const OBSERVED_NODEPG_GRAPH=Object.freeze({
  algorithm:'sha256-canonical-json-v1',
  dependency:'pg@8.23.1',
  packageCount:14,
  sha256:'b5e2aa1735babcbca40748c0983a73c36c57488f96d857fd4087ae4e7a5341fa',
});
const ROOT=fileURLToPath(new URL('../../',import.meta.url));
export const LOCK_ARGS=Object.freeze([
  'install','--package-lock-only','--ignore-scripts','--omit=dev',
  '--no-audit','--no-fund','--no-progress','--registry='+REGISTRY,
]);
export const CLEAN_INSTALL_ARGS=Object.freeze([
  'ci','--ignore-scripts','--omit=dev',
  '--no-audit','--no-fund','--no-progress','--registry='+REGISTRY,
]);
function refuse(){throw new Error(DENIED);}
export function enforceBackend16GenuineLockCiEnvironment(e,nodeMajor){
  if(!e||e.GITHUB_ACTIONS!=='true'||e.CI!=='true'||nodeMajor!==24||
     e.NODE_ENV==='production'||e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
     e.RAILWAY_PROJECT_ID||e.RAILWAY_ENVIRONMENT_ID||
     e.RAILWAY_SERVICE_ID||e.RAILWAY_ENVIRONMENT||
     e.RAILWAY_ENVIRONMENT_NAME||e.RAILWAY_PROJECT_NAME)refuse();
}
export function createBackend16GenuineLockCiManifest(){
  return {
    name:EXPECTED_NAME,
    version:'0.0.0',
    private:true,
    type:'module',
    engines:{node:'24.x'},
    dependencies:{pg:EXPECTED_PG_VERSION},
  };
}
function boundedJson(file,maxBytes=1_000_000){
  let data;
  try{data=readFileSync(file);}catch{refuse();}
  if(data.length<1||data.length>maxBytes)refuse();
  try{return JSON.parse(data.toString('utf8'));}
  catch{refuse();}
}
export function safeNpmFailureCode(stderr,systemError){
  const recognized=new Set([
    'EAI_AGAIN','ENOTFOUND','ETIMEDOUT','ECONNRESET','ECONNREFUSED',
    'EACCES','EPERM','ENOENT','EUSAGE','ERESOLVE','E404','E403',
    'CERT_HAS_EXPIRED','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  ]);
  const raw=String(systemError?.code||'')||String(
    String(stderr||'').match(/(?:npm (?:error|ERR!) code)\s+([A-Z0-9_]+)/i)?.[1]||'');
  const code=raw.toUpperCase();
  return recognized.has(code)?code:'UNCLASSIFIED';
}
/**
 * Compare genuine independent resolutions, not merely two installs sharing
 * the same generated lock. Key ordering in npm JSON is immaterial; graph
 * metadata, registry tarball origins, versions and SRI must be identical.
 * Each input is separately validated before entering this function in CI.
 */
function stableJson(value,depth=0){
  if(depth>32)refuse();
  if(value===null||typeof value==='string'||typeof value==='boolean'||
     (typeof value==='number'&&Number.isFinite(value)))
    return JSON.stringify(value);
  if(Array.isArray(value))
    return '['+value.map(item=>stableJson(item,depth+1)).join(',')+']';
  if(!value||typeof value!=='object'||
     Object.getPrototypeOf(value)!==Object.prototype)refuse();
  return '{'+Object.keys(value).sort().map(key=>
    JSON.stringify(key)+':'+stableJson(value[key],depth+1)).join(',')+'}';
}
export function assertIndependentBackend16NodePgLocks(first,second){
  const a=stableJson(first);
  const b=stableJson(second);
  if(a!==b)refuse();
  return createHash('sha256').update(a).digest('hex');
}
/**
 * Enforce the historical, separately observed canonical graph from #84
 * BEFORE either clean install. This is drift detection, not code-signing.
 */
export function assertObservedBackend16NodePgGraph(sha256,packageCount){
  if(typeof sha256!=='string'||!(/^[0-9a-f]{64}$/).test(sha256)||
     sha256!==OBSERVED_NODEPG_GRAPH.sha256||
     !Number.isSafeInteger(packageCount)||
     packageCount!==OBSERVED_NODEPG_GRAPH.packageCount)refuse();
  return 'B16_REAL_LOCK_CI_OBSERVED_GRAPH_MATCH_PASS';
}
function runNpm(args,dir){
  const minimalEnv={
    PATH:process.env.PATH||'/usr/local/bin:/usr/bin:/bin',
    HOME:dir,
    TMPDIR:dir,
    LANG:'C',
    CI:'true',
    NO_UPDATE_NOTIFIER:'1',
    npm_config_cache:join(dir,'npm-cache'),
    npm_config_userconfig:join(dir,'empty-user.npmrc'),
    npm_config_globalconfig:join(dir,'empty-global.npmrc'),
    npm_config_ignore_scripts:'true',
    npm_config_audit:'false',
    npm_config_fund:'false',
    npm_config_registry:REGISTRY,
  };
  // Never print raw npm errors: registry/client output may include paths,
  // request metadata or untrusted package-supplied text.
  const p=spawnSync('npm',[...args],{
    cwd:dir,env:minimalEnv,encoding:'utf8',
    stdio:['ignore','pipe','pipe'],
    timeout:120_000,maxBuffer:2_000_000,
  });
  if(p.error||p.status!==0||p.signal){
    const phase=args[0]==='install'?'RESOLVE':'CLEAN_INSTALL';
    console.error('B16_REAL_LOCK_CI_NPM_'+phase+'_FAIL_'+
      safeNpmFailureCode(p.stderr,p.error));
    refuse();
  }
}
async function main(){
  enforceBackend16GenuineLockCiEnvironment(
    process.env,Number(process.versions.node.split('.')[0]));
  if(existsSync(join(ROOT,'package-lock.json')))refuse();
  const frontend=boundedJson(join(ROOT,'package.json'));
  if(frontend.name!=='cli-proxy-webui-react'||
     frontend.packageManager!=='bun@1.3.14'||
     !existsSync(join(ROOT,'bun.lock')))refuse();
  const rootDir=mkdtempSync(join(tmpdir(),'b16-nodepg-dual-lock-ci-'));
  try{
    const pkg=createBackend16GenuineLockCiManifest();
    const dirs=[join(rootDir,'independent-a'),join(rootDir,'independent-b')];
    const receipts=[];
    console.info('B16_REAL_LOCK_CI_RESOLUTION_START');
    for(const dir of dirs){
      mkdirSync(dir,{mode:0o700});
      // Independent HOME, cache, manifest and lock: neither registry
      // resolution can consult the other's npm cache or package-lock.
      writeFileSync(join(dir,'empty-user.npmrc'),'',{mode:0o600});
      writeFileSync(join(dir,'empty-global.npmrc'),'',{mode:0o600});
      writeFileSync(join(dir,'package.json'),JSON.stringify(pkg)+'\n',{mode:0o600});
      runNpm(LOCK_ARGS,dir);
      const lockFile=join(dir,'package-lock.json');
      const lockBytes=readFileSync(lockFile);
      if(lockBytes.length<1||lockBytes.length>1_000_000)refuse();
      const lock=boundedJson(lockFile);
      const proof=verifyBackend16NodePgRuntimePackage(pkg,lock,frontend);
      assert.equal(proof.status,'PACKAGE_LOCK_CONTRACT_PASS_NOT_RELEASE_APPROVAL');
      const digest=createHash('sha256').update(lockBytes).digest('hex');
      receipts.push({dir,lockFile,lock,digest,proof});
    }
    const normalizedDigest=assertIndependentBackend16NodePgLocks(
      receipts[0].lock,receipts[1].lock);
    if(receipts[0].proof.packageCount!==receipts[1].proof.packageCount)refuse();
    const observed=assertObservedBackend16NodePgGraph(
      normalizedDigest,receipts[0].proof.packageCount);
    console.info('B16_REAL_LOCK_CI_GRAPH_VALIDATED');
    console.info(observed);
    console.info('B16_REAL_LOCK_CI_INDEPENDENT_RESOLUTIONS_MATCH_PASS');
    for(const {dir,lockFile,digest} of receipts){
      runNpm(CLEAN_INSTALL_ARGS,dir);
      // Both frozen installs must preserve their independently reviewed lock.
      const after=readFileSync(lockFile);
      if(createHash('sha256').update(after).digest('hex')!==digest)refuse();
      const installed=boundedJson(join(dir,'node_modules/pg/package.json'));
      if(installed.name!=='pg'||installed.version!==EXPECTED_PG_VERSION||
         existsSync(join(dir,'node_modules/pg-native')))refuse();
    }
    if(existsSync(join(ROOT,'package-lock.json')))refuse();
    console.info('B16_REAL_LOCK_CI_FROZEN_INSTALL_PASS');
    console.info('PASS Backend16 Node24 independently resolved pg lock twice: '+
      receipts[0].proof.packageCount+' packages; canonical_sha256='+
      normalizedDigest+'; two frozen installs; NO RELEASE AUTHORIZATION');
  }finally{
    rmSync(rootDir,{recursive:true,force:true});
  }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  main().catch(()=>{
    console.error('STOP Backend16 genuine NodePG CI lock refused; NO RELEASE AUTHORIZATION');
    process.exitCode=1;
  });
}
