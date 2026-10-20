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
import {existsSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {
  EXPECTED_NAME,EXPECTED_PG_VERSION,verifyBackend16NodePgRuntimePackage,
} from './verify-backend16-nodepg-runtime-lock.mjs';

const REGISTRY='https://registry.npmjs.org';
const DENIED='Backend16 genuine NodePG CI lock refused';
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
function runNpm(args,dir){
  const minimalEnv={
    PATH:process.env.PATH||'/usr/local/bin:/usr/bin:/bin',
    HOME:dir,
    TMPDIR:dir,
    LANG:'C',
    CI:'true',
    NO_UPDATE_NOTIFIER:'1',
    npm_config_cache:join(dir,'npm-cache'),
    npm_config_userconfig:'/dev/null',
    npm_config_globalconfig:'/dev/null',
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
  if(p.error||p.status!==0||p.signal)refuse();
}
async function main(){
  enforceBackend16GenuineLockCiEnvironment(
    process.env,Number(process.versions.node.split('.')[0]));
  if(existsSync(join(ROOT,'package-lock.json')))refuse();
  const frontend=boundedJson(join(ROOT,'package.json'));
  if(frontend.name!=='cli-proxy-webui-react'||
     frontend.packageManager!=='bun@1.3.14'||
     !existsSync(join(ROOT,'bun.lock')))refuse();
  const dir=mkdtempSync(join(tmpdir(),'b16-nodepg-real-lock-ci-'));
  try{
    const pkg=createBackend16GenuineLockCiManifest();
    writeFileSync(join(dir,'package.json'),JSON.stringify(pkg)+'\n',{mode:0o600});
    console.info('B16_REAL_LOCK_CI_RESOLUTION_START');
    runNpm(LOCK_ARGS,dir);
    const lockFile=join(dir,'package-lock.json');
    const lockBytes=readFileSync(lockFile);
    if(lockBytes.length<1||lockBytes.length>1_000_000)refuse();
    const lock=boundedJson(lockFile);
    const proof=verifyBackend16NodePgRuntimePackage(pkg,lock,frontend);
    assert.equal(proof.status,'PACKAGE_LOCK_CONTRACT_PASS_NOT_RELEASE_APPROVAL');
    const digest=createHash('sha256').update(lockBytes).digest('hex');
    console.info('B16_REAL_LOCK_CI_GRAPH_VALIDATED');
    runNpm(CLEAN_INSTALL_ARGS,dir);
    // npm ci must not rewrite the reviewed dependency lock.
    const after=readFileSync(lockFile);
    if(createHash('sha256').update(after).digest('hex')!==digest)refuse();
    const installed=boundedJson(join(dir,'node_modules/pg/package.json'));
    if(installed.name!=='pg'||installed.version!==EXPECTED_PG_VERSION||
       existsSync(join(dir,'node_modules/pg-native')))refuse();
    if(existsSync(join(ROOT,'package-lock.json')))refuse();
    console.info('B16_REAL_LOCK_CI_FROZEN_INSTALL_PASS');
    console.info('PASS Backend16 Node24 genuine ephemeral pg lock and npm ci: '+
      proof.packageCount+' packages; sha256='+digest+
      '; NO RELEASE AUTHORIZATION');
  }finally{
    rmSync(dir,{recursive:true,force:true});
  }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  main().catch(()=>{
    console.error('STOP Backend16 genuine NodePG CI lock refused; NO RELEASE AUTHORIZATION');
    process.exitCode=1;
  });
}
