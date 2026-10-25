/**
 * P2 CI-only transport-library packaging, NOT a complete server artifact.
 * Two cold builds on ONE hosted runner. No runtime approval, dependency install,
 * publisher signature, independent reproducible executable or live deployment.
 */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {
  constants,closeSync,fstatSync,lstatSync,mkdirSync,mkdtempSync,openSync,
  readFileSync,readdirSync,readlinkSync,rmSync,writeFileSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,isAbsolute,join,relative,resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const PACKAGE='scripts/saas-staging/backend16-native-transport-package-ci';
const POLICY='scripts/saas-staging/backend16-native-server-source-closure.v1.json';
const INPUTS=Object.freeze(['build.mjs','bun.lock','index.ts','package.json','smoke.mjs']);
const BUILTINS=Object.freeze(['node:crypto','node:https','node:tls']);
const INVENTORY='9a0e30c78d1c2d07ee3b4695cdfa1d570f5c8f0e2f75f2371b010a8edad5687c';
const HEX=/^[a-f0-9]{64}$/;
const fail=()=>{throw Error('Backend16 isolated transport package refused');};
export const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');

export function assertTransportPackageInputs(manifest,lock){
  // Manual review pins for these new CI-only metadata files, not publisher signatures.
  // Byte equality rejects duplicate keys AND whitespace hidden inside string values.
  const pins=[
    'be4715954a29078b224b0e5ab09efbbc972e61900d6bc3119ff0952a0adc395f',
    'cdbce651e3c473706f51b4701639617fb7afabce0ca703439c2bc3082e5d29c4',
  ];
  for(const [i,bytes] of [manifest,lock].entries()){
    if(!Buffer.isBuffer(bytes)||bytes.length>4096||sha256(bytes)!==pins[i])fail();
  }
  return true;
}

export function readTransportPackageFile(path,max=1_000_000){
  const before=lstatSync(path);
  if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||
     (before.mode&0o022)||before.size<1||before.size>max)fail();
  const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{
    const st=fstatSync(fd);
    if(st.ino!==before.ino||st.dev!==before.dev||st.size!==before.size)fail();
    const bytes=readFileSync(fd);
    if(bytes.length!==st.size)fail();
    return bytes;
  }finally{closeSync(fd);}
}

export function transportChildEnvironment(dir,parentNetwork){
  if(!isAbsolute(dir)||resolve(dir)!==dir||dir.includes('\0')||
     !/^net:\[\d+\]$/.test(parentNetwork))fail();
  // Construct an allowlist from scratch; never spread process.env or caller credentials.
  return Object.freeze({
    PATH:'/usr/bin:/bin',HOME:join(dir,'home'),TMPDIR:join(dir,'tmp'),
    XDG_CONFIG_HOME:join(dir,'home/config'),XDG_CACHE_HOME:join(dir,'cache'),
    BUN_INSTALL:join(dir,'bun-home'),BUN_INSTALL_CACHE_DIR:join(dir,'cache/install'),
    BUN_RUNTIME_TRANSPILER_CACHE_PATH:join(dir,'cache/transpiler'),
    CI:'true',TZ:'UTC',LANG:'C.UTF-8',TERM:'dumb',
    B16_TRANSPORT_PACKAGE_CI:'true',B16_PARENT_NETWORK_NS:parentNetwork,
  });
}

function localPath(path,root){
  if(typeof path!=='string'||path.includes('\\')||path.includes('\0'))fail();
  const normalized=isAbsolute(path)?relative(root,path):path.replace(/^\.\//,'');
  if(!normalized||normalized.split('/').some(p=>!p||p==='.'||p==='..'))fail();
  return normalized;
}
export function inspectTransportBuildGraph(meta,root,files){
  if(!meta||!meta.inputs||!meta.outputs||Array.isArray(meta.inputs)||
     Array.isArray(meta.outputs))fail();
  const wanted=['index.ts',...files].sort();
  const paths=Object.keys(meta.inputs).map(p=>localPath(p,root)).sort();
  assert.deepEqual(paths,wanted);
  const builtins=new Set();
  const imports=rows=>{
    if(!Array.isArray(rows)||rows.length>100)fail();
    return rows.map(row=>{
      if(!row||!['import-statement','require-call'].includes(row.kind)||
         typeof row.path!=='string')fail();
      // No require-call is present in the reviewed source closure.
      if(row.kind!=='import-statement')fail();
      if(row.external===true){
        if(!BUILTINS.includes(row.path))fail();
        builtins.add(row.path);
        return row.path;
      }
      const target=localPath(row.path,root);
      if(!wanted.includes(target))fail();
      return target;
    }).sort();
  };
  const graph=Object.entries(meta.inputs).map(([path,data])=>{
    const key=localPath(path,root);
    const bytes=readTransportPackageFile(join(root,key));
    if(data.bytes!==bytes.length)fail();
    return {path:key,sha256:sha256(bytes),imports:imports(data.imports)};
  }).sort((a,b)=>a.path.localeCompare(b.path,'en'));
  const outputs=Object.entries(meta.outputs);
  if(outputs.length!==1||localPath(outputs[0][0],root)!=='dist/transport.mjs')fail();
  const output=outputs[0][1];
  if(localPath(output.entryPoint,root)!=='index.ts'||
     !output.inputs||Object.keys(output.inputs).some(p=>!wanted.includes(localPath(p,root))))
    fail();
  imports(output.imports);
  assert.deepEqual([...builtins].sort(),BUILTINS);
  const bundle=readTransportPackageFile(join(root,'dist/transport.mjs'));
  if(output.bytes!==bundle.length)fail();
  return sha256(JSON.stringify({graph,builtins:BUILTINS}));
}

export function compareTransportBuildReceipts(a,b){
  const keys=['bundleSha256','graphSha256','lockSha256','manifestSha256',
    'recipeSha256','sourceInventorySha256'];
  for(const receipt of [a,b]){
    if(!receipt||Object.keys(receipt).sort().join(',')!==keys.join(',')||
       keys.some(key=>typeof receipt[key]!=='string'||
        !HEX.test(receipt[key])||receipt[key]==='0'.repeat(64))||
       receipt.sourceInventorySha256!==INVENTORY)fail();
  }
  assert.deepEqual(a,b);
  return true;
}

function execute(binary,args,cwd,env,maxBuffer=1_000_000){
  const result=spawnSync(binary,args,{
    cwd,env,encoding:'utf8',stdio:['ignore','pipe','pipe'],
    timeout:45_000,killSignal:'SIGKILL',maxBuffer,
  });
  if(result.error||result.signal||result.status!==0)fail();
  return result.stdout;
}
function offline(binary,args,cwd,env){
  const uid=process.getuid(),gid=process.getgid();
  if(!Number.isSafeInteger(uid)||uid<=0||!Number.isSafeInteger(gid)||gid<=0)fail();
  return execute('/usr/bin/sudo',[
    '-n','/usr/bin/unshare','--net','--','/usr/bin/setpriv',
    '--reuid='+uid,'--regid='+gid,'--clear-groups',
    '/usr/bin/env','-i',...Object.entries(env).map(([k,v])=>k+'='+v),binary,...args,
  ],cwd,{PATH:'/usr/bin:/bin'});
}

async function main(){
  let stage='context';
  let temp;
  try{
    if(process.argv.length!==2||process.env.SAAS_B16_TRANSPORT_PACKAGE_CI!=='true')fail();
    const pin=await import('./install-backend16-official-stable-144-ci.mjs');
    pin.enforceBackend16OfficialStable144CiEnvironment(process.env,
      Number(process.versions.node.split('.')[0]),process.platform,process.arch);
    const e=process.env;
    if(execute('git',['rev-parse','HEAD'],ROOT,{PATH:'/usr/bin:/bin'}).trim()!==e.B16_PR_HEAD_SHA)
      fail();
    const binary=e.SAAS_B16_STABLE_144_BIN;
    if(typeof binary!=='string'||!/^\/tmp\/b16-official-stable-144-ci-[A-Za-z0-9]+\/bun$/.test(binary))
      fail();
    stage='runtime-bytes';
    const archive=join(dirname(binary),'release.zip');
    pin.verifyBackend16OfficialStable144Archive(readTransportPackageFile(archive,150_000_000));
    // Independently bind the installed ELF to the already integrity-verified release ZIP.
    const extracted=spawnSync('/usr/bin/unzip',['-p',archive,'bun-linux-x64/bun'],{
      stdio:['ignore','pipe','pipe'],timeout:30_000,maxBuffer:240_000_000,
      env:{PATH:'/usr/bin:/bin'},
    });
    if(extracted.error||extracted.signal||extracted.status!==0||extracted.stderr.length||
       !extracted.stdout.length||sha256(extracted.stdout)!==
       sha256(readTransportPackageFile(binary,240_000_000)))fail();
    const binarySha256=sha256(extracted.stdout);
    const {inspectBackend16NativeSourceClosure:inspect}=await import(
      './verify-backend16-native-source-closure-ci.mjs');
    stage='source-and-package';
    const source=inspect(ROOT);
    if(source.sourceInventorySha256!==INVENTORY)fail();
    const policy=JSON.parse(readTransportPackageFile(join(ROOT,POLICY)));
    const files=policy.modules.map(x=>policy.root+'/'+x.file);
    assert.deepEqual(readdirSync(join(ROOT,PACKAGE)).sort(),INPUTS);
    const inputs=Object.fromEntries(INPUTS.map(f=>[f,readTransportPackageFile(join(ROOT,PACKAGE,f))]));
    assertTransportPackageInputs(inputs['package.json'],inputs['bun.lock']);
    const fixed=['package.json','bun.lock',
      'scripts/saas-staging/backend16-native-server-artifact-evidence-contract.v1.json'];
    const before=fixed.map(f=>sha256(readTransportPackageFile(join(ROOT,f))));
    const recipeSha256=sha256(Buffer.concat([
      readTransportPackageFile(fileURLToPath(import.meta.url)),...Object.values(inputs),
    ]));
    temp=mkdtempSync(join(tmpdir(),'b16-native-transport-package-ci-'));
    const results=[];
    for(const slot of ['a','b']){
      const dir=join(temp,slot);
      mkdirSync(dir,{mode:0o700});
      for(const name of ['home','home/config','tmp','cache','cache/install','cache/transpiler','bun-home'])
        mkdirSync(join(dir,name),{recursive:true,mode:0o700});
      for(const [name,bytes] of Object.entries(inputs))
        writeFileSync(join(dir,name),bytes,{flag:'wx',mode:0o600});
      for(const file of files){
        mkdirSync(dirname(join(dir,file)),{recursive:true,mode:0o700});
        writeFileSync(join(dir,file),readTransportPackageFile(join(ROOT,file)),{flag:'wx',mode:0o600});
      }
      assert.deepEqual(inspect(dir),source);
      const env=transportChildEnvironment(dir,readlinkSync('/proc/self/ns/net'));
      stage='frozen-zero-package-validation-'+slot;
      // Zero external packages: native frozen DRY RUN validates the checked lock;
      // deliberately do not claim a dependency installation when there is nothing to install.
      offline(binary,['install','--frozen-lockfile','--ignore-scripts','--dry-run'],dir,env);
      assert.deepEqual(readTransportPackageFile(join(dir,'package.json')),inputs['package.json']);
      assert.deepEqual(readTransportPackageFile(join(dir,'bun.lock')),inputs['bun.lock']);
      assert.equal(readdirSync(dir).includes('node_modules'),false);
      stage='offline-build-'+slot;
      assert.equal(offline(binary,['--no-install','build.mjs'],dir,env).trim(),
        'B16_TRANSPORT_PACKAGE_OFFLINE_BUILD_PASS');
      assert.deepEqual(readdirSync(join(dir,'dist')).sort(),['graph.json','transport.mjs']);
      const graph=JSON.parse(readTransportPackageFile(join(dir,'dist/graph.json')));
      const graphSha256=inspectTransportBuildGraph(graph,dir,files);
      const bundle=readTransportPackageFile(join(dir,'dist/transport.mjs'));
      assert.deepEqual(inspect(dir),source);
      stage='emitted-only-smoke-'+slot;
      const smoke=join(temp,'emitted-'+slot);mkdirSync(smoke,{mode:0o700});
      for(const name of ['home','home/config','tmp','cache','cache/install',
        'cache/transpiler','bun-home'])
        mkdirSync(join(smoke,name),{recursive:true,mode:0o700});
      writeFileSync(join(smoke,'transport.mjs'),bundle,{flag:'wx',mode:0o600});
      writeFileSync(join(smoke,'smoke.mjs'),inputs['smoke.mjs'],{flag:'wx',mode:0o600});
      // Delete ALL staged sources and package inputs before the detached smoke process.
      rmSync(dir,{recursive:true});
      const smokeEnv=transportChildEnvironment(smoke,readlinkSync('/proc/self/ns/net'));
      assert.equal(offline(binary,['--no-install','smoke.mjs'],smoke,smokeEnv).trim(),
        'B16_TRANSPORT_PACKAGE_EMITTED_FAIL_CLOSED_SMOKE_PASS');
      results.push({bundleSha256:sha256(bundle),graphSha256,
        lockSha256:sha256(inputs['bun.lock']),manifestSha256:sha256(inputs['package.json']),
        recipeSha256,sourceInventorySha256:source.sourceInventorySha256});
    }
    stage='same-runner-comparison';
    compareTransportBuildReceipts(...results);
    assert.deepEqual(fixed.map(f=>sha256(readTransportPackageFile(join(ROOT,f)))),before);
    assert.deepEqual(inspect(ROOT),source);
    assert.equal(sha256(readTransportPackageFile(binary,240_000_000)),binarySha256);
    console.info(JSON.stringify({
      schema:'backend16-isolated-transport-package-ci-v1',
      scope:'TRANSPORT_LIBRARY_ONLY_TWO_COLD_BUILDS_ONE_RUNNER',
      head:e.B16_PR_HEAD_SHA,...results[0],binarySha256,
      runtimeRevision:pin.B16_OFFICIAL_STABLE_144.fullRevision,
      externalPackageCount:0,transportBundleBuilt:true,serverArtifactBuilt:false,
      stableRuntimeApproved:false,stagingAuthorized:false,productionAuthorized:false,
      releaseState:'BLOCKED_RELEASE',
    }));
    console.info('B16_TRANSPORT_PACKAGE_TWO_OFFLINE_BUILDS_MATCH');
    console.info('B16_TRANSPORT_PACKAGE_EMITTED_FAIL_CLOSED_SMOKE_PASS');
    console.info('NO RELEASE AUTHORIZATION');
  }catch{
    console.error('STOP Backend16 isolated transport package: '+stage);
    process.exitCode=1;
  }finally{if(temp)rmSync(temp,{recursive:true,force:true});}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)await main();
