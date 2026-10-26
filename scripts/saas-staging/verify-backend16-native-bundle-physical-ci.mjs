/** Node24 supervisor. The application path executes ONLY the emitted Bun library. */
import {execFileSync,spawn} from 'node:child_process';
import {existsSync,lstatSync,mkdirSync,mkdtempSync,readdirSync,realpathSync,rmSync,writeFileSync} from 'node:fs';
import {dirname,join,resolve} from 'node:path';
import {createInterface} from 'node:readline';
import {pathToFileURL} from 'node:url';
import {collectInputs,readInput,isOutside,isolatedEnvironment,sha256,SOURCE_INVENTORY_SHA256}
  from './backend16-native-package-contract.mjs';
import {COMBINED_REVISION,COMBINED_STEPS,parseCombinedCommand,assertCombinedBrokerReceipt}
  from './backend16-stable-144-combined-contract.mjs';
import {BUILD,INPUT_SHA256,BUNDLE_MARKERS,stop,assertBundleEnvironment,bundleChildEnvironment,
  emittedHarness,assertBuiltBundle,assertRuntimeBytes,makeBundleReceipt}
  from './backend16-native-bundle-physical-contract.mjs';

function command(binary,args,cwd,env,timeout=30_000){
  return execFileSync(binary,args,{cwd,env,timeout,maxBuffer:2_000_000,
    encoding:'utf8',stdio:['ignore','pipe','pipe']});
}
function writeNew(path,bytes){writeFileSync(path,bytes,{flag:'wx',mode:0o600});}
function noAncestorConfig(stage){
  for(let dir=dirname(stage);;dir=dirname(dir)){
    if(readdirSync(dir).some(n=>['node_modules','package.json','bunfig.toml','.npmrc',
      'tsconfig.json','jsconfig.json'].includes(n)||n==='.env'||n.startsWith('.env.')))stop();
    if(dirname(dir)===dir)break;
  }
}
function filesAt(root,current=''){
  const files=[];
  for(const name of readdirSync(join(root,current)).sort()){
    const p=current?current+'/'+name:name,st=lstatSync(join(root,p));
    if(st.isSymbolicLink())stop();
    if(st.isDirectory())files.push(...filesAt(root,p));
    else if(st.isFile())files.push(p);else stop();
  }
  return files.sort();
}
function runtime(binary){
  if(!/^\/tmp\/b16-official-stable-144-ci-[A-Za-z0-9]{6}\/bun$/.test(binary)||
     realpathSync(binary)!==binary)stop();
  assertRuntimeBytes(readInput(dirname(binary),'bun',240_000_000));
}

async function exercise(binary,stage,e,broker){
  const child=spawn(binary,['--no-install','--no-env-file','./probe.ts'],{
    cwd:stage,env:bundleChildEnvironment(e,stage),stdio:['pipe','pipe','pipe'],
  });
  const closed=new Promise(resolveClose=>child.once('close',resolveClose));
  let timer,lines;
  try{
    await new Promise((resolveProof,rejectProof)=>{
      let index=0,bytes=0,failed=false,settled=false;
      let chain=Promise.resolve();
      const abort=()=>{
        if(settled)return;
        failed=true;settled=true;child.kill('SIGKILL');
        rejectProof(Error('Backend16 emitted bundle child refused'));
      };
      timer=setTimeout(abort,120_000);
      child.on('error',abort);child.stdin.on('error',abort);
      child.stdout.on('error',abort);child.stderr.on('error',abort);
      child.stdout.on('data',part=>{bytes+=part.length;if(bytes>8192)abort();});
      // Deliberately never echo raw child exceptions, SQL, passwords, PEM or tokens.
      child.stderr.on('data',part=>{
        const safe=part.toString('utf8').trim();
        if(/^STOP B16 combined child [A-Z_]{1,30}$/.test(safe))console.error(safe);
        abort();
      });
      lines=createInterface({input:child.stdout});
      lines.on('line',line=>{
        chain=chain.then(async()=>{
          if(failed)return;
          const message=parseCombinedCommand(line,index++);
          if(['pass','wrong-version','expired','deferred'].includes(message.op))broker.choose(message.op);
          else if(message.op==='wait')await broker.waitForDeferred();
          else if(message.op==='release')broker.releaseDeferred();
          else if(message.op==='done')assertCombinedBrokerReceipt(broker.calls(),broker.received);
          if(!failed)child.stdin.write(JSON.stringify({id:message.id,ok:true,calls:broker.calls()})+'\n');
        }).catch(abort);
      });
      child.once('close',(code,signal)=>{
        if(code!==0||signal){abort();return;}
        void chain.then(()=>{
          if(settled)return;
          if(failed||index!==COMBINED_STEPS.length){abort();return;}
          try{
            assertCombinedBrokerReceipt(broker.calls(),broker.received);
            settled=true;resolveProof();
          }catch{abort();}
        }).catch(abort);
      });
      // Independent broker PKI only. Generated principal passwords are never on stdin.
      child.stdin.write(JSON.stringify({id:0,port:broker.port,trust:broker.trust})+'\n');
    });
  }finally{
    clearTimeout(timer);lines?.close();
    if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');
    await closed;
  }
}

export async function runBundledPhysicalCi(root,e=process.env){
  // Reject untrusted calls BEFORE subprocesses, source copies or broker startup.
  const major=Number(process.versions.node.split('.')[0]);
  assertBundleEnvironment(e,major,process.platform,process.arch,e.B16_PR_HEAD_SHA);
  root=resolve(root);
  const head=command('git',['rev-parse','HEAD'],root,{PATH:'/usr/bin:/bin',LC_ALL:'C'},5000).trim();
  assertBundleEnvironment(e,major,process.platform,process.arch,head);
  if(realpathSync(root)!==root||!isOutside(root,e.RUNNER_TEMP))stop();
  const saved=new Map(['package.json','bun.lock',
    'scripts/saas-staging/backend16-native-server-artifact-evidence-contract.v1.json',
  ].map(p=>[p,readInput(root,p)]));
  const {inspectBackend16NativeSourceClosure}=await import('./verify-backend16-native-source-closure-ci.mjs');
  const closure=inspectBackend16NativeSourceClosure(root);
  if(closure.sourceInventorySha256!==SOURCE_INVENTORY_SHA256||closure.fileCount!==7||
     closure.externalPackageCount!==0||closure.productionAuthorized!==false||
     closure.stableRuntimeApproved!==false)stop();
  command(process.execPath,['scripts/saas-staging/verify-backend16-native-server-artifact-evidence-contract-ci.mjs'],
    root,{PATH:'/usr/bin:/bin',LC_ALL:'C'});
  const files=collectInputs(root);
  const inventory=files.map(x=>({path:x.path,bytes:x.bytes.length,sha256:sha256(x.bytes)}));
  if(sha256(JSON.stringify(inventory))!==INPUT_SHA256)stop();
  const harness=emittedHarness(readInput(root,'scripts/saas-staging/backend16-stable-144-combined-child.ts'));
  const recipe=['scripts/saas-staging/backend16-native-bundle-physical-contract.mjs',
    'scripts/saas-staging/verify-backend16-native-bundle-physical-ci.mjs',
    'scripts/saas-staging/backend16-native-package-contract.mjs',
    'scripts/saas-staging/backend16-stable-144-combined-contract.mjs',
    'scripts/saas-staging/backend16-nodepg-synthetic-mtls-broker-ci.ts',
  ].map(path=>({path,sha256:sha256(readInput(root,path))}));
  const binary=e.SAAS_B16_STABLE_144_BIN;
  runtime(binary); // Actual executable bytes must match PR107, not just a version string.
  const build=mkdtempSync(join(e.RUNNER_TEMP,'b16-bundle-build-'));
  let stage,broker;
  try{
    if(!isOutside(root,build))stop();noAncestorConfig(build);
    for(const dir of ['src','home','tmp','cache'])mkdirSync(join(build,dir),{mode:0o700});
    for(const file of files)writeNew(join(build,file.path),file.bytes);
    const buildEnv=isolatedEnvironment(build); // NO application or fixture DB credentials.
    if(command(binary,['--revision'],build,buildEnv).trim()!=='1.4.4+38afee6c8'||
       command(binary,['-p','Bun.revision'],build,buildEnv).trim()!==COMBINED_REVISION)stop();
    command(binary,BUILD,build,buildEnv);
    const bundle=readInput(build,'dist/transport.js');assertBuiltBundle(bundle);
    if(command(binary,['--no-install','--no-env-file','smoke.mjs'],build,buildEnv)!==
       'B16_NATIVE_PACKAGE_BUNDLE_IMPORT_AND_DEFAULT_DENIAL_PASS\n')stop();
    for(const file of files)if(!readInput(build,file.path).equals(file.bytes))stop();
    if(JSON.stringify(filesAt(build))!==JSON.stringify([...files.map(x=>x.path),'dist/transport.js'].sort()))stop();
    stage=mkdtempSync(join(e.RUNNER_TEMP,'b16-bundle-exec-'));
    if(!isOutside(root,stage))stop();noAncestorConfig(stage);
    for(const dir of ['home','tmp','cache'])mkdirSync(join(stage,dir),{mode:0o700});
    writeNew(join(stage,'transport.js'),bundle);writeNew(join(stage,'probe.ts'),harness);
    // No copied source, manifest, source-input lock or build recipe at execution time.
    rmSync(build,{recursive:true,force:true});
    if(existsSync(build)||filesAt(stage).join(',')!=='probe.ts,transport.js')stop();
    assertBuiltBundle(readInput(stage,'transport.js'));runtime(binary);
    const {startSyntheticBackend16MtlsBroker}=await import(pathToFileURL(join(root,
      'scripts/saas-staging/backend16-nodepg-synthetic-mtls-broker-ci.ts')).href);
    broker=await startSyntheticBackend16MtlsBroker(['A','B'].map((k,i)=>({
      pgLogin:i===0?'saas_b14_person':'saas_b16_person_b',
      secretId:'b16-stg-pg-'+k.toLowerCase().repeat(20),version:k.toLowerCase().repeat(32),
      password:e['SAAS_B16_CI_'+k+'_PASSWORD'],
    })));
    await exercise(binary,stage,e,broker);
    assertCombinedBrokerReceipt(broker.calls(),broker.received);
    assertBuiltBundle(readInput(stage,'transport.js'));
    if(!readInput(stage,'probe.ts').equals(harness)||existsSync(build)||
       filesAt(stage).join(',')!=='probe.ts,transport.js')stop();
    runtime(binary);
    for(const [p,bytes] of saved)if(!readInput(root,p).equals(bytes))stop();
    const receipt=makeBundleReceipt(head,e.GITHUB_RUN_ID,e.GITHUB_RUN_ATTEMPT,
      sha256(harness),sha256(JSON.stringify({files:recipe,build:BUILD})));
    // Bounded unsigned hash-only log evidence, NEVER an uploaded executable or secrets.
    for(const marker of BUNDLE_MARKERS)console.info(marker);
    console.info('B16_EMITTED_BUNDLE_RECEIPT='+JSON.stringify(receipt));
    console.info('NO RELEASE AUTHORIZATION');
    return receipt;
  }finally{
    try{await broker?.close();}
    finally{
      rmSync(build,{recursive:true,force:true});
      if(stage)rmSync(stage,{recursive:true,force:true});
    }
  }
}
