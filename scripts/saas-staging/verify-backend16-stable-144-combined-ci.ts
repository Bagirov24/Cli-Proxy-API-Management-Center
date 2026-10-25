/** Independent Node24 broker -> credential-isolated official Bun child. Disposable CI ONLY. */
import assert from 'node:assert/strict';
import {execFileSync,spawn} from 'node:child_process';
import {lstatSync,realpathSync} from 'node:fs';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';
import {startSyntheticBackend16MtlsBroker} from './backend16-nodepg-synthetic-mtls-broker-ci.ts';
import {
  COMBINED_REVISION,COMBINED_STEPS,COMBINED_MARKERS,
  assertCombinedEnvironment,combinedChildEnvironment,parseCombinedCommand,
  assertCombinedBrokerReceipt,
} from './backend16-stable-144-combined-contract.mjs';

async function main(){
  const e=process.env;
  assert.equal(process.argv.length,2);
  const root=fileURLToPath(new URL('../../',import.meta.url));
  const head=execFileSync('git',['rev-parse','HEAD'],{
    cwd:root,encoding:'utf8',timeout:5000,stdio:['ignore','pipe','ignore'],
  }).trim();
  assertCombinedEnvironment(e,Number(process.versions.node.split('.')[0]),head);
  assert.equal(process.platform,'linux');assert.equal(process.arch,'x64');
  const binary=e.SAAS_B16_STABLE_144_BIN!;
  const stat=lstatSync(binary);
  assert.ok(stat.isFile()&&!stat.isSymbolicLink()&&!(stat.mode&0o022));
  assert.equal(realpathSync(binary),binary);
  for(const [args,expected] of [
    [['--revision'],'1.4.4+38afee6c8'],
    [['-p','Bun.revision'],COMBINED_REVISION],
  ] as const)assert.equal(execFileSync(binary,[...args],{
    encoding:'utf8',timeout:5000,stdio:['ignore','pipe','ignore'],
  }).trim(),expected);
  // Reuse the existing independent Node24 fixture; this flag does NOT load pg.
  e.SAAS_B16_NODEPG_PHYSICAL_CI='true';e.SAAS_B16_BROKER_MTLS_CI='true';
  const entries=['A','B'].map((k,i)=>({
    pgLogin:i===0?'saas_b14_person':'saas_b16_person_b',
    secretId:'b16-stg-pg-'+k.toLowerCase().repeat(20),
    version:k.toLowerCase().repeat(32),password:e['SAAS_B16_CI_'+k+'_PASSWORD']!,
  }));
  const broker=await startSyntheticBackend16MtlsBroker(entries);
  let child:ReturnType<typeof spawn>|undefined;
  try{
    child=spawn(binary,[fileURLToPath(new URL(
      './backend16-stable-144-combined-child.ts',import.meta.url))],{
      cwd:root,env:combinedChildEnvironment(e),stdio:['pipe','pipe','pipe'],
    });
    const proc=child;
    await new Promise<void>((resolve,reject)=>{
      let index=0,bytes=0,failed=false,stderrBytes=0;
      let chain=Promise.resolve();
      const abort=()=>{failed=true;proc.kill('SIGKILL');};
      const deadline=setTimeout(abort,120_000);
      proc.on('error',abort);proc.stdin!.on('error',abort);
      proc.stdout!.on('data',(part:Buffer)=>{bytes+=part.length;if(bytes>8192)abort();});
      proc.stderr!.on('data',(part:Buffer)=>{
        stderrBytes+=part.length;failed=true;
        // Only a fixed diagnostic phase may escape; never credentials, PEM or raw errors.
        const safe=part.toString('utf8').trim();
        if(/^STOP B16 combined child [A-Z_]{1,30}$/.test(safe))console.error(safe);
        if(stderrBytes>1024)abort();
      });
      const lines=createInterface({input:proc.stdout!});
      lines.on('line',(line:string)=>{
        chain=chain.then(async()=>{
          const message=parseCombinedCommand(line,index++);
          if(['pass','wrong-version','expired','deferred'].includes(message.op))
            broker.choose(message.op);
          else if(message.op==='wait')await broker.waitForDeferred();
          else if(message.op==='release')broker.releaseDeferred();
          else if(message.op==='done')assertCombinedBrokerReceipt(broker.calls(),broker.received);
          proc.stdin!.write(JSON.stringify({id:message.id,ok:true,calls:broker.calls()})+'\n');
        }).catch(abort);
      });
      proc.once('close',(code,signal)=>{
        void chain.then(()=>{
          clearTimeout(deadline);lines.close();
          if(code===0&&!signal&&!failed&&index===COMBINED_STEPS.length){
            try{assertCombinedBrokerReceipt(broker.calls(),broker.received);resolve();}
            catch{reject(Error('Backend16 combined broker receipt refused'));}
          }else reject(Error('Backend16 stable combined child failed'));
        });
      });
      // Only disposable broker PKI travels through stdin, NEVER principal DB passwords.
      proc.stdin!.write(JSON.stringify({id:0,port:broker.port,trust:broker.trust})+'\n');
    });
    for(const marker of COMBINED_MARKERS)console.info(marker);
    console.info('NO RELEASE AUTHORIZATION');
  }finally{
    if(child&&child.exitCode===null&&child.signalCode===null){
      child.kill('SIGKILL');
      await new Promise<void>(resolve=>child!.once('close',()=>resolve()));
    }
    await broker.close();
  }
}
main().catch(()=>{
  console.error('STOP Backend16 stable combined CI refused');process.exitCode=1;
});
