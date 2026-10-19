/**
 * Backend16.14: actual Bun 1.3.14 TLS client versus isolated Node TLS server.
 * Runs exclusively in disposable GitHub CI. Never connects to Railway/PG.
 */
import assert from 'node:assert/strict';
import {spawn,execFileSync,type ChildProcessWithoutNullStreams} from 'node:child_process';
import {createHash,X509Certificate} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createBackend16StagingPgTlsTrust}
  from '../../src/features/saasBlueprint/controlApi/server/backend16StagingPgTlsTrust.ts';
import {verifyBackend16DisposableCiPrivatePgTls}
  from '../../src/features/saasBlueprint/controlApi/server/backend16VerifiedPrivatePgTls.ts';

const HOST='postgres.railway.internal';
const SIDE_CAR=fileURLToPath(new URL('./backend16-ci-node-pg-ssl-sidecar.cjs',import.meta.url));
const ENVS=['GITHUB_ACTIONS','SAAS_B16_EPHEMERAL_CI','SAAS_B16_VERIFYFULL_CI'] as const;
const refused=/Backend16 pinned private PostgreSQL TLS verification refused/;
if(process.env.GITHUB_ACTIONS!=='true'||
   process.env.RAILWAY_PROJECT_ID||process.env.RAILWAY_ENVIRONMENT_ID||
   process.env.RAILWAY_SERVICE_ID||process.env.NODE_ENV==='production')
  throw new Error('Backend16 disposable Bun TLS CI requires isolated GitHub Actions');
const previous=ENVS.map(k=>process.env[k]);
for(const k of ENVS)process.env[k]='true';
const dir=mkdtempSync(join(tmpdir(),'b16-bun-tls-'));
function openssl(args:string[]){
  execFileSync('openssl',args,{cwd:dir,stdio:'ignore',timeout:15_000});
}
function root(name:string){
  openssl(['req','-x509','-newkey','rsa:3072','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.pem','-days','30',
    '-subj','/CN=Backend16 CI Root '+name,
    '-addext','basicConstraints=critical,CA:TRUE',
    '-addext','keyUsage=critical,keyCertSign,cRLSign']);
  const pem=readFileSync(join(dir,name+'.pem'),'utf8');
  const pin=createHash('sha256').update(
    new X509Certificate(pem).raw).digest('hex');
  return createBackend16StagingPgTlsTrust({
    caPem:pem,approvedCaDerSha256:pin,
  });
}
function leaf(name:string,ca:string,host:string){
  openssl(['req','-newkey','rsa:2048','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+HOST]);
  writeFileSync(join(dir,name+'.ext'),[
    'basicConstraints=critical,CA:FALSE',
    'extendedKeyUsage=serverAuth',
    'keyUsage=digitalSignature,keyEncipherment',
    'subjectAltName=DNS:'+host,
  ].join('\n')+'\n',{mode:0o600});
  openssl(['x509','-req','-in',name+'.csr','-CA',ca+'.pem',
    '-CAkey',ca+'.key','-CAcreateserial','-out',name+'.pem',
    '-days','2','-sha256','-extfile',name+'.ext']);
  return {cert:join(dir,name+'.pem'),key:join(dir,name+'.key')};
}
async function startSidecar(
  mode:'tls'|'no-ssl',cert:string,key:string,
):Promise<{port:number;stop:()=>Promise<void>}>{
  return new Promise((resolve,reject)=>{
    const child=spawn('node',[SIDE_CAR,mode,cert,key],{
      cwd:dir,
      env:process.env,
      stdio:['ignore','pipe','pipe'],
    }) as ChildProcessWithoutNullStreams;
    let completed=false,buffer='';
    const limit=setTimeout(()=>finish(),4500);
    const finish=(port?:number)=>{
      if(completed)return;
      completed=true;
      clearTimeout(limit);
      child.off('exit',onExit);
      child.off('error',onError);
      if(!port){
        child.kill('SIGTERM');
        reject(new Error('Backend16 TLS disposable Node fixture refused'));
        return;
      }
      resolve({
        port,
        async stop(){
          if(child.exitCode!==null||child.signalCode!==null)return;
          await new Promise<void>(resolveStop=>{
            const timer=setTimeout(()=>{
              child.kill('SIGKILL');resolveStop();
            },1500);
            child.once('exit',()=>{clearTimeout(timer);resolveStop();});
            child.kill('SIGTERM');
          });
        },
      });
    };
    const onExit=()=>finish();
    const onError=()=>finish();
    child.once('exit',onExit);
    child.once('error',onError);
    child.stdout.on('data',(chunk:Uint8Array)=>{
      buffer+=Buffer.from(chunk).toString('utf8');
      const match=buffer.match(/(?:^|\n)PORT:(\d+)(?:\n|$)/);
      if(match){
        const port=Number(match[1]);
        if(Number.isSafeInteger(port)&&port>=1024&&port<=65535)
          finish(port);
        else finish();
      }
      if(buffer.length>1000)finish();
    });
  });
}
async function run(){
  try{
    const trusted=root('trusted');
    const untrusted=root('untrusted');
    const good=leaf('good','trusted',HOST);
    const wrongHost=leaf('wrong-host','trusted','wrong.railway.internal');
    const wildcardHost=leaf('wildcard-host','trusted','*.railway.internal');
    async function exchange(
      mode:'tls'|'no-ssl',cert:string,key:string,
      trust:ReturnType<typeof root>,accepted:boolean,
    ){
      const sidecar=await startSidecar(mode,cert,key);
      try{
        if(accepted){
          const result=await verifyBackend16DisposableCiPrivatePgTls(
            trust,new AbortController().signal,sidecar.port);
          assert.equal(result.tlsChainAuthorized,true);
          assert.equal(result.dnsSanMatchesPrivateHostname,true);
          assert.equal(result.noPostgresqlCredentialsOrSql,true);
          assert.equal(result.productionAuthorized,false);
        }else await assert.rejects(
          verifyBackend16DisposableCiPrivatePgTls(
            trust,new AbortController().signal,sidecar.port),refused);
      }finally{await sidecar.stop();}
    }
    console.info('B16_BUN_TLS_CI_PINNED_ROOT_START');
    await exchange('tls',good.cert,good.key,trusted,true);
    console.info('B16_BUN_TLS_CI_PINNED_ROOT_PASS');
    await exchange('tls',good.cert,good.key,untrusted,false);
    console.info('B16_BUN_TLS_CI_WRONG_ROOT_DENY');
    await exchange('tls',wrongHost.cert,wrongHost.key,trusted,false);
    console.info('B16_BUN_TLS_CI_WRONG_SAN_DENY');
    await exchange('tls',wildcardHost.cert,wildcardHost.key,trusted,false);
    console.info('B16_BUN_TLS_CI_CA_SIGNED_WILDCARD_SAN_DENY');
    await exchange('no-ssl',good.cert,good.key,trusted,false);
    console.info('B16_BUN_TLS_CI_NO_SSL_DENY');
    console.info('PASS Backend16.14 real Bun verified-full private TLS client');
  }finally{
    ENVS.forEach((k,i)=>previous[i]===undefined?
      delete process.env[k]:process.env[k]=previous[i]);
    rmSync(dir,{recursive:true,force:true});
  }
}
await run();
