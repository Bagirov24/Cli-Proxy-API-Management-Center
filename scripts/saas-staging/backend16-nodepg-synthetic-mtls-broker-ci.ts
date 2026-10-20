/**
 * Disposable CI-only mutual TLS exact-version secret broker.
 * This test component is deliberately NOT a runtime server or Railway service.
 * All keys live in a temporary directory and are erased at process end.
 */
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,X509Certificate} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {createServer} from 'node:https';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import type {Backend16OperatorApprovedSecretBrokerMtls}
  from '../../src/features/saasBlueprint/controlApi/server/backend16PrivateMtlsVersionedSecretReader.ts';

const BROKER_HOST='saas-secret-broker.railway.internal';
const UUID_SECRET=/^b16-stg-pg-[a-z0-9_-]{16,80}$/;
const VERSION=/^[a-f0-9]{32,64}$/;
const PASSWORD=/^[\x21-\x7e]{32,256}$/;
const APPROVED=new Set(['saas_b14_person','saas_b16_person_b']);
export type SyntheticBackend16PrincipalSecret=Readonly<{
  pgLogin:string;secretId:string;version:string;password:string;
}>;
type Mode='pass'|'wrong-version'|'expired'|'deferred';

export async function startSyntheticBackend16MtlsBroker(
  candidates:readonly SyntheticBackend16PrincipalSecret[],
){
  const e=process.env;
  if(e.GITHUB_ACTIONS!=='true'||e.SAAS_B16_EPHEMERAL_CI!=='true'||
     e.SAAS_B16_NODEPG_PHYSICAL_CI!=='true'||
     e.SAAS_B16_BROKER_MTLS_CI!=='true'||
     e.PGHOST!=='127.0.0.1'||e.PGPORT!=='5432'||
     e.PGDATABASE!=='saas_ephemeral_test'||
     e.PGPASSWORD!=='ci_ephemeral_test_only'||
     e.NODE_ENV==='production'||e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
     e.RAILWAY_PROJECT_ID||e.RAILWAY_ENVIRONMENT_ID||
     e.RAILWAY_SERVICE_ID||e.RAILWAY_ENVIRONMENT||
     Number(process.versions.node.split('.')[0])!==24)
    throw Error('B16 synthetic mTLS broker is disposable GitHub CI only');
  if(!Array.isArray(candidates)||candidates.length!==2)throw Error('B16 broker scope denied');
  const entries=candidates.map(x=>{
    if(!x||!APPROVED.has(x.pgLogin)||!UUID_SECRET.test(x.secretId)||
       !VERSION.test(x.version)||!PASSWORD.test(x.password))
      throw Error('B16 broker scope denied');
    return Object.freeze({
      pgLogin:x.pgLogin,secretId:x.secretId,version:x.version,
      password:x.password,
    });
  });
  if(new Set(entries.map(x=>x.pgLogin)).size!==2||
     new Set(entries.map(x=>x.secretId)).size!==2)
    throw Error('B16 broker duplicate principal denied');

  const dir=mkdtempSync(join(tmpdir(),'b16-nodepg-mtls-'));
  const openssl=(args:string[])=>{
    execFileSync('openssl',args,{cwd:dir,stdio:'ignore',timeout:15000});
  };
  const digest=(pem:string)=>createHash('sha256')
    .update(new X509Certificate(pem).raw).digest('hex');
  const cert=(name:string)=>readFileSync(join(dir,name+'.pem'),'utf8');
  const key=(name:string)=>readFileSync(join(dir,name+'.key'),'utf8');
  let running=false;
  try{
    openssl([
      'req','-x509','-newkey','rsa:3072','-nodes','-sha256',
      '-keyout','root.key','-out','root.pem','-days','30',
      '-subj','/CN=B16 isolated synthetic mTLS root',
      '-addext','basicConstraints=critical,CA:TRUE',
      '-addext','keyUsage=critical,keyCertSign,cRLSign',
    ]);
    for(const [name,usage,san] of [
      ['client','clientAuth',''],
      ['server','serverAuth',BROKER_HOST],
    ]){
      openssl([
        'req','-newkey','rsa:3072','-nodes','-sha256',
        '-keyout',name+'.key','-out',name+'.csr',
        '-subj','/CN=B16 synthetic '+name,
      ]);
      writeFileSync(join(dir,name+'.ext'),[
        'basicConstraints=critical,CA:FALSE',
        'keyUsage=digitalSignature,keyEncipherment',
        'extendedKeyUsage='+usage,
        ...(san?['subjectAltName=DNS:'+san]:[]),
      ].join('\n')+'\n',{mode:0o600});
      openssl([
        'x509','-req','-in',name+'.csr',
        '-CA','root.pem','-CAkey','root.key','-CAcreateserial',
        '-out',name+'.pem','-days','5','-sha256',
        '-extfile',name+'.ext',
      ]);
    }
    const trust:Backend16OperatorApprovedSecretBrokerMtls=Object.freeze({
      caPem:cert('root'),approvedCaDerSha256:digest(cert('root')),
      clientCertPem:cert('client'),
      approvedClientCertDerSha256:digest(cert('client')),
      clientPrivateKeyPem:key('client'),
    });
    const approvedClient=trust.approvedClientCertDerSha256;
    let mode:Mode='pass',requests=0;
    const received:Array<{pgLogin:string;secretId:string;version:string}>=[];
    let deferred:(()=>void)|undefined;
    let deferredReady:(()=>void)|undefined;
    const server=createServer({
      ca:trust.caPem,cert:cert('server'),key:key('server'),
      requestCert:true,rejectUnauthorized:true,
      minVersion:'TLSv1.2',maxVersion:'TLSv1.3',
    },(req,res)=>{
      requests++;
      const peer=req.socket.getPeerCertificate(true);
      const certPin=peer.raw?createHash('sha256')
        .update(peer.raw).digest('hex'):'';
      const match=entries.find(x=>req.url===
        '/v1/staging/principals/'+x.secretId+'/versions/'+x.version);
      if(req.socket.authorized!==true||certPin!==approvedClient||
         req.method!=='GET'||req.headers.accept!=='application/json'||
         req.headers['cache-control']!=='no-store'||!match){
        res.writeHead(404,{'Cache-Control':'no-store'});res.end();return;
      }
      received.push({
        pgLogin:match.pgLogin,secretId:match.secretId,version:match.version,
      });
      const body=JSON.stringify({
        username:match.pgLogin,password:match.password,
        version:mode==='wrong-version'?'f'.repeat(32):match.version,
        expiresAtMs:Date.now()+(mode==='expired'?5_000:120_000),
      });
      const send=()=>{
        res.writeHead(200,{
          'Content-Type':'application/json','Cache-Control':'no-store',
          'Content-Length':Buffer.byteLength(body),'Connection':'close',
        });
        res.end(body);
      };
      if(mode==='deferred'){
        deferred=send;deferredReady?.();deferredReady=undefined;
      }else send();
    });
    await new Promise<void>((resolve,reject)=>{
      server.once('error',reject);
      server.listen(0,'127.0.0.1',resolve);
    });
    running=true;
    const address=server.address();
    assert.ok(address&&typeof address!=='string');
    return Object.freeze({
      port:address.port,trust,
      calls:()=>requests,
      received,
      choose:(next:Mode)=>{mode=next;},
      async waitForDeferred(){
        if(deferred)return;
        await new Promise<void>((resolve,reject)=>{
          const deadline=setTimeout(()=>reject(
            Error('B16 synthetic mTLS deferred request unavailable')),2500);
          deferredReady=()=>{clearTimeout(deadline);resolve();};
        });
      },
      releaseDeferred(){
        if(!deferred)throw Error('B16 synthetic mTLS response not held');
        const send=deferred;deferred=undefined;send();
      },
      async close(){
        server.closeAllConnections();
        await new Promise<void>(resolve=>server.close(()=>resolve()));
        rmSync(dir,{recursive:true,force:true});
      },
    });
  }catch{
    if(!running)rmSync(dir,{recursive:true,force:true});
    throw Error('B16 disposable mTLS fixture unavailable');
  }
}
