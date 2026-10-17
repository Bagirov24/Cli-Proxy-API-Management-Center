/**
 * Backend16.15 — real Node24 mTLS HTTP acceptance with ephemeral certs.
 * Explicit disposable GitHub CI-only. NEVER a Railway/production provider.
 * No real LOGINs or credentials; all private keys are deleted at end.
 */
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,X509Certificate} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {createServer} from 'node:https';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
  createBackend16DisposableCiMtlsSecretReader,
  createBackend16StagingMtlsSecretReader,
  type Backend16OperatorApprovedSecretBrokerMtls,
} from '../../src/features/saasBlueprint/controlApi/server/backend16PrivateMtlsVersionedSecretReader.ts';
import {
  createBackend16StagingVersionedPrincipalVault,
} from '../../src/features/saasBlueprint/controlApi/server/backend16StagingVersionedPrincipalVault.ts';

const NAME='saas-secret-broker.railway.internal';
const A='saas_b16_reader_a';
const ID='b16-stg-pg-'+('a'.repeat(20));
const VERSION='a'.repeat(32);
const PASSWORD='synthetic_ci_pg_password_'+('x'.repeat(42));
const ERROR=/Backend16 private versioned secret service unavailable/;
const names=[
  'GITHUB_ACTIONS','SAAS_B16_EPHEMERAL_CI','SAAS_B16_BROKER_MTLS_CI',
  'RAILWAY_PROJECT_ID','RAILWAY_ENVIRONMENT_ID','RAILWAY_SERVICE_ID',
  'RAILWAY_ENVIRONMENT','NODE_ENV','NODE_TLS_REJECT_UNAUTHORIZED',
];
const original=Object.fromEntries(names.map(k=>[k,process.env[k]]));
if(process.env.GITHUB_ACTIONS!=='true'||
   names.filter(k=>k.startsWith('RAILWAY_')).some(k=>process.env[k]))
  throw Error('B16 CI-only broker acceptance refused');
process.env.SAAS_B16_EPHEMERAL_CI='true';
process.env.SAAS_B16_BROKER_MTLS_CI='true';
delete process.env.NODE_ENV;
delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const dir=mkdtempSync(join(tmpdir(),'b16-mtls-'));
function openssl(args:string[]):void{
  execFileSync('openssl',args,{cwd:dir,stdio:'ignore',timeout:15000});
}
function root(name:string):string{
  openssl([
    'req','-x509','-newkey','rsa:3072','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.pem','-days','30',
    '-subj','/CN=Backend16 Disposable CI CA '+name,
    '-addext','basicConstraints=critical,CA:TRUE',
    '-addext','keyUsage=critical,keyCertSign,cRLSign',
  ]);
  return readFileSync(join(dir,name+'.pem'),'utf8');
}
function leaf(prefix:string,rootName:string,usage:'client'|'server',san?:string){
  openssl([
    'req','-newkey','rsa:3072','-nodes','-sha256',
    '-keyout',prefix+'.key','-out',prefix+'.csr',
    '-subj','/CN=Backend16 CI '+prefix,
  ]);
  const extensions=[
    'basicConstraints=critical,CA:FALSE',
    'keyUsage=digitalSignature,keyEncipherment',
    'extendedKeyUsage='+ (usage==='client'?'clientAuth':'serverAuth'),
    ...(san?['subjectAltName=DNS:'+san]:[]),
  ].join('\n')+'\n';
  writeFileSync(join(dir,prefix+'.ext'),extensions,{mode:0o600});
  openssl([
    'x509','-req','-in',prefix+'.csr',
    '-CA',rootName+'.pem','-CAkey',rootName+'.key',
    '-CAcreateserial','-out',prefix+'.pem',
    '-days','5','-sha256','-extfile',prefix+'.ext',
  ]);
  return{
    pem:readFileSync(join(dir,prefix+'.pem'),'utf8'),
    key:readFileSync(join(dir,prefix+'.key'),'utf8'),
  };
}
function digest(pem:string):string{
  return createHash('sha256').update(new X509Certificate(pem).raw)
    .digest('hex');
}
function secret(version=VERSION,expiry=Date.now()+120_000){
  return JSON.stringify({
    username:A,password:PASSWORD,version,expiresAtMs:expiry,
  });
}
type Behaviour='pass'|'wrong-version'|'expired'|'extra'|'duplicate'|
  'redirect'|'absent'|'oversize'|'hang';
async function broker(
  rootPem:string,serverCert:{pem:string;key:string},
  requiredClient:string,
){
  let behaviour:Behaviour='pass',requests=0;
  const received:Array<{method?:string;path?:string;clientAuthorized:boolean}>= [];
  const server=createServer({
    key:serverCert.key,cert:serverCert.pem,ca:rootPem,
    requestCert:true,rejectUnauthorized:true,
    minVersion:'TLSv1.2',maxVersion:'TLSv1.3',
  },(req,res)=>{
    requests++;
    const auth=req.socket.authorized===true;
    received.push({
      method:req.method,path:req.url,clientAuthorized:auth,
    });
    const client=req.socket.getPeerCertificate(true);
    if(!auth||!client.raw||
       createHash('sha256').update(client.raw).digest('hex')!==requiredClient){
      res.writeHead(403);res.end();return;
    }
    if(behaviour==='hang')return;
    if(behaviour==='redirect'){
      res.writeHead(307,{Location:'https://public.example.invalid/secrets'});
      res.end();return;
    }
    if(behaviour==='absent'){res.writeHead(404);res.end();return;}
    let body=secret();
    if(behaviour==='wrong-version')body=secret('f'.repeat(32));
    if(behaviour==='expired')body=secret(VERSION,Date.now()+5_000);
    if(behaviour==='extra')body=body.slice(0,-1)+',"admin":true}';
    if(behaviour==='duplicate')body=body.slice(0,-1)+
      ',"password":"attacker_shadow"}';
    if(behaviour==='oversize')body='x'.repeat(5000);
    res.writeHead(200,{
      'Content-Type':'application/json','Cache-Control':'no-store',
      'Content-Length':Buffer.byteLength(body),
    });
    res.end(body);
  });
  await new Promise<void>((resolve,reject)=>{
    server.once('error',reject);
    server.listen(0,'127.0.0.1',resolve);
  });
  const port=(server.address() as import('node:net').AddressInfo).port;
  return{
    port,choose:(next:Behaviour)=>{behaviour=next;},
    calls:()=>requests,received,
    async close(){
      server.closeAllConnections();
      await new Promise<void>(resolve=>server.close(()=>resolve()));
    },
  };
}

try{
  const rootPem=root('root');
  const client=leaf('client','root','client');
  const unapprovedClient=leaf('other-client','root','client');
  const serverCert=leaf('broker-server','root','server',NAME);
  const wrongServer=leaf('wrong-san','root','server','wrong.railway.internal');
  const trust:Backend16OperatorApprovedSecretBrokerMtls={
    caPem:rootPem,
    approvedCaDerSha256:digest(rootPem),
    clientCertPem:client.pem,
    approvedClientCertDerSha256:digest(client.pem),
    clientPrivateKeyPem:client.key,
  };
  const approvedClient=digest(client.pem);
  const good=await broker(rootPem,serverCert,approvedClient);
  try{
    console.info('B16_MTLS_BROKER_CI_AUTHORIZED_START');
    const reader=createBackend16DisposableCiMtlsSecretReader(
      trust,good.port);
    const manifest={entries:[{
      pgLogin:A,secretId:ID,version:VERSION,
    }],approvedManifestSha256:createHash('sha256').update(JSON.stringify({
      schema:'backend16-staging-vault-v1',
      entries:[[A,ID,VERSION]],
    })).digest('hex')};
    const vault=await createBackend16StagingVersionedPrincipalVault({
      source:reader,manifest,
    });
    const principal=await vault.readPrincipal(A,new AbortController().signal);
    assert.deepEqual(principal,{username:A,password:PASSWORD});
    assert.equal(good.calls(),1);
    assert.deepEqual(good.received[0],{
      method:'GET',
      path:'/v1/staging/principals/'+ID+'/versions/'+VERSION,
      clientAuthorized:true,
    });
    console.info('B16_MTLS_BROKER_CI_AUTHORIZED_PASS');

    good.choose('absent');
    await assert.rejects(vault.readPrincipal(A,new AbortController().signal));
    assert.equal(good.calls(),2,'revocation must not use cache or retry');
    for(const variant of [
      'wrong-version','expired','extra','duplicate',
      'redirect','oversize',
    ] as const){
      good.choose(variant);
      const before=good.calls();
      await assert.rejects(reader.readVersion(
        ID,VERSION,new AbortController().signal),ERROR);
      assert.equal(good.calls(),before+1,
        'every denied record must cause exactly one mTLS request');
    }
    console.info('B16_MTLS_BROKER_CI_REVOCATION_AND_MALFORMED_DENY');

    const count=good.calls();
    await assert.rejects(reader.readVersion(
      '../root-secret',VERSION,new AbortController().signal),ERROR);
    await assert.rejects(reader.readVersion(
      ID,'latest',new AbortController().signal),ERROR);
    assert.equal(good.calls(),count,
      'invalid inputs must never create an HTTPS request');

    good.choose('hang');
    const controller=new AbortController();
    const request=reader.readVersion(ID,VERSION,controller.signal);
    setTimeout(()=>controller.abort(),50);
    await assert.rejects(request,ERROR);
    console.info('B16_MTLS_BROKER_CI_HUNG_ABORT_DENY');

    const badTrust={
      ...trust,approvedCaDerSha256:'0'.repeat(64),
    };
    assert.throws(()=>createBackend16DisposableCiMtlsSecretReader(
      badTrust,good.port),ERROR);
    assert.throws(()=>createBackend16DisposableCiMtlsSecretReader(
      {...trust,approvedClientCertDerSha256:'0'.repeat(64)},
      good.port),ERROR);
    assert.throws(()=>createBackend16DisposableCiMtlsSecretReader(
      {...trust,clientPrivateKeyPem:unapprovedClient.key},
      good.port),ERROR);
    assert.throws(()=>createBackend16StagingMtlsSecretReader(trust),
      ERROR,'live Railway profile must refuse disposable CI');
    console.info('B16_MTLS_BROKER_CI_UNTRUSTED_IDENTITY_DENY');
  }finally{await good.close();}

  const wrong=await broker(rootPem,wrongServer,approvedClient);
  try{
    const reader=createBackend16DisposableCiMtlsSecretReader(
      trust,wrong.port);
    await assert.rejects(reader.readVersion(
      ID,VERSION,new AbortController().signal),ERROR);
    assert.equal(wrong.calls(),0,
      'wrong server SAN cannot progress to HTTP credential request');
    console.info('B16_MTLS_BROKER_CI_WRONG_SERVER_SAN_DENY');
  }finally{await wrong.close();}
  console.info('PASS Backend16.15 actual mutual TLS immutable-version reader');
}finally{
  for(const k of names){
    if(original[k]===undefined)delete process.env[k];
    else process.env[k]=original[k];
  }
  rmSync(dir,{recursive:true,force:true});
}
