import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,X509Certificate} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createSecureContext,TLSSocket} from 'node:tls';
import {
  createBackend16StagingPgTlsTrust,
  type Backend16StagingPgTlsTrust,
} from '../src/features/saasBlueprint/controlApi/server/backend16StagingPgTlsTrust.ts';
import {
  verifyBackend16DisposableCiPrivatePgTls,
  verifyBackend16StagingPrivatePgTls,
} from '../src/features/saasBlueprint/controlApi/server/backend16VerifiedPrivatePgTls.ts';

const HOST='postgres.railway.internal';
const REQUEST=Buffer.from([0,0,0,8,4,210,22,47]);
const source=readFileSync(new URL(
  '../src/features/saasBlueprint/controlApi/server/backend16VerifiedPrivatePgTls.ts',
  import.meta.url),'utf8');

function runOpenSsl(dir:string,args:string[]):void{
  execFileSync('openssl',args,{cwd:dir,stdio:'ignore',timeout:15000});
}
function root(dir:string,prefix:string){
  runOpenSsl(dir,[
    'req','-x509','-newkey','rsa:3072','-nodes','-sha256',
    '-keyout',prefix+'.key','-out',prefix+'.pem','-days','30',
    '-subj','/CN=Backend16 Disposable CI Root '+prefix,
    '-addext','basicConstraints=critical,CA:TRUE',
    '-addext','keyUsage=critical,keyCertSign,cRLSign',
  ]);
  const pem=readFileSync(join(dir,prefix+'.pem'),'utf8');
  const pin=createHash('sha256').update(new X509Certificate(pem).raw)
    .digest('hex');
  return {pem,pin,key:join(dir,prefix+'.key')};
}
function leaf(dir:string,prefix:string,ca:string,hostSan?:string){
  runOpenSsl(dir,[
    'req','-newkey','rsa:2048','-nodes','-sha256',
    '-keyout',prefix+'.key','-out',prefix+'.csr',
    '-subj','/CN='+HOST,
  ]);
  const ext=[
    'basicConstraints=critical,CA:FALSE',
    'extendedKeyUsage=serverAuth',
    'keyUsage=digitalSignature,keyEncipherment',
    ...(hostSan===undefined?[]:['subjectAltName=DNS:'+hostSan]),
  ].join('\n')+'\n';
  writeFileSync(join(dir,prefix+'.ext'),ext,{mode:0o600});
  runOpenSsl(dir,[
    'x509','-req','-in',prefix+'.csr','-CA',ca+'.pem',
    '-CAkey',ca+'.key','-CAcreateserial',
    '-out',prefix+'.pem','-days','2','-sha256',
    '-extfile',prefix+'.ext',
  ]);
  return{
    cert:readFileSync(join(dir,prefix+'.pem'),'utf8'),
    key:readFileSync(join(dir,prefix+'.key'),'utf8'),
  };
}
async function fakePgTls(
  certificate:{cert:string;key:string}|null,
  mode:'tls'|'no-ssl'|'hang'='tls',
){
  let requests=0;
  const sockets=new Set<import('node:net').Socket>();
  const secureSockets=new Set<TLSSocket>();
  const server=createServer(socket=>{
    sockets.add(socket);
    socket.on('close',()=>sockets.delete(socket));
    socket.once('error',()=>socket.destroy());
    socket.once('data',(payload:Buffer)=>{
      requests++;
      if(!payload.equals(REQUEST)){socket.destroy();return;}
      if(mode==='no-ssl'){socket.end('N');return;}
      if(mode==='hang')return;
      if(!certificate){socket.destroy();return;}
      socket.write('S',()=>{
        try{
          const tls=new TLSSocket(socket,{
            isServer:true,
            secureContext:createSecureContext({
              cert:certificate.cert,key:certificate.key,
            }),
          });
          secureSockets.add(tls);
          tls.on('close',()=>secureSockets.delete(tls));
          tls.on('error',()=>tls.destroy());
        }catch{socket.destroy();}
      });
    });
  });
  await new Promise<void>((resolve,reject)=>{
    server.once('error',reject);
    server.listen(0,'127.0.0.1',resolve);
  });
  const port=(server.address() as import('node:net').AddressInfo).port;
  return{
    port,
    count:()=>requests,
    close:async()=>{
      for(const socket of secureSockets)socket.destroy();
      for(const socket of sockets)socket.destroy();
      await new Promise<void>(resolve=>server.close(()=>resolve()));
    },
  };
}

const refused=/Backend16 pinned private PostgreSQL TLS verification refused/;

test('verified TLS source has no PostgreSQL credentials, SQL or unsafe fallback',()=>{
  assert.match(source,/socket\.write\(SSL_REQUEST\)/);
  assert.match(source,/response\.length!==1\|\|response\[0\]!==83/);
  assert.match(source,/rejectUnauthorized:true/);
  assert.match(source,/checkServerIdentity:/);
  assert.match(source,/checkHost\(\s*HOST,\{subject:'never'\}\)/);
  assert.match(source,/verified\.authorized!==true/);
  assert.match(source,/!validTrust\(trust\)/);
  assert.match(source,/env\.RAILWAY_ENVIRONMENT_NAME!=='staging'/);
  assert.match(source,/env\.SAAS_B16_VERIFIED_TLS_EXPLICIT_ENABLE!=='true'/);
  assert.match(source,/env\.GITHUB_ACTIONS!=='true'/);
  assert.match(source,/productionAuthorized:false/);
  assert.doesNotMatch(source,
    /rejectUnauthorized:false|tls:'require'|tls:'disable'|tls:'prefer'/);
  assert.doesNotMatch(source,
    /Bun\.serve|createServer\(|\.listen\(|DATABASE_URL|DATABASE_PUBLIC_URL|password:|SET ROLE|ALTER ROLE|CREATE ROLE|INSERT INTO|UPDATE saas_|DELETE FROM|\\.query\(/);
  assert.equal((source.match(/\.write\(/g)||[]).length,1);
});

test('real disposable PostgreSQL SSLRequest and verify-full leaf+CA chain',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'b16-verifyfull-'));
  const names=[
    'GITHUB_ACTIONS','SAAS_B16_EPHEMERAL_CI','SAAS_B16_VERIFYFULL_CI',
    'NODE_ENV','RAILWAY_PROJECT_ID','RAILWAY_ENVIRONMENT_ID',
    'RAILWAY_SERVICE_ID','RAILWAY_ENVIRONMENT',
  ];
  const original=Object.fromEntries(names.map(k=>[k,process.env[k]]));
  process.env.GITHUB_ACTIONS='true';
  process.env.SAAS_B16_EPHEMERAL_CI='true';
  process.env.SAAS_B16_VERIFYFULL_CI='true';
  delete process.env.NODE_ENV;
  for(const k of names.filter(k=>k.startsWith('RAILWAY_')))
    delete process.env[k];
  const signal=()=>new AbortController().signal;
  try{
    const originalRoot=root(dir,'root-a');
    const otherRoot=root(dir,'root-b');
    const good=leaf(dir,'good','root-a',HOST);
    const wrongHost=leaf(dir,'wrong-host','root-a','other.railway.internal');
    const noSan=leaf(dir,'cn-only','root-a');
    const trust=createBackend16StagingPgTlsTrust({
      caPem:originalRoot.pem,approvedCaDerSha256:originalRoot.pin,
    });
    const secondTrust=createBackend16StagingPgTlsTrust({
      caPem:otherRoot.pem,approvedCaDerSha256:otherRoot.pin,
    });
    async function exchange(
      certificate:{cert:string;key:string}|null,
      selectedTrust:Backend16StagingPgTlsTrust,
      shouldSucceed:boolean,
      mode:'tls'|'no-ssl'|'hang'='tls',
    ){
      const server=await fakePgTls(certificate,mode);
      try{
        if(shouldSucceed){
          const result=await verifyBackend16DisposableCiPrivatePgTls(
            selectedTrust,signal(),server.port);
          assert.equal(result.result,'B16_PINNED_CA_VERIFY_FULL_NO_DATABASE_AUTH');
          assert.equal(result.hostname,HOST);
          assert.equal(result.tlsChainAuthorized,true);
          assert.equal(result.dnsSanMatchesPrivateHostname,true);
          assert.equal(result.leafValidAtObservation,true);
          assert.equal(result.approvedRootDerSha256,originalRoot.pin);
          assert.equal(result.noPostgresqlCredentialsOrSql,true);
          assert.equal(result.productionAuthorized,false);
          assert.ok(result.leafDerSha256.length===64);
          assert.ok(['TLSv1.2','TLSv1.3'].includes(result.tlsVersion));
        }else await assert.rejects(
          verifyBackend16DisposableCiPrivatePgTls(
            selectedTrust,signal(),server.port),
          refused,
        );
        assert.equal(server.count(),1,
          'client must open one socket, never retry or fall back');
      }finally{await server.close();}
    }
    await exchange(good,trust,true);
    await exchange(good,secondTrust,false);
    await exchange(wrongHost,trust,false);
    await exchange(noSan,trust,false,
      'tls'); // correct CN alone must never be enough
    await exchange(null,trust,false,'no-ssl');

    const hung=await fakePgTls(null,'hang');
    try{
      const cancel=new AbortController();
      const request=verifyBackend16DisposableCiPrivatePgTls(
        trust,cancel.signal,hung.port);
      setTimeout(()=>cancel.abort(),50);
      await assert.rejects(request,refused);
      assert.equal(hung.count(),1);
    }finally{await hung.close();}

    assert.throws(
      ()=>verifyBackend16DisposableCiPrivatePgTls(
        {...trust} as never,signal(),12345),refused,
    );
    assert.throws(
      ()=>verifyBackend16DisposableCiPrivatePgTls(
        trust,signal(),5432.5),refused,
    );
    assert.throws(
      ()=>verifyBackend16StagingPrivatePgTls(trust,signal()),refused,
      'GitHub CI must never switch to private Railway staging mode');
  }finally{
    for(const k of names){
      if(original[k]===undefined)delete process.env[k];
      else process.env[k]=original[k];
    }
    rmSync(dir,{recursive:true,force:true});
  }
});

