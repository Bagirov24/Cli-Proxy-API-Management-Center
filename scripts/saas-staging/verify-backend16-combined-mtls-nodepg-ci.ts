/**
 * Backend16 combined CI-only mTLS broker -> version-pinned vault ->
 * Node24 verified TLS -> exact-session SQL0008 -> two-tenant PG16 FORCE RLS.
 * One disposable GitHub postgres:16.6 container, no permanent DB or live IAM.
 */
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,X509Certificate} from 'node:crypto';
import {readFileSync,writeFileSync,mkdtempSync,rmSync} from 'node:fs';
import {createServer} from 'node:https';
import {createRequire} from 'node:module';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as sleep} from 'node:timers/promises';
import {createBackend16StagingPgTlsTrust}
  from '../../src/features/saasBlueprint/controlApi/server/backend16StagingPgTlsTrust.ts';
import {createBackend16DisposableCiMtlsSecretReader}
  from '../../src/features/saasBlueprint/controlApi/server/backend16PrivateMtlsVersionedSecretReader.ts';
import {createBackend16StagingVersionedPrincipalVault}
  from '../../src/features/saasBlueprint/controlApi/server/backend16StagingVersionedPrincipalVault.ts';
import {createBackend16DisposableCiNodePgPhysicalPool,
  type Backend16NodePgClientConstructor}
  from '../../src/features/saasBlueprint/controlApi/server/backend16DisposableNodePgPhysicalPool.ts';
import {createBackend16ExactSqlReadPort,BACKEND16_EXACT_READ_SQL as SQL}
  from '../../src/features/saasBlueprint/controlApi/server/backend16ExactSessionSqlRead.ts';
import type {VerifiedPrincipal}
  from '../../src/features/saasBlueprint/controlApi/server/backend16PrivateTenantProjectRead.ts';

const e=process.env;
const A='saas_b14_person',B='saas_b16_person_b';
const PG_HOST='postgres.railway.internal';
const BROKER_HOST='saas-secret-broker.railway.internal';
const container=e.SAAS_B16_CI_PG_CONTAINER??'';
const HEX=/^[a-f0-9]{64}$/;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
if(e.GITHUB_ACTIONS!=='true'||e.SAAS_B16_EPHEMERAL_CI!=='true'||
   e.SAAS_B16_BROKER_MTLS_CI!=='true'||
   e.SAAS_B16_NODEPG_PHYSICAL_CI!=='true'||
   e.SAAS_B16_COMBINED_MTLS_PG_CI!=='true'||
   e.PGHOST!=='127.0.0.1'||e.PGPORT!=='5432'||
   e.PGDATABASE!=='saas_ephemeral_test'||
   e.PGPASSWORD!=='ci_ephemeral_test_only'||
   e.NODE_ENV==='production'||e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
   e.RAILWAY_PROJECT_ID||e.RAILWAY_ENVIRONMENT_ID||
   e.RAILWAY_SERVICE_ID||e.RAILWAY_ENVIRONMENT||
   !HEX.test(container)||
   !HEX.test(e.SAAS_B16_CI_A_PASSWORD??'')||
   !HEX.test(e.SAAS_B16_CI_B_PASSWORD??'')||
   !HEX.test(e.SAAS_B16_CI_A_SUBJECT_SHA??'')||
   !HEX.test(e.SAAS_B16_CI_B_SUBJECT_SHA??'')||
   !['A','B'].every(k=>['TENANT','SESSION','BINDING'].every(f=>
     UUID.test(e['SAAS_B16_CI_'+k+'_'+f]??'')))||
   Number(process.versions.node.split('.')[0])!==24)
  throw Error('B16 combined mTLS/PG16 refused non-disposable CI environment');

const require=createRequire(import.meta.url);
const pkgRoot='/tmp/b16-nodepg-peer/node_modules';
assert.equal((require(pkgRoot+'/pg/package.json') as {version:string}).version,'8.23.1');
const Client=(require(pkgRoot+'/pg') as {
  Client:Backend16NodePgClientConstructor;
}).Client;
function command(program:string,args:string[],cwd?:string){
  return execFileSync(program,args,{
    cwd,encoding:'utf8',stdio:['ignore','pipe','ignore'],timeout:15000,
  }).trim();
}
assert.equal(command('docker',['inspect','--format','{{.Config.Image}}',container]),
  'postgres:16.6');
assert.equal(command('docker',['exec',container,'printenv','PGDATA']),
  '/var/lib/postgresql/data');

const dir=mkdtempSync(join(tmpdir(),'b16-mtls-nodepg-'));
function root(name:string){
  command('openssl',[
    'req','-x509','-newkey','rsa:3072','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.pem','-days','30',
    '-subj','/CN=B16 disposable combined CA '+name,
    '-addext','basicConstraints=critical,CA:TRUE',
    '-addext','keyUsage=critical,keyCertSign,cRLSign',
  ],dir);
  return readFileSync(join(dir,name+'.pem'),'utf8');
}
function leaf(name:string,ca:string,usage:'server'|'client',san?:string){
  command('openssl',[
    'req','-newkey','rsa:3072','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.csr',
    '-subj','/CN=B16 disposable combined '+name,
  ],dir);
  writeFileSync(join(dir,name+'.ext'),[
    'basicConstraints=critical,CA:FALSE',
    'keyUsage=digitalSignature,keyEncipherment',
    'extendedKeyUsage='+(usage==='server'?'serverAuth':'clientAuth'),
    ...(san?['subjectAltName=DNS:'+san]:[]),
  ].join('\n')+'\n',{mode:0o600});
  command('openssl',[
    'x509','-req','-in',name+'.csr',
    '-CA',ca+'.pem','-CAkey',ca+'.key','-CAcreateserial',
    '-out',name+'.crt','-days','5','-sha256',
    '-extfile',name+'.ext',
  ],dir);
  return {
    pem:readFileSync(join(dir,name+'.crt'),'utf8'),
    key:readFileSync(join(dir,name+'.key'),'utf8'),
  };
}
const pin=(pem:string)=>createHash('sha256')
  .update(new X509Certificate(pem).raw).digest('hex');
function pgServerCert(name:string){
  for(const extension of ['crt','key'])
    command('docker',['cp',join(dir,name+'.'+extension),
      container+':/tmp/b16-mtls-nodepg.'+extension]);
  command('docker',['exec','--user','root',container,'sh','-c',
    'mv /tmp/b16-mtls-nodepg.crt /var/lib/postgresql/data/server.crt && '+
    'mv /tmp/b16-mtls-nodepg.key /var/lib/postgresql/data/server.key && '+
    'chown postgres:postgres /var/lib/postgresql/data/server.crt '+
    '/var/lib/postgresql/data/server.key && '+
    'chmod 0600 /var/lib/postgresql/data/server.key']);
}
const admin=new Client({
  host:'127.0.0.1',port:5432,database:'saas_staging_ci',
  user:'postgres',password:'ci_ephemeral_test_only',
  connectionTimeoutMillis:4000,ssl:false,
});
admin.on('error',()=>{});
let adminConnected=false;
let server:ReturnType<typeof createServer>|undefined;
const fresh=()=>new AbortController().signal;
function principal(login:string):VerifiedPrincipal{
  const k=login===A?'A':'B';
  return Object.freeze({
    kind:'verified-server-session',
    issuer:'https://ci-b16-idp.invalid',
    pgLogin:login,
    subjectFingerprintSha256:e['SAAS_B16_CI_'+k+'_SUBJECT_SHA']!,
    sessionId:e['SAAS_B16_CI_'+k+'_SESSION']!,
    bindingId:e['SAAS_B16_CI_'+k+'_BINDING']!,
    sessionExpiresAtMs:Date.now()+180_000,
  });
}
async function scalar(sql:string,args:string[]=[]):Promise<unknown>{
  const rows=(await admin.query(sql,args)).rows;
  assert.equal(rows.length,1);
  return Object.values(rows[0])[0];
}
async function reload(){
  assert.equal(await scalar('SELECT pg_reload_conf() AS ok'),true);
  await sleep(300);
}
async function noLogin(login:string){
  assert.equal(await scalar(
    'SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname=$1 AND usename=$2',
    ['saas_staging_ci',login]),0);
}
async function gone(pid:number){
  for(let i=0;i<40;i++){
    if(await scalar('SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid=$1',
      [String(pid)])===0)return;
    await sleep(45);
  }
  throw Error('B16 mTLS+NodePG physical PID survived discard');
}
async function execute(){
  const pgCa=root('postgres-root');
  leaf('postgres-good','postgres-root','server',PG_HOST);
  const brokerCa=root('broker-root');
  const serverCert=leaf('broker-server','broker-root','server',BROKER_HOST);
  const clientCert=leaf('broker-client','broker-root','client');
  const clientPin=pin(clientCert.pem);
  const entries=[
    {pgLogin:A,secretId:'b16-stg-pg-'+('a'.repeat(20)),version:'a'.repeat(32)},
    {pgLogin:B,secretId:'b16-stg-pg-'+('b'.repeat(20)),version:'b'.repeat(32)},
  ];
  const credentials=new Map<string,string>([
    [A,e.SAAS_B16_CI_A_PASSWORD!],[B,e.SAAS_B16_CI_B_PASSWORD!],
  ]);
  const allowed=new Map<string,{login:string;version:string}>();
  for(const entry of entries)
    allowed.set('/v1/staging/principals/'+entry.secretId+'/versions/'+entry.version,
      {login:entry.pgLogin,version:entry.version});
  let brokerCalls=0,authorizedRequests=0;
  let defer=false;
  let notifyArrival:(()=>void)|undefined;
  let releaseReply:(()=>void)|undefined;
  const arrival=new Promise<void>(resolve=>{notifyArrival=resolve;});
  server=createServer({
    cert:serverCert.pem,key:serverCert.key,ca:brokerCa,
    requestCert:true,rejectUnauthorized:true,
    minVersion:'TLSv1.2',maxVersion:'TLSv1.3',
  },async(req,res)=>{
    brokerCalls++;
    const peer=req.socket.getPeerCertificate(true);
    const identityOk=req.socket.authorized===true&&
      !!peer.raw&&createHash('sha256').update(peer.raw).digest('hex')===clientPin;
    if(!identityOk||req.method!=='GET'||
       req.headers.accept!=='application/json'){
      res.writeHead(403,{'Cache-Control':'no-store'});res.end();return;
    }
    authorizedRequests++;
    const entry=allowed.get(req.url??'');
    if(!entry){
      res.writeHead(404,{'Cache-Control':'no-store'});res.end();return;
    }
    const body=JSON.stringify({
      username:entry.login,password:credentials.get(entry.login),
      version:entry.version,expiresAtMs:Date.now()+120_000,
    });
    if(defer){
      notifyArrival?.();
      await new Promise<void>(resolve=>{releaseReply=resolve;});
      defer=false;
    }
    res.writeHead(200,{
      'Content-Type':'application/json',
      'Cache-Control':'no-store',
      'Content-Length':Buffer.byteLength(body),
      'Connection':'close',
    });
    res.end(body);
  });
  await new Promise<void>((resolve,reject)=>{
    server!.once('error',reject);
    server!.listen(0,'127.0.0.1',resolve);
  });
  const port=(server.address() as import('node:net').AddressInfo).port;
  const brokerTrust={
    caPem:brokerCa,approvedCaDerSha256:pin(brokerCa),
    clientCertPem:clientCert.pem,
    approvedClientCertDerSha256:clientPin,
    clientPrivateKeyPem:clientCert.key,
  };
  const reader=createBackend16DisposableCiMtlsSecretReader(brokerTrust,port);
  const manifestPin=createHash('sha256').update(JSON.stringify({
    schema:'backend16-staging-vault-v1',
    entries:entries.map(x=>[x.pgLogin,x.secretId,x.version]),
  })).digest('hex');
  const vault=await createBackend16StagingVersionedPrincipalVault({
    manifest:{entries,approvedManifestSha256:manifestPin},
    source:reader,
  });
  await admin.connect();adminConnected=true;
  pgServerCert('postgres-good');
  await admin.query("ALTER SYSTEM SET ssl='on'");
  await reload();
  assert.equal(await scalar('SHOW ssl'),'on');
  const pgTrust=createBackend16StagingPgTlsTrust({
    caPem:pgCa,approvedCaDerSha256:pin(pgCa),
  });
  const a=principal(A),b=principal(B);
  const ta=e.SAAS_B16_CI_A_TENANT!,tb=e.SAAS_B16_CI_B_TENANT!;
  const pool=createBackend16DisposableCiNodePgPhysicalPool(
    vault,pgTrust,Client);
  try{
    const read=createBackend16ExactSqlReadPort({
      pool,expectedDatabase:'saas_staging_ci',
    });
    assert.equal((await read(a,ta,fresh())).kind,'authorized');
    assert.equal((await read(b,tb,fresh())).kind,'authorized');
    assert.deepEqual(await read(a,tb,fresh()),{kind:'denied'});
    assert.deepEqual(await read(b,ta,fresh()),{kind:'denied'});
    await noLogin(A);await noLogin(B);
    assert.equal(brokerCalls,4,
      'each physical PG login MUST require one fresh authenticated mTLS GET');
    assert.equal(authorizedRequests,brokerCalls);
    console.info('B16_COMBINED_MTLS_VAULT_NODEPG_RLS_TWO_TENANTS_PASS');
  }finally{await pool.shutdown();}

  const identityPool=createBackend16DisposableCiNodePgPhysicalPool(
    vault,pgTrust,Client);
  let pid:number;
  try{
    const c=await identityPool.acquirePrincipal(A,fresh());
    const signal=fresh();
    for(const sql of [SQL.begin,SQL.statementTimeout,SQL.lockTimeout])
      await c.query(sql,[],signal);
    const proof=await c.query(SQL.identity,[],signal);
    assert.equal(proof.rows[0].session_login,A);
    pid=proof.rows[0].backend_pid as number;
    assert.ok(Number.isSafeInteger(pid)&&pid>0);
    const tls=await admin.query(
      'SELECT ssl,version FROM pg_stat_ssl WHERE pid=$1',[String(pid)]);
    assert.equal(tls.rows.length,1);
    assert.equal(tls.rows[0].ssl,true);
    assert.ok(['TLSv1.2','TLSv1.3'].includes(tls.rows[0].version as string));
    await assert.rejects(c.release(true),/Backend16 Node PostgreSQL/);
    await gone(pid);
    console.info('B16_COMBINED_MTLS_AUTHENTICATED_PHYSICAL_TLS_PID_DISCARD');
  }finally{await identityPool.shutdown();}

  // A genuine accepted client mTLS request is PAUSED before HTTP 200.
  // Revoking the local approval during that request MUST yield NO vault
  // material and MUST NOT allocate an authenticated physical PostgreSQL PID.
  const blocked=createBackend16DisposableCiNodePgPhysicalPool(
    vault,pgTrust,Client);
  try{
    defer=true;
    const read=createBackend16ExactSqlReadPort({
      pool:blocked,expectedDatabase:'saas_staging_ci',
    });
    const pending=read(a,ta,fresh());
    await Promise.race([
      arrival,
      sleep(2000).then(()=>{throw Error('B16 broker mTLS request not reached');}),
    ]);
    e.SAAS_B16_BROKER_MTLS_CI='false';
    releaseReply?.();
    try{
      await assert.rejects(pending,
        /Backend16 exact SQL data source unavailable/);
    }finally{
      e.SAAS_B16_BROKER_MTLS_CI='true';
    }
    await noLogin(A);
    assert.equal(authorizedRequests,brokerCalls);
    console.info('B16_COMBINED_MTLS_INFLIGHT_REVOKED_NO_POSTGRES_LOGIN');
  }finally{
    e.SAAS_B16_BROKER_MTLS_CI='true';
    releaseReply?.();
    await blocked.shutdown();
  }
  console.info('PASS Backend16 combined mTLS broker vault Node PostgreSQL16 TLS tenant RLS');
}
try{await execute();}
finally{
  e.SAAS_B16_BROKER_MTLS_CI='true';
  if(adminConnected){
    try{await admin.query('ALTER SYSTEM RESET ssl');await reload();}
    catch{/* disposable PG only */}
    try{await admin.end();}catch{/* disposable only */}
  }
  if(server){
    server.closeAllConnections();
    await new Promise<void>(resolve=>server!.close(()=>resolve()));
  }
  rmSync(dir,{recursive:true,force:true});
}
