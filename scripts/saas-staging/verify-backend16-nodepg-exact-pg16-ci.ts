/**
 * CI-only Node pg same-socket verified TLS -> SQL0008 exact-session
 * -> two independent physical LOGINs -> tenant FORCE RLS -> COMMIT.
 *
 * ALL PostgreSQL data and private keys are disposable GitHub Actions fixtures.
 * This is not a staging/production listener, secret broker or runtime package.
 */
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,X509Certificate} from 'node:crypto';
import {readFileSync,writeFileSync,mkdtempSync,rmSync} from 'node:fs';
import {createRequire} from 'node:module';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as sleep} from 'node:timers/promises';
import {createBackend16StagingPgTlsTrust}
  from '../../src/features/saasBlueprint/controlApi/server/backend16StagingPgTlsTrust.ts';
import {createBackend16StagingVersionedPrincipalVault}
  from '../../src/features/saasBlueprint/controlApi/server/backend16StagingVersionedPrincipalVault.ts';
import {createBackend16DisposableCiMtlsSecretReader}
  from '../../src/features/saasBlueprint/controlApi/server/backend16PrivateMtlsVersionedSecretReader.ts';
import {startSyntheticBackend16MtlsBroker}
  from './backend16-nodepg-synthetic-mtls-broker-ci.ts';
import {createBackend16DisposableCiNodePgPhysicalPool,
  type Backend16NodePgClientConstructor}
  from '../../src/features/saasBlueprint/controlApi/server/backend16DisposableNodePgPhysicalPool.ts';
import {createBackend16ExactSqlReadPort,BACKEND16_EXACT_READ_SQL as SQL}
  from '../../src/features/saasBlueprint/controlApi/server/backend16ExactSessionSqlRead.ts';
import type {VerifiedPrincipal}
  from '../../src/features/saasBlueprint/controlApi/server/backend16PrivateTenantProjectRead.ts';

const e=process.env;
const A='saas_b14_person',B='saas_b16_person_b';
const HOST='postgres.railway.internal';
const id=e.SAAS_B16_CI_PG_CONTAINER??'';
const HEX=/^[a-f0-9]{64}$/;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
if(e.GITHUB_ACTIONS!=='true'||e.SAAS_B16_EPHEMERAL_CI!=='true'||
   e.SAAS_B16_NODEPG_PHYSICAL_CI!=='true'||
   e.SAAS_B16_BROKER_MTLS_CI!=='true'||
   e.PGHOST!=='127.0.0.1'||e.PGPORT!=='5432'||
   e.PGDATABASE!=='saas_ephemeral_test'||
   e.PGPASSWORD!=='ci_ephemeral_test_only'||
   e.NODE_ENV==='production'||e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
   e.RAILWAY_PROJECT_ID||e.RAILWAY_ENVIRONMENT_ID||
   e.RAILWAY_SERVICE_ID||e.RAILWAY_ENVIRONMENT||
   !HEX.test(id)||
   !HEX.test(e.SAAS_B16_CI_A_PASSWORD??'')||
   !HEX.test(e.SAAS_B16_CI_B_PASSWORD??'')||
   !HEX.test(e.SAAS_B16_CI_A_SUBJECT_SHA??'')||
   !HEX.test(e.SAAS_B16_CI_B_SUBJECT_SHA??'')||
   !['A','B'].every(k=>['TENANT','SESSION','BINDING'].every(f=>
     UUID.test(e['SAAS_B16_CI_'+k+'_'+f]??'')))||
   Number(process.versions.node.split('.')[0])!==24)
  throw Error('Backend16 Node PG exact RLS requires disposable GitHub CI');

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
assert.equal(command('docker',['inspect','--format','{{.Config.Image}}',id]),
  'postgres:16.6');
assert.equal(command('docker',['exec',id,'printenv','PGDATA']),
  '/var/lib/postgresql/data');

const dir=mkdtempSync(join(tmpdir(),'b16-nodepg-exact-'));
let activeBroker:Awaited<ReturnType<typeof startSyntheticBackend16MtlsBroker>>|undefined;
function root(name:string):string{
  command('openssl',[
    'req','-x509','-newkey','rsa:3072','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.pem','-days','30',
    '-subj','/CN=B16 Node PG exact ephemeral '+name,
    '-addext','basicConstraints=critical,CA:TRUE',
    '-addext','keyUsage=critical,keyCertSign,cRLSign',
  ],dir);
  return readFileSync(join(dir,name+'.pem'),'utf8');
}
function leaf(name:string,hostname:string){
  command('openssl',[
    'req','-newkey','rsa:2048','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+HOST,
  ],dir);
  writeFileSync(join(dir,name+'.ext'),[
    'basicConstraints=critical,CA:FALSE',
    'keyUsage=digitalSignature,keyEncipherment',
    'extendedKeyUsage=serverAuth',
    'subjectAltName=DNS:'+hostname,
  ].join('\n')+'\n',{mode:0o600});
  command('openssl',[
    'x509','-req','-in',name+'.csr','-CA','root.pem',
    '-CAkey','root.key','-CAcreateserial','-out',name+'.crt',
    '-days','2','-sha256','-extfile',name+'.ext',
  ],dir);
}
function install(name:string){
  for(const suffix of ['crt','key'])
    command('docker',['cp',join(dir,name+'.'+suffix),
      id+':/tmp/b16-nodepg-exact.'+suffix]);
  command('docker',['exec','--user','root',id,'sh','-c',
    'mv /tmp/b16-nodepg-exact.crt /var/lib/postgresql/data/server.crt && '+
    'mv /tmp/b16-nodepg-exact.key /var/lib/postgresql/data/server.key && '+
    'chown postgres:postgres /var/lib/postgresql/data/server.crt '+
    '/var/lib/postgresql/data/server.key && '+
    'chmod 0600 /var/lib/postgresql/data/server.key']);
}
const pin=(pem:string)=>createHash('sha256')
  .update(new X509Certificate(pem).raw).digest('hex');
const trust=(pem:string)=>createBackend16StagingPgTlsTrust({
  caPem:pem,approvedCaDerSha256:pin(pem),
});
const admin=new Client({
  host:'127.0.0.1',port:5432,database:'saas_staging_ci',
  user:'postgres',password:'ci_ephemeral_test_only',
  connectionTimeoutMillis:4000,ssl:false,
});
admin.on('error',()=>{});
let adminConnected=false;
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
async function scalar(sql:string,params:string[]=[]):Promise<unknown>{
  const result=await admin.query(sql,params);
  assert.equal(result.rows.length,1);
  return Object.values(result.rows[0])[0];
}
async function gone(pid:number,watcher:typeof admin=admin){
  for(let i=0;i<60;i++){
    // During a revoke race the admin session holds FOR UPDATE; using it
    // for this probe would keep an old pg_stat_activity snapshot until
    // ROLLBACK and falsely report a killed physical backend as still live.
    const observation=await watcher.query(
      'SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid=$1',
      [String(pid)]);
    assert.equal(observation.rows.length,1);
    if(observation.rows[0].n===0)return;
    await sleep(40);
  }
  throw Error('B16 Node PG authenticated backend PID survived physical close');
}
async function noLogin(login:string){
  assert.equal(await scalar(
    'SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname=$1 AND usename=$2',
    ['saas_staging_ci',login]),0);
}
async function reload(){
  assert.equal(await scalar('SELECT pg_reload_conf() AS ok'),true);
  await sleep(300);
}
async function execute(){
  const caPem=root('root'),otherRoot=root('unrelated');
  leaf('good',HOST);
  leaf('wildcard','*.railway.internal');
  const wildcard=new X509Certificate(
    readFileSync(join(dir,'wildcard.crt'),'utf8'));
  assert.equal(wildcard.verify(new X509Certificate(caPem).publicKey),true);
  assert.ok(trust(caPem).checkServerIdentity(HOST,{
    raw:wildcard.raw,subjectaltname:wildcard.subjectAltName,
    subject:{CN:HOST},
  }) instanceof Error);
  await admin.connect();adminConnected=true;
  install('good');
  await admin.query("ALTER SYSTEM SET ssl='on'");
  await reload();
  assert.equal(await scalar('SHOW ssl'),'on');

  const entries=[
    {pgLogin:A,secretId:'b16-stg-pg-'+('a'.repeat(20)),version:'a'.repeat(32)},
    {pgLogin:B,secretId:'b16-stg-pg-'+('b'.repeat(20)),version:'b'.repeat(32)},
  ];
  const digest=createHash('sha256').update(JSON.stringify({
    schema:'backend16-staging-vault-v1',
    entries:entries.map(x=>[x.pgLogin,x.secretId,x.version]),
  })).digest('hex');
  // Real loopback mTLS with a distinct ephemeral broker CA. Secrets remain
  // CI-generated and are only returned as exact immutable versions.
  const broker=await startSyntheticBackend16MtlsBroker(entries.map(x=>({
    ...x,password:e['SAAS_B16_CI_'+(x.pgLogin===A?'A':'B')+'_PASSWORD']!,
  })));
  activeBroker=broker;
  const reader=createBackend16DisposableCiMtlsSecretReader(
    broker.trust,broker.port);
  const vault=await createBackend16StagingVersionedPrincipalVault({
    manifest:{entries,approvedManifestSha256:digest},
    source:reader,
  });
  const a=principal(A),b=principal(B);
  const ta=e.SAAS_B16_CI_A_TENANT!,tb=e.SAAS_B16_CI_B_TENANT!;
  const first=createBackend16DisposableCiNodePgPhysicalPool(
    vault,trust(caPem),Client);
  try{
    const read=createBackend16ExactSqlReadPort({
      pool:first,expectedDatabase:'saas_staging_ci',
    });
    assert.equal((await read(a,ta,fresh())).kind,'authorized');
    assert.equal((await read(b,tb,fresh())).kind,'authorized');
    assert.deepEqual(await read(a,tb,fresh()),{kind:'denied'});
    assert.deepEqual(await read(b,ta,fresh()),{kind:'denied'});
    await noLogin(A);await noLogin(B);
    console.info('B16_NODEPG_EXACT_TWO_TENANT_TLS_RLS_PASS');
  }finally{await first.shutdown();}
  assert.ok(broker.calls()>=4,'each valid physical LOGIN must fetch a secret');
  assert.ok(broker.received.some(x=>x.pgLogin===A));
  assert.ok(broker.received.some(x=>x.pgLogin===B));
  console.info('B16_NODEPG_COMBINED_MTLS_VERSIONED_TLS_RLS_PASS');

  // Authenticated broker replies with an incorrect immutable version or a
  // stale lease must never result in PostgreSQL LOGIN authorization.
  for(const failure of ['wrong-version','expired'] as const){
    broker.choose(failure);
    const deniedPool=createBackend16DisposableCiNodePgPhysicalPool(
      vault,trust(caPem),Client);
    try{
      const deniedRead=createBackend16ExactSqlReadPort({
        pool:deniedPool,expectedDatabase:'saas_staging_ci',
      });
      await assert.rejects(deniedRead(a,ta,fresh()),
        /Backend16 exact SQL data source unavailable/);
      await noLogin(A);
    }finally{
      await deniedPool.shutdown();
      broker.choose('pass');
    }
  }
  console.info('B16_NODEPG_MTLS_WRONG_VERSION_AND_EXPIRED_PREAUTH_DENY');

  // The mTLS handshake and GET may already have succeeded, but the
  // server-held approval can still be revoked before HTTP 200 is received.
  broker.choose('deferred');
  const revokePool=createBackend16DisposableCiNodePgPhysicalPool(
    vault,trust(caPem),Client);
  try{
    const deniedRead=createBackend16ExactSqlReadPort({
      pool:revokePool,expectedDatabase:'saas_staging_ci',
    });
    const pending=deniedRead(a,ta,fresh());
    const settled=pending.then(()=>false,()=>true);
    await broker.waitForDeferred();
    process.env.SAAS_B16_BROKER_MTLS_CI='false';
    broker.releaseDeferred();
    assert.equal(await settled,true,'revoked workload cannot receive secret');
    await noLogin(A);
    console.info('B16_NODEPG_MTLS_REVOKED_IN_FLIGHT_PREAUTH_DENY');
  }finally{
    process.env.SAAS_B16_BROKER_MTLS_CI='true';
    broker.choose('pass');
    await revokePool.shutdown();
  }

  const physical=createBackend16DisposableCiNodePgPhysicalPool(
    vault,trust(caPem),Client);
  let pid:number;
  try{
    const conn=await physical.acquirePrincipal(A,fresh());
    const signal=fresh();
    for(const sql of [SQL.begin,SQL.statementTimeout,SQL.lockTimeout])
      await conn.query(sql,[],signal);
    const identity=await conn.query(SQL.identity,[],signal);
    assert.equal(identity.rows[0].session_login,A);
    pid=identity.rows[0].backend_pid as number;
    assert.ok(Number.isSafeInteger(pid)&&pid>0);
    const tls=await admin.query(
      'SELECT ssl,version FROM pg_stat_ssl WHERE pid=$1',[String(pid)]);
    assert.equal(tls.rows.length,1);
    assert.equal(tls.rows[0].ssl,true);
    assert.ok(['TLSv1.2','TLSv1.3'].includes(tls.rows[0].version as string));
    await assert.rejects(conn.release(true),/Backend16 Node PostgreSQL/);
    await gone(pid);
    console.info('B16_NODEPG_EXACT_PHYSICAL_SSL_PID_DISCARD_PASS');
  }finally{await physical.shutdown();}

  const wrong=createBackend16DisposableCiNodePgPhysicalPool(
    vault,trust(otherRoot),Client);
  try{
    const read=createBackend16ExactSqlReadPort({
      pool:wrong,expectedDatabase:'saas_staging_ci',
    });
    await assert.rejects(read(a,ta,fresh()),
      /Backend16 exact SQL data source unavailable/);
    await noLogin(A);
    console.info('B16_NODEPG_EXACT_WRONG_CA_PREAUTH_DENY');
  }finally{await wrong.shutdown();}

  install('wildcard');await reload();
  const badSan=createBackend16DisposableCiNodePgPhysicalPool(
    vault,trust(caPem),Client);
  try{
    const read=createBackend16ExactSqlReadPort({
      pool:badSan,expectedDatabase:'saas_staging_ci',
    });
    await assert.rejects(read(a,ta,fresh()),
      /Backend16 exact SQL data source unavailable/);
    await noLogin(A);
    console.info('B16_NODEPG_EXACT_CA_VALID_WILDCARD_PREAUTH_DENY');
  }finally{await badSan.shutdown();}
  // Restore approved exact certificate before the baseline CI revoke races.
  install('good');await reload();
  // Prove certificate rotation really restored authenticated exact-SAN TLS
  // before a second test intentionally stalls on the authorization row lock.
  const restoredPool=createBackend16DisposableCiNodePgPhysicalPool(
    vault,trust(caPem),Client);
  try{
    const restoredRead=createBackend16ExactSqlReadPort({
      pool:restoredPool,expectedDatabase:'saas_staging_ci',
    });
    assert.equal((await restoredRead(a,ta,fresh())).kind,'authorized');
  }finally{await restoredPool.shutdown();}
  console.info('B16_NODEPG_EXACT_RESTORED_TLS_PRE_LOCK_PASS');

  // Real PG16 FOR UPDATE competing with exact-session FOR SHARE: cancel the
  // waiting physical client and prove its socket dies with no data published.
  const waitingPool=createBackend16DisposableCiNodePgPhysicalPool(
    vault,trust(caPem),Client);
  // Monitoring must use a DIFFERENT physical transaction from the row-lock
  // holder. PostgreSQL can cache statistics for an observer within a long
  // transaction; never infer a concurrent lock from its own snapshot.
  const observer=new Client({
    host:'127.0.0.1',port:5432,database:'saas_staging_ci',
    user:'postgres',password:'ci_ephemeral_test_only',
    connectionTimeoutMillis:4000,ssl:false,
  });
  observer.on('error',()=>{});
  let locked=false,observerConnected=false;
  try{
    await observer.connect();observerConnected=true;
    await admin.query('BEGIN');
    locked=true;
    const row=await admin.query(
      'SELECT access_revision FROM saas_acl.principal_tenants '+
      'WHERE principal_name=$1 AND tenant_id=$2 FOR UPDATE',[A,ta]);
    assert.equal(row.rows.length,1);
    const read=createBackend16ExactSqlReadPort({
      pool:waitingPool,expectedDatabase:'saas_staging_ci',
    });
    const cancel=new AbortController();
    const waiting=read(a,ta,cancel.signal);
    // Consume early rejection immediately. A legitimate lock wait must be
    // independently observed BEFORE cancellation, not inferred from failure.
    let readSettled=false;
    const refused=assert.rejects(waiting,
      /Backend16 exact SQL data source unavailable/)
      .then(()=>{readSettled=true;});
    let waitingPid=0;
    for(let i=0;i<280&&!readSettled;i++){
      const rows=await observer.query(
        "SELECT pid::int AS pid FROM pg_stat_activity WHERE datname=$1 "+
        "AND usename=$2 AND application_name=$3 "+
        "AND wait_event_type='Lock' LIMIT 1",
        ['saas_staging_ci',A,'b16-nodepg-exact-ci']);
      if(rows.rows.length===1&&Number.isSafeInteger(rows.rows[0].pid)){
        waitingPid=rows.rows[0].pid as number;break;
      }
      await sleep(18);
    }
    assert.ok(waitingPid>0,
      'exact PG read must genuinely wait on current grant before cancellation');
    cancel.abort();
    await refused;
    await gone(waitingPid,observer);
    console.info('B16_NODEPG_EXACT_LOCK_ABORT_PID_DEATH_PASS');
  }finally{
    if(locked){try{await admin.query('ROLLBACK');}catch{/* CI only */}}
    if(observerConnected){try{await observer.end();}catch{/* CI only */}}
    await waitingPool.shutdown();
  }
  assert.ok(broker.calls()>=10,
    'each physical LOGIN must fetch a new mutually authenticated exact-version secret');
  assert.ok(broker.received.every(x=>entries.some(y=>
    x.pgLogin===y.pgLogin&&x.secretId===y.secretId&&x.version===y.version)),
    'broker must refuse alias versions and enumeration');
  console.info('PASS Backend16 Node PG real TLS exact SQL0008 two-tenant PG16 RLS');
  console.info('PASS Backend16 Node PG synthetic mTLS broker vault PG16 RLS full chain');
}
try{await execute();}
finally{
  if(activeBroker){try{await activeBroker.close();}catch{/* disposable CI */}}
  if(adminConnected){
    try{await admin.query('ALTER SYSTEM RESET ssl');await reload();}
    catch{/* CI service is thrown away */}
    try{await admin.end();}catch{/* CI only */}
  }
  rmSync(dir,{recursive:true,force:true});
}
