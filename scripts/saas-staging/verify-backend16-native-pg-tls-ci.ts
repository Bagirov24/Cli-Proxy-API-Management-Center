/**
 * Disposable GitHub PostgreSQL16 ONLY: real native Bun.SQL verify-full TLS,
 * exact principal LOGIN, tenant RLS, physical socket disposal and CA/SAN deny.
 * Synthetic certificates are minted in /tmp and installed on the GitHub
 * postgres:16.6 service container selected by job.services.postgres.id.
 * No Railway, persistent SQL0008, production database or external endpoint.
 */
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,X509Certificate} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {SQL} from 'bun';
import {createBackend16StagingPgTlsTrust}
  from '../../src/features/saasBlueprint/controlApi/server/backend16StagingPgTlsTrust.ts';
import {createBackend16StagingDisposableCiTlsPhysicalPgPool}
  from '../../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts';
import {createBackend16StagingVersionedPrincipalVault}
  from '../../src/features/saasBlueprint/controlApi/server/backend16StagingVersionedPrincipalVault.ts';
import {createBackend16ExactSqlReadPort,BACKEND16_EXACT_READ_SQL}
  from '../../src/features/saasBlueprint/controlApi/server/backend16ExactSessionSqlRead.ts';
import type {VerifiedPrincipal}
  from '../../src/features/saasBlueprint/controlApi/server/backend16PrivateTenantProjectRead.ts';

const env=process.env;
const LOGIN_A='saas_b14_person',LOGIN_B='saas_b16_person_b';
const HOST='postgres.railway.internal';
const HEX=/^[a-f0-9]{64}$/;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const dockerId=env.SAAS_B16_CI_PG_CONTAINER??'';
if(env.GITHUB_ACTIONS!=='true'||
   env.SAAS_B16_EPHEMERAL_CI!=='true'||
   env.SAAS_B16_PHYSICAL_CI!=='true'||
   env.SAAS_B16_PHYSICAL_TLS_CI!=='true'||
   env.PGHOST!=='127.0.0.1'||env.PGPORT!=='5432'||
   env.PGDATABASE!=='saas_ephemeral_test'||
   env.PGPASSWORD!=='ci_ephemeral_test_only'||
   env.NODE_ENV==='production'||env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
   env.RAILWAY_PROJECT_ID||env.RAILWAY_SERVICE_ID||
   env.RAILWAY_ENVIRONMENT_ID||env.RAILWAY_ENVIRONMENT||
   !HEX.test(dockerId)||
   !HEX.test(env.SAAS_B16_CI_A_PASSWORD??'')||
   !HEX.test(env.SAAS_B16_CI_B_PASSWORD??'')||
   !HEX.test(env.SAAS_B16_CI_A_SUBJECT_SHA??'')||
   !HEX.test(env.SAAS_B16_CI_B_SUBJECT_SHA??'')||
   !['A','B'].every(k=>
     ['TENANT','SESSION','BINDING'].every(field=>
       UUID.test(env['SAAS_B16_CI_'+k+'_'+field]??'')))){
  throw new Error('B16 native SQL TLS refused non-disposable CI environment');
}

function command(tool:string,args:string[],cwd?:string):string{
  return execFileSync(tool,args,{
    cwd,encoding:'utf8',stdio:['ignore','pipe','ignore'],timeout:15000,
  }).trim();
}
assert.equal(command('docker',['inspect','--format','{{.Config.Image}}',dockerId]),
  'postgres:16.6','only the exact disposable GitHub PG16 container');
assert.equal(command('docker',['exec',dockerId,'printenv','PGDATA']),
  '/var/lib/postgresql/data');

const dir=mkdtempSync(join(tmpdir(),'b16-native-pg-tls-'));
const admin=new SQL({
  adapter:'postgres',hostname:'127.0.0.1',port:5432,
  username:'postgres',database:'saas_staging_ci',
  password:'ci_ephemeral_test_only',max:3,prepare:false,
  connectionTimeout:4,idleTimeout:0,
});
const fresh=()=>new AbortController().signal;
const pin=(pem:string)=>createHash('sha256')
  .update(new X509Certificate(pem).raw).digest('hex');
function root(name:string){
  command('openssl',[
    'req','-x509','-newkey','rsa:3072','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.pem','-days','30',
    '-subj','/CN=Backend16 Disposable native TLS root '+name,
    '-addext','basicConstraints=critical,CA:TRUE',
    '-addext','keyUsage=critical,keyCertSign,cRLSign',
  ],dir);
  return readFileSync(join(dir,name+'.pem'),'utf8');
}
function leaf(name:string,san:string){
  command('openssl',[
    'req','-newkey','rsa:2048','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.csr',
    '-subj','/CN='+HOST,
  ],dir);
  writeFileSync(join(dir,name+'.ext'),[
    'basicConstraints=critical,CA:FALSE',
    'keyUsage=digitalSignature,keyEncipherment',
    'extendedKeyUsage=serverAuth','subjectAltName=DNS:'+san,
  ].join('\n')+'\n',{mode:0o600});
  command('openssl',[
    'x509','-req','-in',name+'.csr',
    '-CA','root.pem','-CAkey','root.key','-CAcreateserial',
    '-out',name+'.crt','-days','2','-sha256',
    '-extfile',name+'.ext',
  ],dir);
}
function installCertificate(name:string){
  // Docker operations are restricted to the exact ephemeral GitHub service.
  for(const ext of ['crt','key']){
    command('docker',['cp',join(dir,name+'.'+ext),
      dockerId+':/tmp/b16-ci-next.'+ext]);
  }
  command('docker',['exec','--user','root',dockerId,'sh','-c',
    'mv /tmp/b16-ci-next.crt /var/lib/postgresql/data/server.crt && '+
    'mv /tmp/b16-ci-next.key /var/lib/postgresql/data/server.key && '+
    'chown postgres:postgres /var/lib/postgresql/data/server.crt '+
    '/var/lib/postgresql/data/server.key && '+
    'chmod 0600 /var/lib/postgresql/data/server.key']);
}
async function scalar(query:string,params:string[]=[]):Promise<unknown>{
  const rows=await admin.unsafe(query,params).execute();
  assert.equal(rows.length,1);
  return Object.values(rows[0])[0];
}
async function reloadTls(){
  assert.equal(await scalar('SELECT pg_reload_conf()'),true);
  await Bun.sleep(300);
  assert.equal(await scalar('SHOW ssl'),'on');
}
async function gone(login:string){
  for(let i=0;i<35;i++){
    const active=await scalar(
      'SELECT count(*)::int AS count FROM pg_stat_activity '+
      'WHERE datname=$1 AND usename=$2',['saas_staging_ci',login]);
    if(active===0)return;
    await Bun.sleep(60);
  }
  throw new Error('B16 native TLS physical backend survived close');
}
function principal(letter:'A'|'B'):VerifiedPrincipal{
  return Object.freeze({
    kind:'verified-server-session',
    issuer:'https://ci-b16-idp.invalid',
    pgLogin:letter==='A'?LOGIN_A:LOGIN_B,
    subjectFingerprintSha256:env['SAAS_B16_CI_'+letter+'_SUBJECT_SHA']!,
    sessionId:env['SAAS_B16_CI_'+letter+'_SESSION']!,
    bindingId:env['SAAS_B16_CI_'+letter+'_BINDING']!,
    sessionExpiresAtMs:Date.now()+180_000,
  });
}
const credentials=new Map([
  [LOGIN_A,env.SAAS_B16_CI_A_PASSWORD!],
  [LOGIN_B,env.SAAS_B16_CI_B_PASSWORD!],
]);
const entries=[
  {pgLogin:LOGIN_A,secretId:'b16-stg-pg-'+('a'.repeat(20)),version:'a'.repeat(32)},
  {pgLogin:LOGIN_B,secretId:'b16-stg-pg-'+('b'.repeat(20)),version:'b'.repeat(32)},
];
let vaultCalls=0;
async function makeVault(){
  const digest=createHash('sha256').update(JSON.stringify({
    schema:'backend16-staging-vault-v1',
    entries:entries.map(x=>[x.pgLogin,x.secretId,x.version]),
  })).digest('hex');
  return createBackend16StagingVersionedPrincipalVault({
    manifest:{entries,approvedManifestSha256:digest},
    source:{
      async readVersion(id,version,signal){
        vaultCalls++;
        const selected=entries.find(x=>x.secretId===id&&x.version===version);
        if(!selected||signal.aborted)return null;
        return {username:selected.pgLogin,
          password:credentials.get(selected.pgLogin),
          version,expiresAtMs:Date.now()+120000};
      },
    },
  });
}
try{
  const rootPem=root('root');
  const wrongPem=root('wrong-root');
  leaf('valid',HOST);
  leaf('wildcard','*.railway.internal');
  assert.throws(()=>command('openssl',[ 'verify','-CAfile',
    join(dir,'wrong-root.pem'),join(dir,'valid.crt')]));
  const approved=createBackend16StagingPgTlsTrust({
    caPem:rootPem,approvedCaDerSha256:pin(rootPem),
  });
  const unrelatedRoot=createBackend16StagingPgTlsTrust({
    caPem:wrongPem,approvedCaDerSha256:pin(wrongPem),
  });
  const vault=await makeVault();
  installCertificate('valid');
  assert.equal(await scalar('SHOW ssl'),'off',
    'disposable postgres service is expected to start without TLS');
  await admin.unsafe("ALTER SYSTEM SET ssl='on'").execute();
  await reloadTls();
  console.info('B16_NATIVE_SQL_TLS_EPHEMERAL_PG_ENABLED');

  const pool=createBackend16StagingDisposableCiTlsPhysicalPgPool(
    vault,approved);
  const read=createBackend16ExactSqlReadPort({
    pool,expectedDatabase:'saas_staging_ci',
  });
  const a=principal('A'),b=principal('B');
  const ta=env.SAAS_B16_CI_A_TENANT!,tb=env.SAAS_B16_CI_B_TENANT!;
  try{
    const connection=await pool.acquirePrincipal(LOGIN_A,fresh());
    for(const sql of [
      BACKEND16_EXACT_READ_SQL.begin,
      BACKEND16_EXACT_READ_SQL.statementTimeout,
      BACKEND16_EXACT_READ_SQL.lockTimeout,
    ])await connection.query(sql,[],fresh());
    const identity=await connection.query(
      BACKEND16_EXACT_READ_SQL.identity,[],fresh());
    const pid=identity.rows[0].backend_pid;
    assert.equal(identity.rows[0].session_login,LOGIN_A);
    assert.ok(Number.isSafeInteger(pid));
    const pgSsl=await admin.unsafe(
      'SELECT ssl,version FROM pg_stat_ssl WHERE pid=$1',
      [String(pid)]).execute();
    assert.equal(pgSsl.length,1);
    assert.equal(pgSsl[0].ssl,true,
      'authenticated principal must use native TLS on that physical PID');
    assert.ok(['TLSv1.2','TLSv1.3'].includes(pgSsl[0].version));
    await assert.rejects(connection.release(true),/discarded/);
    await gone(LOGIN_A);
    console.info('B16_NATIVE_SQL_TLS_REAL_PID_VERIFIED');

    assert.equal((await read(a,ta,fresh())).kind,'authorized');
    assert.equal((await read(b,tb,fresh())).kind,'authorized');
    assert.deepEqual(await read(a,tb,fresh()),{kind:'denied'});
    assert.deepEqual(await read(b,ta,fresh()),{kind:'denied'});
    await gone(LOGIN_A);
    await gone(LOGIN_B);
    console.info('B16_NATIVE_SQL_TLS_TWO_TENANT_RLS_PASS');
  }finally{await pool.shutdown();}

  // An unconditionally refusing callback must run before ANY SQL login.
  // This independent probe distinguishes TLS verification from merely
  // having pg_stat_ssl.ssl=true (encryption without trusted identity).
  let alwaysDenyFired=false;
  const rejectAll=new SQL({
    adapter:'postgres',hostname:'127.0.0.1',port:5432,
    username:LOGIN_A,password:credentials.get(LOGIN_A),
    database:'saas_staging_ci',max:1,prepare:false,
    tls:{ca:rootPem,serverName:HOST,rejectUnauthorized:true,
      checkServerIdentity:()=>{
        alwaysDenyFired=true;
        return new Error('B16 intentionally rejected native TLS callback');
      },
    },
  });
  let forcedCallbackDenied=false;
  try{
    try{await rejectAll.unsafe('SELECT 1 AS synthetic_probe').execute();}
    catch{forcedCallbackDenied=true;}
  }finally{await rejectAll.close({timeout:0});}
  console.info('B16_NATIVE_SQL_TLS_ALWAYS_DENY_CALLBACK_'+
    (forcedCallbackDenied&&alwaysDenyFired?'ENFORCED':'NOT_ENFORCED'));

  const wrongRootPool=createBackend16StagingDisposableCiTlsPhysicalPgPool(
    vault,unrelatedRoot);
  let wrongRootDenied=false;
  try{
    const rejected=createBackend16ExactSqlReadPort({
      pool:wrongRootPool,expectedDatabase:'saas_staging_ci',
    });
    try{await rejected(a,ta,fresh());}
    catch{wrongRootDenied=true;}
    await gone(LOGIN_A);
    console.info('B16_NATIVE_SQL_TLS_WRONG_ROOT_'+
      (wrongRootDenied?'DENIED':'UNEXPECTEDLY_ACCEPTED'));
  }finally{await wrongRootPool.shutdown();}

  // Node's default DNS matcher WOULD accept this same-CA wildcard.
  const wildcard=new X509Certificate(
    readFileSync(join(dir,'wildcard.crt'),'utf8'));
  assert.equal(wildcard.checkHost(HOST),HOST);
  assert.ok(approved.checkServerIdentity(HOST,{
    raw:wildcard.raw,subjectaltname:wildcard.subjectAltName,
    subject:{CN:HOST},
  }) instanceof Error);
  installCertificate('wildcard');
  await reloadTls();
  const wildcardPool=createBackend16StagingDisposableCiTlsPhysicalPgPool(
    vault,approved);
  let wildcardDenied=false;
  try{
    const rejected=createBackend16ExactSqlReadPort({
      pool:wildcardPool,expectedDatabase:'saas_staging_ci',
    });
    try{await rejected(a,ta,fresh());}
    catch{wildcardDenied=true;}
    await gone(LOGIN_A);
    console.info('B16_NATIVE_SQL_TLS_CA_SIGNED_WILDCARD_'+
      (wildcardDenied?'DENIED':'UNEXPECTEDLY_ACCEPTED'));
  }finally{await wildcardPool.shutdown();}

  assert.ok(forcedCallbackDenied&&alwaysDenyFired&&wrongRootDenied&&wildcardDenied,
    'STOP: native Bun.SQL TLS trust/identity negative probe was accepted');
  assert.ok(vaultCalls>=7,
    'every physical attempt requires a fresh immutable-version vault read');
  console.info('PASS Backend16 native Bun.SQL TLS to real disposable PG16');
}finally{
  await admin.close({timeout:0});
  rmSync(dir,{recursive:true,force:true});
}
