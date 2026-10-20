/**
 * Integrity-pinned upstream native SQL TLS acceptance (CI only).
 * Uses fresh GitHub Actions postgres:16.6; no SQL migrations or live data.
 * This NEVER authorizes a Bun runtime upgrade or staging deployment.
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

const e=process.env,id=e.SAAS_B16_CI_PG_CONTAINER??'';
if(e.GITHUB_ACTIONS!=='true'||e.SAAS_B16_EXPERIMENTAL_TLS_CI!=='true'||
   Bun.version!=='1.4.4'||Bun.revision!=='6bb5dc1956505dd1113455f58d4757c924f3ad54'||e.NODE_ENV==='production'||
   e.PGHOST!=='127.0.0.1'||e.PGPORT!=='5432'||
   e.PGDATABASE!=='saas_ephemeral_test'||
   e.PGPASSWORD!=='ci_ephemeral_test_only'||
   e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
   e.RAILWAY_PROJECT_ID||e.RAILWAY_ENVIRONMENT_ID||
   e.RAILWAY_SERVICE_ID||e.RAILWAY_ENVIRONMENT||
   !/^[0-9a-f]{64}$/.test(id))
  throw new Error('B16 native TLS version probe refused environment');
function command(tool:string,args:string[],cwd?:string):string{
  return execFileSync(tool,args,{cwd,encoding:'utf8',
    stdio:['ignore','pipe','ignore'],timeout:15000}).trim();
}
assert.equal(command('docker',['inspect','--format','{{.Config.Image}}',id]),
  'postgres:16.6');
assert.equal(command('docker',['exec',id,'printenv','PGDATA']),
  '/var/lib/postgresql/data');
const dir=mkdtempSync(join(tmpdir(),'b16-143-native-tls-'));
const HOST='postgres.railway.internal';
const admin=new SQL({
  adapter:'postgres',hostname:'127.0.0.1',port:5432,
  username:'postgres',password:'ci_ephemeral_test_only',
  database:'saas_ephemeral_test',max:1,prepare:false,
});
function root(name:string):string{
  command('openssl',[
    'req','-x509','-newkey','rsa:3072','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.pem',
    '-days','30','-subj','/CN=Disposable '+name,
    '-addext','basicConstraints=critical,CA:TRUE',
    '-addext','keyUsage=critical,keyCertSign,cRLSign',
  ],dir);
  return readFileSync(join(dir,name+'.pem'),'utf8');
}
function leaf(name:string,dns:string){
  command('openssl',[
    'req','-newkey','rsa:2048','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+HOST,
  ],dir);
  writeFileSync(join(dir,name+'.ext'),[
    'basicConstraints=critical,CA:FALSE',
    'keyUsage=digitalSignature,keyEncipherment',
    'extendedKeyUsage=serverAuth','subjectAltName=DNS:'+dns,
  ].join('\n')+'\n',{mode:0o600});
  command('openssl',[
    'x509','-req','-in',name+'.csr',
    '-CA','root.pem','-CAkey','root.key','-CAcreateserial',
    '-out',name+'.crt','-days','2','-sha256','-extfile',name+'.ext',
  ],dir);
}
function install(name:string){
  for(const suffix of ['crt','key'])
    command('docker',['cp',join(dir,name+'.'+suffix),
      id+':/tmp/b16-experiment-next.'+suffix]);
  command('docker',['exec','--user','root',id,'sh','-c',
    'mv /tmp/b16-experiment-next.crt /var/lib/postgresql/data/server.crt && '+
    'mv /tmp/b16-experiment-next.key /var/lib/postgresql/data/server.key && '+
    'chown postgres:postgres /var/lib/postgresql/data/server.crt '+
    '/var/lib/postgresql/data/server.key && '+
    'chmod 0600 /var/lib/postgresql/data/server.key']);
}
const pin=(pem:string)=>createHash('sha256')
  .update(new X509Certificate(pem).raw).digest('hex');
const trust=(pem:string)=>createBackend16StagingPgTlsTrust({
  caPem:pem,approvedCaDerSha256:pin(pem),
});
async function query(tls:Record<string,unknown>):Promise<boolean>{
  const sql=new SQL({
    adapter:'postgres',hostname:'127.0.0.1',port:5432,
    username:'postgres',password:'ci_ephemeral_test_only',
    database:'saas_ephemeral_test',max:1,prepare:false,tls,
  });
  try{
    const rows=await sql.unsafe(
      'SELECT s.ssl,s.version FROM pg_stat_ssl s '+
      'WHERE s.pid=pg_backend_pid()').execute();
    assert.equal(rows.length,1);
    assert.equal(rows[0].ssl,true);
    assert.ok(['TLSv1.2','TLSv1.3'].includes(rows[0].version));
    return true;
  }catch{
    return false;
  }finally{await sql.close({timeout:0});}
}
try{
  const goodRoot=root('root'),otherRoot=root('other-root');
  leaf('good',HOST);
  leaf('wildcard','*.railway.internal');
  assert.throws(()=>command('openssl',['verify','-CAfile',
    join(dir,'other-root.pem'),join(dir,'good.crt')]));
  install('good');
  assert.equal((await admin.unsafe('SHOW ssl').execute())[0].ssl,'off');
  await admin.unsafe("ALTER SYSTEM SET ssl='on'").execute();
  assert.equal((await admin.unsafe('SELECT pg_reload_conf()').execute())[0].pg_reload_conf,true);
  await Bun.sleep(300);

  const accepted=await query(trust(goodRoot));
  assert.equal(accepted,true,'valid root and exact SAN must connect');
  console.info('B16_PINNED_NATIVE_TLS_AUTHENTICATED_POSITIVE');

  let invoked=0;
  const denyAlways=await query({
    ...trust(goodRoot),
    checkServerIdentity:()=>{
      invoked++;return new Error('B16 expected deliberate callback rejection');
    },
  });
  console.info('B16_PINNED_NATIVE_ONE_ARG_ALWAYS_DENY_'+
    (!denyAlways&&invoked>0?'ENFORCED':'IGNORED'));
  console.info('B16_PINNED_NATIVE_ONE_ARG_CALLBACK_CALLS_'+invoked);

  // Determine whether the constructor accepts TLSOptions ONLY when the
  // connection URL and options are supplied as separate arguments.
  let urlInvoked=0,urlDenied=false;
  const urlSql=new SQL('postgres://postgres@127.0.0.1:5432/saas_ephemeral_test',{
    username:'postgres',password:'ci_ephemeral_test_only',
    max:1,prepare:false,
    tls:{...trust(goodRoot),checkServerIdentity:()=>{
      urlInvoked++;return new Error('B16 expected URL callback denial');
    }},
  });
  try{
    try{await urlSql.unsafe('SELECT 1 AS syntax_only').execute();}
    catch{urlDenied=true;}
  }finally{await urlSql.close({timeout:0});}
  console.info('B16_PINNED_NATIVE_TWO_ARG_URL_ALWAYS_DENY_'+
    (urlDenied&&urlInvoked>0?'ENFORCED':'IGNORED'));
  console.info('B16_PINNED_NATIVE_TWO_ARG_CALLBACK_CALLS_'+urlInvoked);

  const plaintext=new SQL({
    adapter:'postgres',hostname:'127.0.0.1',port:5432,
    username:'postgres',password:'ci_ephemeral_test_only',
    database:'saas_ephemeral_test',max:1,prepare:false,tls:'disable',
  });
  let sslDisabled=false;
  try{
    const plainRows=await plaintext.unsafe(
      'SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()').execute();
    sslDisabled=plainRows.length===1&&plainRows[0].ssl===false;
  }finally{await plaintext.close({timeout:0});}
  console.info('B16_PINNED_NATIVE_EXPLICIT_TLS_DISABLE_'+
    (sslDisabled?'HONORED':'IGNORED'));

  const wrongRootAccepted=await query(trust(otherRoot));
  console.info('B16_PINNED_NATIVE_TLS_WRONG_ROOT_'+
    (wrongRootAccepted?'UNEXPECTEDLY_ACCEPTED':'DENIED'));

  const wildcardCert=new X509Certificate(
    readFileSync(join(dir,'wildcard.crt'),'utf8'));
  assert.ok(wildcardCert.subjectAltName?.split(/,\s*/).includes(
    'DNS:*.railway.internal'),'fixture must contain a wildcard DNS SAN');
  assert.equal(wildcardCert.verify(new X509Certificate(goodRoot).publicKey),true,
    'wildcard leaf must really be signed by the pinned fixture CA');
  assert.ok(trust(goodRoot).checkServerIdentity(HOST,{
    raw:wildcardCert.raw,subjectaltname:wildcardCert.subjectAltName,
    subject:{CN:HOST},
  }) instanceof Error);
  install('wildcard');
  assert.equal((await admin.unsafe('SELECT pg_reload_conf()').execute())[0].pg_reload_conf,true);
  await Bun.sleep(300);
  const wildcardAccepted=await query(trust(goodRoot));
  console.info('B16_PINNED_NATIVE_TLS_WILDCARD_'+
    (wildcardAccepted?'UNEXPECTEDLY_ACCEPTED':'DENIED'));
  assert.ok(!denyAlways&&invoked>0&&urlDenied&&urlInvoked>0&&
    sslDisabled&&!wrongRootAccepted&&!wildcardAccepted,
    'STOP: Pinned native PostgreSQL TLS validation was not enforced');
  console.info('PASS Backend16 pinned native PG TLS peer validation');
}finally{
  await admin.close({timeout:0});
  rmSync(dir,{recursive:true,force:true});
}
