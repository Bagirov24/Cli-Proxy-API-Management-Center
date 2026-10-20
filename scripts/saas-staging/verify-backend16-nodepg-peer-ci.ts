/**
 * GitHub-only PostgreSQL16 Node TLS identity experiment; not runtime code.
 * Tests same authenticated physical PG connection, not a separate TLS probe.
 * The pinned node-postgres package is installed only into /tmp by its CI job.
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

const e=process.env;
const HOST='postgres.railway.internal';
const id=e.SAAS_B16_CI_PG_CONTAINER??'';
if(e.GITHUB_ACTIONS!=='true'||e.SAAS_B16_NODEPG_PEER_CI!=='true'||
   e.PGHOST!=='127.0.0.1'||e.PGPORT!=='5432'||
   e.PGUSER!=='postgres'||e.PGDATABASE!=='saas_ephemeral_test'||
   e.PGPASSWORD!=='ci_ephemeral_test_only'||
   e.NODE_ENV==='production'||e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
   e.RAILWAY_PROJECT_ID||e.RAILWAY_ENVIRONMENT_ID||
   e.RAILWAY_SERVICE_ID||e.RAILWAY_ENVIRONMENT||
   !/^[a-f0-9]{64}$/.test(id)||
   Number(process.versions.node.split('.')[0])!==24)
  throw Error('B16 Node PG experiment refused non-disposable CI');

const require=createRequire(import.meta.url);
const packageRoot='/tmp/b16-nodepg-peer/node_modules';
const pkg=require(packageRoot+'/pg/package.json') as {version:string};
if(pkg.version!=='8.23.1')throw Error('B16 Node PG candidate version refused');
type QueryResult={rows:Record<string,unknown>[]};
type ClientLike={
  connect():Promise<void>;
  query(text:string,values?:unknown[]):Promise<QueryResult>;
  end():Promise<void>;
  on(event:'error',cb:()=>void):unknown;
};
type ClientCtor=new(config:Record<string,unknown>)=>ClientLike;
const {Client}=require(packageRoot+'/pg') as {Client:ClientCtor};
function command(program:string,args:string[],cwd?:string){
  return execFileSync(program,args,{
    cwd,encoding:'utf8',stdio:['ignore','pipe','ignore'],timeout:15000,
  }).trim();
}
assert.equal(command('docker',['inspect','--format','{{.Config.Image}}',id]),
  'postgres:16.6');
assert.equal(command('docker',['exec',id,'printenv','PGDATA']),
  '/var/lib/postgresql/data');

const dir=mkdtempSync(join(tmpdir(),'b16-nodepg-peer-'));
function root(name:string):string{
  command('openssl',[
    'req','-x509','-newkey','rsa:3072','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.pem','-days','30',
    '-subj','/CN=B16 disposable CA '+name,
    '-addext','basicConstraints=critical,CA:TRUE',
    '-addext','keyUsage=critical,keyCertSign,cRLSign',
  ],dir);
  return readFileSync(join(dir,name+'.pem'),'utf8');
}
function leaf(name:string,san?:string){
  command('openssl',[
    'req','-newkey','rsa:2048','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.csr',
    '-subj','/CN='+HOST,
  ],dir);
  writeFileSync(join(dir,name+'.ext'),[
    'basicConstraints=critical,CA:FALSE',
    'keyUsage=digitalSignature,keyEncipherment',
    'extendedKeyUsage=serverAuth',
    ...(san?['subjectAltName=DNS:'+san]:[]),
  ].join('\n')+'\n',{mode:0o600});
  command('openssl',[
    'x509','-req','-in',name+'.csr',
    '-CA','root.pem','-CAkey','root.key','-CAcreateserial',
    '-out',name+'.crt','-days','2','-sha256',
    '-extfile',name+'.ext',
  ],dir);
}
function install(name:string){
  for(const ext of ['crt','key'])
    command('docker',['cp',join(dir,name+'.'+ext),
      id+':/tmp/b16-nodepg-next.'+ext]);
  command('docker',['exec','--user','root',id,'sh','-c',
    'mv /tmp/b16-nodepg-next.crt /var/lib/postgresql/data/server.crt && '+
    'mv /tmp/b16-nodepg-next.key /var/lib/postgresql/data/server.key && '+
    'chown postgres:postgres /var/lib/postgresql/data/server.crt '+
    '/var/lib/postgresql/data/server.key && '+
    'chmod 0600 /var/lib/postgresql/data/server.key']);
}
function freshClient(ssl:unknown,name:string):ClientLike{
  const client=new Client({
    host:'127.0.0.1',port:5432,database:'saas_ephemeral_test',
    user:'postgres',password:'ci_ephemeral_test_only',
    application_name:name,connectionTimeoutMillis:4000,
    ssl,
  });
  client.on('error',()=>{}); // TLS rejection expected in negative CI.
  return client;
}
const pin=(pem:string)=>createHash('sha256')
  .update(new X509Certificate(pem).raw).digest('hex');
function tlsOptions(pem:string){
  const branded=createBackend16StagingPgTlsTrust({
    caPem:pem,approvedCaDerSha256:pin(pem),
  });
  let called=0;
  return {
    options:{
      ca:branded.ca,servername:HOST,
      rejectUnauthorized:true,minVersion:'TLSv1.2',
      checkServerIdentity:(hostname:string,peer:unknown)=>{
        called++;
        if(hostname!==HOST)
          return new Error('B16 Node PG TLS SNI mismatch');
        return branded.checkServerIdentity(hostname,peer);
      },
    },
    calls:()=>called,
    branded,
  };
}
const admin=freshClient(false,'b16-nodepg-admin');
let adminConnected=false;
async function reload(){
  assert.equal((await admin.query('SELECT pg_reload_conf() AS ok')).rows[0].ok,true);
  await sleep(280);
}
async function ensureNoLogin(name:string){
  const result=await admin.query(
    'SELECT count(*)::int AS n FROM pg_stat_activity WHERE application_name=$1',
    [name]);
  assert.equal(result.rows[0].n,0,
    'TLS refusal must not leave an authenticated PostgreSQL backend');
}
async function expectTlsRefusal(
  tag:string,ssl:Record<string,unknown>,check:()=>void,
){
  const label='b16-nodepg-refused-'+tag;
  const client=freshClient(ssl,label);
  let connected=false;
  try{
    try{await client.connect();connected=true;}
    catch{/* expected TLS rejection; do not log certificate details */}
    assert.equal(connected,false,tag+' must refuse BEFORE DB login');
  }finally{try{await client.end();}catch{/* no live TLS socket */}}
  check();
  await ensureNoLogin(label);
  console.info('B16_NODEPG_'+tag+'_DENIED');
}
async function run(){
  const pem=root('root');
  const other=root('different-root');
  leaf('valid',HOST);
  leaf('wildcard','*.railway.internal');
  leaf('wrong-host','wrong.railway.internal');
  leaf('cn-only');
  const wc=new X509Certificate(readFileSync(join(dir,'wildcard.crt'),'utf8'));
  assert.equal(wc.verify(new X509Certificate(pem).publicKey),true);
  assert.equal(wc.checkHost(HOST),'*.railway.internal',
    'Node default hostname matcher accepts CA-valid wildcard; strict callback must refuse');
  assert.ok(tlsOptions(pem).branded.checkServerIdentity(HOST,{
    raw:wc.raw,subjectaltname:wc.subjectAltName,subject:{CN:HOST},
  }) instanceof Error,'same-CA wildcard must fail offline exact SAN predicate');

  await admin.connect();adminConnected=true;
  install('valid');
  assert.equal((await admin.query('SHOW ssl')).rows[0].ssl,'off');
  await admin.query("ALTER SYSTEM SET ssl='on'");
  await reload();
  assert.equal((await admin.query('SHOW ssl')).rows[0].ssl,'on');

  const selected=tlsOptions(pem);
  const client=freshClient(selected.options,'b16-nodepg-authorized');
  let pid:number=0;
  try{
    await client.connect();
    const result=await client.query(
      'SELECT current_user::text AS login,pg_backend_pid()::int AS pid,'+
      's.ssl,s.version FROM pg_stat_ssl s WHERE s.pid=pg_backend_pid()');
    assert.equal(result.rows.length,1);
    assert.equal(result.rows[0].login,'postgres');
    assert.equal(result.rows[0].ssl,true,'actual authenticated socket needs TLS');
    assert.ok(['TLSv1.2','TLSv1.3'].includes(result.rows[0].version as string));
    pid=result.rows[0].pid as number;
    assert.ok(Number.isSafeInteger(pid)&&pid>0);
    assert.equal(selected.calls(),1,
      'Node TLS exact identity callback must run on authenticated connection');
    console.info('B16_NODEPG_AUTHENTICATED_SSL_AND_EXACT_SAN_PASS');
  }finally{await client.end();}
  let gone=false;
  for(let i=0;i<40;i++){
    const rs=await admin.query(
      'SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid=$1',[pid]);
    if(rs.rows[0].n===0){gone=true;break;}
    await sleep(45);
  }
  assert.equal(gone,true,'physical backend must disappear after close');
  console.info('B16_NODEPG_PHYSICAL_PID_DISCARD_PASS');

  const trusted=tlsOptions(pem);
  let forced=0;
  await expectTlsRefusal('FORCED_CALLBACK',{
    ...trusted.options,checkServerIdentity:()=>{
      forced++;
      return new Error('B16 test forced identity denial');
    },
  },()=>assert.equal(forced,1,'must invoke forced callback before login'));
  const unrelated=tlsOptions(other);
  await expectTlsRefusal('WRONG_CA',unrelated.options,
    ()=>assert.equal(unrelated.calls(),0,'chain fails before hostname callback'));

  for(const [fixture,tag] of [
    ['wildcard','WILDCARD_SAN'],
    ['wrong-host','WRONG_SAN'],
    ['cn-only','CN_ONLY'],
  ]){
    install(fixture);
    await reload();
    const expected=tlsOptions(pem);
    await expectTlsRefusal(tag,expected.options,
      ()=>assert.equal(expected.calls(),1,
        'exact SAN predicate must reject CA-valid certificate'));
  }
  console.info('PASS Backend16 Node24 pg authenticated PostgreSQL peer verification');
}
try{await run();}
finally{
  if(adminConnected){
    try{await admin.query('ALTER SYSTEM RESET ssl');await reload();}
    catch{/* only temporary CI PG16 */ }
    try{await admin.end();}catch{/* only disposable */ }
  }
  rmSync(dir,{recursive:true,force:true});
}
