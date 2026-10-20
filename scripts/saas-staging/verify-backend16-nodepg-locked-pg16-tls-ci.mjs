/**
 * LOCKED NODE PG — DISPOSABLE GITHUB CI ONLY
 *
 * This verifies that an npm-integrity-checked pg@8.23.1 installed into
 * two temporary, independently approved directories really authenticates
 * PostgreSQL16 over strict peer-verified TLS.
 * It creates throwaway CA and leaf certificates for the job's PG16 Docker
 * service. This does NOT grant production access or establish tenant RLS.
 */
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {X509Certificate} from 'node:crypto';
import {existsSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {pathToFileURL} from 'node:url';
import {EXPECTED_PG_VERSION} from './verify-backend16-nodepg-runtime-lock.mjs';

const HOST='postgres.railway.internal';
const DB='saas_ephemeral_test';
const LOGIN='b16_locked_pg_ci';
const PASSWORD='only_ci_disposable_pg16_client_20261020';
const REFUSED='Backend16 locked NodePG physical TLS CI refused';
const CONTAINER=/^[a-f0-9]{64}$/;
const SSL_TRUE=true;
function refuse(){throw new Error(REFUSED);}

export function enforceLockedPg16CiEnvironment(env,nodeMajor){
  if(!env||env.GITHUB_ACTIONS!=='true'||env.CI!=='true'||
     env.SAAS_B16_LOCKED_PG16_CI!=='true'||nodeMajor!==24||
     env.PGHOST!=='127.0.0.1'||env.PGPORT!=='5432'||
     env.PGDATABASE!==DB||env.PGUSER!=='postgres'||
     env.PGPASSWORD!=='ci_ephemeral_test_only'||
     !CONTAINER.test(env.SAAS_B16_NODEPG_PG16_CONTAINER??'')||
     env.NODE_ENV==='production'||env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
     env.RAILWAY_PROJECT_ID||env.RAILWAY_SERVICE_ID||
     env.RAILWAY_ENVIRONMENT_ID||env.RAILWAY_ENVIRONMENT||
     env.RAILWAY_PROJECT_NAME||env.RAILWAY_ENVIRONMENT_NAME)
    refuse();
}
function run(cmd,args,cwd,timeout=20000){
  const result=spawnSync(cmd,args,{
    cwd,encoding:'utf8',stdio:['ignore','pipe','pipe'],
    timeout,maxBuffer:1024*512,
  });
  // Avoid logging raw tool output (could contain credentials, private paths).
  if(result.error||result.signal||result.status!==0)refuse();
  return String(result.stdout).trim();
}
export function exactLockedPg16ServerIdentity(hostname,peer){
  const denied=()=>new Error('Backend16 locked NodePG TLS SAN refused');
  if(hostname!==HOST||!peer||typeof peer!=='object')return denied();
  try{
    const raw=peer.raw;
    if(!(raw instanceof Uint8Array)||raw.length<256||raw.length>32768)
      return denied();
    const cert=new X509Certificate(raw);
    if(!cert.subjectAltName?.split(/,\s*/).includes('DNS:'+HOST)||
       cert.checkHost(HOST,{subject:'never',wildcards:false})!==HOST)
      return denied();
    // Preserve Node TLS host validation in addition to exact SAN matching.
    // This callback is supplied to the *actual authenticated pg.Client*.
    return checkPeerHostname(hostname,peer)??undefined;
  }catch{return denied();}
}
import {checkServerIdentity as checkPeerHostname} from 'node:tls';

function makeCa(dir,name){
  run('openssl',[
    'req','-x509','-newkey','rsa:3072','-nodes','-sha256',
    '-keyout',name+'.key','-out',name+'.pem','-days','2',
    '-subj','/CN=B16 locked NodePG throwaway '+name,
    '-addext','basicConstraints=critical,CA:TRUE',
    '-addext','keyUsage=critical,keyCertSign,cRLSign',
  ],dir);
  return readFileSync(join(dir,name+'.pem'),'utf8');
}
function makeLeaf(dir,label,san){
  run('openssl',[
    'req','-newkey','rsa:2048','-nodes','-sha256',
    '-keyout',label+'.key','-out',label+'.csr',
    '-subj','/CN='+HOST,
  ],dir);
  writeFileSync(join(dir,label+'.ext'),[
    'basicConstraints=critical,CA:FALSE',
    'keyUsage=digitalSignature,keyEncipherment',
    'extendedKeyUsage=serverAuth',
    'subjectAltName=DNS:'+san,
  ].join('\n')+'\n',{mode:0o600});
  run('openssl',[
    'x509','-req','-in',label+'.csr','-CA','root.pem',
    '-CAkey','root.key','-CAcreateserial',
    '-out',label+'.crt','-days','2','-sha256',
    '-extfile',label+'.ext',
  ],dir);
}
function clientCtor(dir){
  if(typeof dir!=='string'||!existsSync(join(dir,'package-lock.json')))refuse();
  const require=createRequire(pathToFileURL(join(dir,'package.json')));
  const metadata=require('pg/package.json');
  if(metadata.name!=='pg'||metadata.version!==EXPECTED_PG_VERSION)refuse();
  const imported=require('pg');
  if(typeof imported.Client!=='function')refuse();
  return imported.Client;
}
function createClient(Client,ca,track){
  return new Client({
    host:'127.0.0.1',port:5432,database:DB,
    user:LOGIN,password:PASSWORD,
    connectionTimeoutMillis:4000,
    statement_timeout:4000,
    application_name:'b16-locked-pg16-ci',
    ssl:{
      ca,servername:HOST,rejectUnauthorized:true,
      minVersion:'TLSv1.2',
      checkServerIdentity:(hostname,peer)=>{
        track.callbacks++;
        return exactLockedPg16ServerIdentity(hostname,peer);
      },
    },
  });
}
function applyCert(container,dir,label){
  for(const ext of ['crt','key']){
    run('docker',['cp',join(dir,label+'.'+ext),
      container+':/tmp/b16-locked-pg16.'+ext],dir);
  }
  // Target is the throwaway postgres:16.6 GH Actions service only.
  run('docker',['exec','--user','root',container,'sh','-c',
    'set -eu; mv /tmp/b16-locked-pg16.crt "$PGDATA/server.crt"; '+
    'mv /tmp/b16-locked-pg16.key "$PGDATA/server.key"; '+
    'chown postgres:postgres "$PGDATA/server.crt" "$PGDATA/server.key"; '+
    'chmod 0600 "$PGDATA/server.key"'],dir);
  run('docker',['exec','--user','postgres',container,'psql',
    '-X','-v','ON_ERROR_STOP=1','-d',DB,'-c','SELECT pg_reload_conf();'],dir);
}
async function connectAndRead(Client,ca){
  const track={callbacks:0};
  const client=createClient(Client,ca,track);
  client.on('error',()=>{});
  try{
    await client.connect();
    const result=await client.query(
      'SELECT pg_backend_pid()::int AS pid, session_user::text AS login, '+
      '(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) AS tls');
    const row=result.rows?.[0];
    if(result.rows?.length!==1||!Number.isSafeInteger(row?.pid)||
       row.pid<=0||row.login!==LOGIN||row.tls!==SSL_TRUE||track.callbacks<1)
      refuse();
    return row.pid;
  }finally{
    client.connection?.stream?.destroy();
    await client.end().catch(()=>{});
  }
}
async function expectRefused(Client,ca,requireCallback){
  const track={callbacks:0};
  const client=createClient(Client,ca,track);
  client.on('error',()=>{});
  let authenticated=false;
  try{
    await client.connect();
    authenticated=true;
  }catch{
    // A negative MUST fail before an authenticated SQL query is possible.
  }finally{
    client.connection?.stream?.destroy();
    await client.end().catch(()=>{});
  }
  if(authenticated||(requireCallback&&track.callbacks<1))refuse();
}
export async function runLockedPg16PhysicalTlsCi(dirs){
  enforceLockedPg16CiEnvironment(
    process.env,Number(process.versions.node.split('.')[0]));
  if(!Array.isArray(dirs)||dirs.length!==2||
     dirs[0]===dirs[1]||dirs.some(x=>typeof x!=='string'))refuse();
  const clients=dirs.map(clientCtor);
  const id=process.env.SAAS_B16_NODEPG_PG16_CONTAINER;
  if(run('docker',['inspect','--format','{{.Config.Image}}',id])!==
      'postgres:16.6'||run('docker',['exec',id,'printenv','PGDATA'])!==
      '/var/lib/postgresql/data')refuse();
  const dir=mkdtempSync(join(tmpdir(),'b16-locked-pg16-tls-'));
  try{
    const root=makeCa(dir,'root');
    const wrong=makeCa(dir,'wrong');
    makeLeaf(dir,'exact',HOST);
    makeLeaf(dir,'wildcard','*.railway.internal');
    applyCert(id,dir,'exact');
    run('docker',['exec','--user','postgres',id,'psql',
      '-X','-v','ON_ERROR_STOP=1','-d',DB,'-c',"ALTER SYSTEM SET ssl='on';"]);
    run('docker',['exec','--user','postgres',id,'psql',
      '-X','-v','ON_ERROR_STOP=1','-d',DB,'-c','SELECT pg_reload_conf();']);
    run('docker',['exec','--user','postgres',id,'psql','-X','-v',
      'ON_ERROR_STOP=1','-d',DB,'-c',
      "CREATE ROLE "+LOGIN+" LOGIN NOSUPERUSER NOBYPASSRLS "+
      "NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '"+PASSWORD+"';"]);
    await delay(500);
    const a=await connectAndRead(clients[0],root);
    const b=await connectAndRead(clients[1],root);
    if(a===b)refuse();
    const live=run('docker',['exec','--user','postgres',id,'psql','-X',
      '-t','-A','-v','ON_ERROR_STOP=1','-d',DB,'-c',
      'SELECT count(*)::int FROM pg_stat_activity WHERE pid IN ('+a+','+b+');']);
    if(live!=='0')refuse();
    console.info('B16_LOCKED_NODEPG_PG16_TLS_TWO_PHYSICAL_PIDS_PASS');
    await expectRefused(clients[0],wrong,false);
    console.info('B16_LOCKED_NODEPG_PG16_WRONG_CA_DENIED_PASS');
    applyCert(id,dir,'wildcard');
    await delay(600);
    await expectRefused(clients[1],root,true);
    console.info('B16_LOCKED_NODEPG_PG16_WILDCARD_SAN_DENIED_PASS');
    console.info('PASS Backend16 locked NodePG authenticated real PG16 TLS (2 clients); NO RELEASE AUTHORIZATION');
  }finally{
    rmSync(dir,{recursive:true,force:true});
  }
}
