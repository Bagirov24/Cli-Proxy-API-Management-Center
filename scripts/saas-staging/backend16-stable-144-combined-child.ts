/** Official Bun only: real mTLS secret -> immutable vault -> native TLS SQL0008. */
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,X509Certificate} from 'node:crypto';
import {mkdtempSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createInterface} from 'node:readline';
import {SQL} from 'bun';
import {COMBINED_REVISION} from './backend16-stable-144-combined-contract.mjs';
import {createBackend16DisposableCiMtlsSecretReader}
  from '../../src/features/saasBlueprint/controlApi/server/backend16PrivateMtlsVersionedSecretReader.ts';
import {createBackend16StagingVersionedPrincipalVault}
  from '../../src/features/saasBlueprint/controlApi/server/backend16StagingVersionedPrincipalVault.ts';
import {createBackend16StagingDisposableCiTlsPhysicalPgPool}
  from '../../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts';
import {createBackend16StagingPgTlsTrust}
  from '../../src/features/saasBlueprint/controlApi/server/backend16StagingPgTlsTrust.ts';
import {createBackend16ExactSqlReadPort,BACKEND16_EXACT_READ_SQL as Q}
  from '../../src/features/saasBlueprint/controlApi/server/backend16ExactSessionSqlRead.ts';
import type {VerifiedPrincipal}
  from '../../src/features/saasBlueprint/controlApi/server/backend16PrivateTenantProjectRead.ts';

let phase='ENVIRONMENT';
async function main(){
  const e=process.env;
  assert.equal(Bun.version,'1.4.4');assert.equal(Bun.revision,COMBINED_REVISION);
  for(const flag of ['CI','GITHUB_ACTIONS','SAAS_B16_EPHEMERAL_CI',
    'SAAS_B16_STABLE_144_COMBINED_CI','SAAS_B16_STABLE_144_FULL_PG16_CI',
    'SAAS_B16_PHYSICAL_CI','SAAS_B16_PHYSICAL_TLS_CI','SAAS_B16_BROKER_MTLS_CI'])
    assert.equal(e[flag],'true');
  assert.equal(e.PGHOST,'127.0.0.1');assert.equal(e.PGPORT,'5432');
  assert.equal(e.PGDATABASE,'saas_ephemeral_test');assert.equal(e.PGUSER,'postgres');
  assert.equal(e.PGPASSWORD,'ci_ephemeral_test_only');
  assert.ok(!Object.keys(e).some(k=>k.startsWith('RAILWAY_')&&e[k]));
  assert.notEqual(e.NODE_ENV,'production');assert.notEqual(e.NODE_TLS_REJECT_UNAUTHORIZED,'0');
  // A valid principal secret MUST arrive over authenticated HTTPS, never child env.
  assert.equal(e.SAAS_B16_CI_A_PASSWORD,undefined);
  assert.equal(e.SAAS_B16_CI_B_PASSWORD,undefined);
  const id=e.SAAS_B16_CI_PG_CONTAINER??'';assert.match(id,/^[a-f0-9]{64}$/);
  const A='saas_b14_person',B='saas_b16_person_b';
  const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
  for(const k of ['A','B']){
    assert.match(e['SAAS_B16_CI_'+k+'_SUBJECT_SHA']??'',/^[a-f0-9]{64}$/);
    for(const f of ['TENANT','SESSION','BINDING'])assert.match(e['SAAS_B16_CI_'+k+'_'+f]??'',UUID);
  }
  const lines=createInterface({input:process.stdin});
  const input=lines[Symbol.asyncIterator]();
  let inputBytes=0;
  process.stdin.on('data',(data:Buffer)=>{inputBytes+=data.length;
    if(inputBytes>65536)process.exit(1);});
  const receive=async()=>{
    const next=await input.next();assert.equal(next.done,false);
    assert.ok(next.value.length<32768);return JSON.parse(next.value);
  };
  const setup=await receive();
  assert.equal(Object.keys(setup).join(','),'id,port,trust');assert.equal(setup.id,0);
  assert.ok(Number.isSafeInteger(setup.port)&&setup.port>=1024&&setup.port<=65535);
  let seq=0;
  async function rpc(op:string){
    process.stdout.write(JSON.stringify({id:++seq,op})+'\n');
    const answer=await receive();
    assert.equal(Object.keys(answer).join(','),'id,ok,calls');
    assert.equal(answer.id,seq);assert.equal(answer.ok,true);
    assert.ok(Number.isSafeInteger(answer.calls)&&answer.calls>=0&&answer.calls<=12);
    return answer.calls as number;
  }
  const cmd=(name:string,args:string[],cwd?:string)=>execFileSync(name,args,{
    cwd,encoding:'utf8',stdio:['ignore','pipe','ignore'],timeout:15000,
  }).trim();
  assert.equal(cmd('docker',['inspect','--format','{{.Config.Image}}',id]),'postgres:16.6');
  assert.equal(cmd('docker',['exec',id,'printenv','PGDATA']),'/var/lib/postgresql/data');
  const dir=mkdtempSync(join(tmpdir(),'b16-stable-combined-'));
  const admin=new SQL({adapter:'postgres',hostname:'127.0.0.1',port:5432,
    username:'postgres',password:'ci_ephemeral_test_only',database:'saas_staging_ci',
    max:3,prepare:false,connectionTimeout:4,idleTimeout:0});
  const scalar=async(sql:string,args:string[]=[])=>{
    const rows=await admin.unsafe(sql,args).execute();assert.equal(rows.length,1);
    return Object.values(rows[0])[0];
  };
  const gone=async(login:string)=>{
    for(let i=0;i<60;i++){
      if(await scalar('SELECT count(*)::int FROM pg_stat_activity WHERE datname=$1 AND usename=$2',
        ['saas_staging_ci',login])===0)return;
      await Bun.sleep(40);
    }
    throw Error('B16 combined physical backend survived close');
  };
  const root=(name:string)=>{
    cmd('openssl',['req','-x509','-newkey','rsa:3072','-nodes','-sha256',
      '-keyout',name+'.key','-out',name+'.pem','-days','30','-subj','/CN=B16 combined '+name,
      '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'],dir);
    return readFileSync(join(dir,name+'.pem'),'utf8');
  };
  const trust=(pem:string)=>createBackend16StagingPgTlsTrust({caPem:pem,
    approvedCaDerSha256:createHash('sha256').update(new X509Certificate(pem).raw).digest('hex')});
  let changed=false;
  try{
    phase='TLS_SETUP';
    assert.equal(await scalar('SHOW ssl'),'off');
    const ca=root('root'),other=root('other');
    cmd('openssl',['req','-newkey','rsa:2048','-nodes','-keyout','server.key',
      '-out','server.csr','-subj','/CN=postgres.railway.internal'],dir);
    writeFileSync(join(dir,'server.ext'),[
      'basicConstraints=critical,CA:FALSE','keyUsage=digitalSignature,keyEncipherment',
      'extendedKeyUsage=serverAuth','subjectAltName=DNS:postgres.railway.internal',
    ].join('\n')+'\n',{mode:0o600});
    cmd('openssl',['x509','-req','-in','server.csr','-CA','root.pem','-CAkey','root.key',
      '-CAcreateserial','-out','server.crt','-days','2','-sha256','-extfile','server.ext'],dir);
    for(const ext of ['key','crt'])cmd('docker',['cp',join(dir,'server.'+ext),
      id+':/tmp/b16-combined.'+ext]);
    cmd('docker',['exec','--user','root',id,'sh','-c',
      'mv /tmp/b16-combined.crt /var/lib/postgresql/data/server.crt && '+
      'mv /tmp/b16-combined.key /var/lib/postgresql/data/server.key && '+
      'chown postgres:postgres /var/lib/postgresql/data/server.crt /var/lib/postgresql/data/server.key && '+
      'chmod 0600 /var/lib/postgresql/data/server.key']);
    await admin.unsafe("ALTER SYSTEM SET ssl='on'").execute();changed=true;
    assert.equal(await scalar('SELECT pg_reload_conf()'),true);await Bun.sleep(300);
    assert.equal(await scalar('SHOW ssl'),'on');
    const reader=createBackend16DisposableCiMtlsSecretReader(setup.trust,setup.port);
    const entries=[{pgLogin:A,secretId:'b16-stg-pg-'+'a'.repeat(20),version:'a'.repeat(32)},
      {pgLogin:B,secretId:'b16-stg-pg-'+'b'.repeat(20),version:'b'.repeat(32)}];
    const digest=createHash('sha256').update(JSON.stringify({schema:'backend16-staging-vault-v1',
      entries:entries.map(x=>[x.pgLogin,x.secretId,x.version])})).digest('hex');
    const vault=await createBackend16StagingVersionedPrincipalVault({
      source:reader,manifest:{entries,approvedManifestSha256:digest}});
    let released=0;
    const observed={async readPrincipal(login:string,signal:AbortSignal){
      const secret=await vault.readPrincipal(login,signal);released++;return secret;
    }};
    const fresh=()=>new AbortController().signal;
    const pool=()=>createBackend16StagingDisposableCiTlsPhysicalPgPool(observed,trust(ca));
    const principal=(k:'A'|'B'):VerifiedPrincipal=>Object.freeze({
      kind:'verified-server-session',issuer:'https://ci-b16-idp.invalid',pgLogin:k==='A'?A:B,
      subjectFingerprintSha256:e['SAAS_B16_CI_'+k+'_SUBJECT_SHA']!,
      sessionId:e['SAAS_B16_CI_'+k+'_SESSION']!,bindingId:e['SAAS_B16_CI_'+k+'_BINDING']!,
      sessionExpiresAtMs:Date.now()+180000,
    });
    const a=principal('A'),b=principal('B'),ta=e.SAAS_B16_CI_A_TENANT!,tb=e.SAAS_B16_CI_B_TENANT!;
    phase='POSITIVE';assert.equal(await rpc('stats'),0);
    const positive=pool();
    try{
      const pids:number[]=[];
      for(const login of [A,B]){
        const conn=await positive.acquirePrincipal(login,fresh());
        try{
          for(const sql of [Q.begin,Q.statementTimeout,Q.lockTimeout])await conn.query(sql,[],fresh());
          const identity=await conn.query(Q.identity,[],fresh());
          assert.equal(identity.rows[0].session_login,login);
          const pid=identity.rows[0].backend_pid as number;assert.ok(Number.isSafeInteger(pid));
          pids.push(pid);
          const ssl=await admin.unsafe('SELECT ssl,version FROM pg_stat_ssl WHERE pid=$1',[String(pid)]).execute();
          assert.equal(ssl.length,1);assert.equal(ssl[0].ssl,true);
          assert.ok(['TLSv1.2','TLSv1.3'].includes(ssl[0].version));
        }finally{await assert.rejects(conn.release(true),/discarded/);}
        await gone(login);
      }
      assert.notEqual(pids[0],pids[1]);
      const read=createBackend16ExactSqlReadPort({pool:positive,expectedDatabase:'saas_staging_ci'});
      assert.equal((await read(a,ta,fresh())).kind,'authorized');
      assert.equal((await read(b,tb,fresh())).kind,'authorized');
      assert.deepEqual(await read(a,tb,fresh()),{kind:'denied'});
      assert.deepEqual(await read(b,ta,fresh()),{kind:'denied'});
      await gone(A);await gone(B);assert.equal(released,6);assert.equal(await rpc('stats'),6);
    }finally{await positive.shutdown();}
    for(const [op,calls] of [['wrong-version',7],['expired',8]] as const){
      phase=op==='expired'?'EXPIRY':'VERSION';await rpc(op);
      const denied=pool();
      try{
        await assert.rejects(denied.acquirePrincipal(A,fresh()),/stopped at VAULT/);
        assert.equal(released,6);await gone(A);
        await assert.rejects(denied.acquirePrincipal(B,fresh()),/physical LOGIN refused/);
        assert.equal(await rpc('stats'),calls);
      }finally{await denied.shutdown();}
    }
    phase='REVOCATION';await rpc('deferred');
    const revoked=pool();
    try{
      const result=revoked.acquirePrincipal(A,fresh()).then(()=>false,()=>true);
      await rpc('wait');e.SAAS_B16_BROKER_MTLS_CI='false';await rpc('release');
      assert.equal(await result,true);assert.equal(released,6);await gone(A);
      assert.equal(await rpc('stats'),9);
    }finally{e.SAAS_B16_BROKER_MTLS_CI='true';await revoked.shutdown();}
    await rpc('pass');phase='LOCK_ABORT';
    const locked=pool();let blocker:Awaited<ReturnType<typeof admin.reserve>>|undefined;
    try{
      blocker=await admin.reserve();await blocker.unsafe('BEGIN').execute();
      const row=await blocker.unsafe('SELECT access_revision FROM saas_acl.principal_tenants '+
        'WHERE principal_name=$1 AND tenant_id=$2 FOR UPDATE',[A,ta]).execute();
      assert.equal(row.length,1);
      const read=createBackend16ExactSqlReadPort({pool:locked,expectedDatabase:'saas_staging_ci'});
      const abort=new AbortController();const pending=read(a,ta,abort.signal);
      const outcome=pending.then(()=>false,()=>true);
      let pid:number|undefined;
      for(let i=0;i<30;i++){
        const rows=await admin.unsafe("SELECT pid::int FROM pg_stat_activity WHERE datname=$1 "+
          "AND usename=$2 AND wait_event_type='Lock'",['saas_staging_ci',A]).execute();
        if(rows.length===1){pid=rows[0].pid as number;break;}await Bun.sleep(30);
      }
      assert.ok(Number.isSafeInteger(pid));abort.abort();assert.equal(await outcome,true);
      await gone(A);await blocker.unsafe('ROLLBACK').execute();blocker.release();blocker=undefined;
      await assert.rejects(read(b,tb,fresh()));
    }finally{
      if(blocker){await blocker.unsafe('ROLLBACK').execute();blocker.release();}
      await locked.shutdown();
    }
    const resumed=pool();
    try{assert.equal((await createBackend16ExactSqlReadPort({pool:resumed,
      expectedDatabase:'saas_staging_ci'})(b,tb,fresh())).kind,'authorized');await gone(B);}
    finally{await resumed.shutdown();}
    phase='WRONG_ROOT';
    const wrong=createBackend16StagingDisposableCiTlsPhysicalPgPool(observed,trust(other));
    try{await assert.rejects(wrong.acquirePrincipal(A,fresh()));await gone(A);}
    finally{await wrong.shutdown();}
    assert.equal(released,9);assert.equal(await rpc('stats'),12);
  }finally{
    if(changed){await admin.unsafe("ALTER SYSTEM SET ssl='off'").execute();
      assert.equal(await scalar('SELECT pg_reload_conf()'),true);await Bun.sleep(300);
      assert.equal(await scalar('SHOW ssl'),'off');}
    await admin.close({timeout:0});rmSync(dir,{recursive:true,force:true});
  }
  phase='DONE';await rpc('done');lines.close();process.stdin.destroy();
}
main().catch(()=>{console.error('STOP B16 combined child '+phase);
  process.exitCode=1;process.stdin.destroy();});
