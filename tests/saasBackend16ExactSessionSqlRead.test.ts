import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BACKEND16_EXACT_READ_SQL as SQL,
  createBackend16ExactSqlReadPort,
} from '../src/features/saasBlueprint/controlApi/server/backend16ExactSessionSqlRead.ts';
import type {
  Backend16PhysicalPgPool, Backend16PgRow,
} from '../src/features/saasBlueprint/controlApi/server/backend16PhysicalPgAdmission.ts';
import {
  createBackend16PrivateReadHandler,
  type VerifiedPrincipal,
} from '../src/features/saasBlueprint/controlApi/server/backend16PrivateTenantProjectRead.ts';

const TENANT='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const FOREIGN='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const P1='cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const P2='dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const NOW=1_800_000_000_000;
const ORIGIN='https://private.saas-unit.example.net';
const principal:VerifiedPrincipal=Object.freeze({
  kind:'verified-server-session',
  issuer:'https://verified-issuer.saas-unit.example.net',
  subjectFingerprintSha256:'f'.repeat(64),
  pgLogin:'saas_principal_ci_a',
  sessionId:'11111111-1111-4111-8111-111111111111',
  bindingId:'22222222-2222-4222-8222-222222222222',
  sessionExpiresAtMs:NOW+120_000,
});
const role={
  active_role:principal.pgLogin,backend_pid:1741,bypass_rls:false,
  can_login:true,create_db:false,create_role:false,
  database_name:'saas_staging_ci',reader_member:true,
  replication:false,session_login:principal.pgLogin,
  staging_only:'true',superuser:false,writer_member:false,
};
const allowedSQL=new Set(Object.values(SQL));
const signal=()=>new AbortController().signal;
type Reason=Parameters<Backend16PhysicalPgPool['quarantine']>[0];
type Cfg={
  role?:Readonly<Record<string,unknown>>;
  exact?:unknown;
  tenant?:Readonly<Record<string,unknown>>|null;
  projects?:readonly Readonly<Record<string,unknown>>[];
  extraRole?:boolean;
  wrong?:string;
  acquireFails?:boolean;
  releaseFails?:boolean;
  onQuery?:(sql:string)=>void;
  nowMs?:()=>number;
};
function fixture(cfg:Cfg={}){
  const seen:{sql:string,params:readonly string[]}[]=[];
  const logins:string[]=[];
  const discards:boolean[]=[];
  const quarantines:Reason[]=[];
  const pool:Backend16PhysicalPgPool={
    quarantine(reason){quarantines.push(reason);},
    async acquirePrincipal(login,_signal){
      logins.push(login);
      if(cfg.acquireFails)throw Error('private database password');
      return {
        async query(sql,params,_signal){
          seen.push({sql,params});
          assert.ok(allowedSQL.has(sql as (typeof SQL)[keyof typeof SQL]),
            'unexpected dynamic SQL statement');
          cfg.onQuery?.(sql);
          if(cfg.wrong===sql)throw Error('SQLSTATE 42501 pg connection secret');
          if(sql===SQL.identity)return {rows:[{...(cfg.role??role),
            ...(cfg.extraRole?{private_password:'injection'}:{})}]};
          if(sql===SQL.exact)return {rows:[{allowed:cfg.exact===undefined?true:cfg.exact}]};
          if(sql===SQL.tenant)return {rows:cfg.tenant===null?[]:
            [cfg.tenant??{tenant_id:TENANT}]};
          if(sql===SQL.projects)return {rows:[...(cfg.projects??[
            {project_id:P1},{project_id:P2},
          ])]};
          return {rows:[]};
        },
        async release(discard){
          discards.push(discard);
          if(cfg.releaseFails)throw Error('failed physical close with password');
        },
      };
    },
  };
  const read=createBackend16ExactSqlReadPort({
    pool,expectedDatabase:'saas_staging_ci',nowMs:cfg.nowMs??(()=>NOW),
  });
  return {read,seen,logins,discards,quarantines};
}
function failure(p:Promise<unknown>){
  return assert.rejects(p,e=>{
    assert.ok(e instanceof Error);
    assert.equal(e.message,'Backend16 exact SQL data source unavailable');
    assert.equal(e.message.includes('password'),false);
    return true;
  });
}

test('server SQL is constant read-only by privilege, never SET ROLE or tenant GUC',()=>{
  assert.equal(SQL.begin,'BEGIN ISOLATION LEVEL READ COMMITTED');
  assert.match(SQL.exact,/saas_acl\.exact_subject_session_authorized/);
  assert.match(SQL.tenant,/saas_data\.tenants/);
  assert.match(SQL.projects,/saas_data\.projects/);
  assert.match(SQL.identity,/session_user::text/);
  assert.match(SQL.projects,/LIMIT 51/);
  assert.deepEqual(Object.keys(SQL),[
    'begin','statementTimeout','lockTimeout','identity',
    'exact','tenant','projects','commit',
  ]);
  for(const sql of Object.values(SQL)){
    assert.doesNotMatch(sql,/\b(?:INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|SET\s+(?:LOCAL\s+)?ROLE)\b/i);
    assert.doesNotMatch(sql,/\bREAD ONLY\b/i);
    assert.doesNotMatch(sql,/current_setting\('saas\.tenant_id'/);
  }
});

test('exact OIDC subject/session/binding + physical login reads only whitelisted IDs after COMMIT',async()=>{
  const f=fixture();
  const r=await f.read(principal,TENANT,signal());
  assert.deepEqual(r,{kind:'authorized',tenantId:TENANT,projectIds:[P1,P2]});
  assert.equal(Object.isFrozen(r),true);
  assert.equal(Object.isFrozen((r as {projectIds:string[]}).projectIds),true);
  assert.deepEqual(f.logins,[principal.pgLogin]);
  assert.deepEqual(f.discards,[false]);
  assert.deepEqual(f.quarantines,[]);
  assert.deepEqual(f.seen.map(x=>x.sql),[
    SQL.begin,SQL.statementTimeout,SQL.lockTimeout,SQL.identity,
    SQL.exact,SQL.tenant,SQL.projects,SQL.commit,
  ]);
  assert.deepEqual(f.seen.filter(x=>x.params.length).map(x=>x.params),[
    [TENANT,principal.sessionId,principal.bindingId,principal.subjectFingerprintSha256],
    [TENANT],[TENANT],
  ]);
});

test('exact gate denial skips all tenant/project data and completes transaction',async()=>{
  const f=fixture({exact:false});
  const r=await f.read(principal,FOREIGN,signal());
  assert.deepEqual(r,{kind:'denied'});
  assert.deepEqual(f.seen.map(x=>x.sql),[
    SQL.begin,SQL.statementTimeout,SQL.lockTimeout,SQL.identity,
    SQL.exact,SQL.commit,
  ]);
  assert.deepEqual(f.seen.find(x=>x.sql===SQL.exact)?.params,[
    FOREIGN,principal.sessionId,principal.bindingId,principal.subjectFingerprintSha256,
  ]);
  assert.deepEqual(f.discards,[false]);
});

test('zero projects may be authorized; no extra row fields or private data',async()=>{
  const f=fixture({projects:[]});
  assert.deepEqual(await f.read(principal,TENANT,signal()),
    {kind:'authorized',tenantId:TENANT,projectIds:[]});
});

test('reject malformed, expired, elevated or reserved principal BEFORE acquiring',async()=>{
  const invalid:VerifiedPrincipal[]=[
    {...principal,sessionExpiresAtMs:NOW},
    {...principal,sessionExpiresAtMs:NOW+901_000},
    {...principal,sessionId:'bad'},
    {...principal,bindingId:'bad'},
    {...principal,pgLogin:'postgres'},
    {...principal,pgLogin:'saas_schema_migrator'},
    {...principal,pgLogin:'pg_authid'},
    {...principal,pgLogin:'saas_runtime_reader'},
    {...principal,subjectFingerprintSha256:'wrong'},
  ];
  const f=fixture();
  for(const p of invalid)assert.deepEqual(await f.read(p,TENANT,signal()),
    {kind:'denied'});
  assert.deepEqual(await f.read(principal,'not-uuid',signal()),{kind:'denied'});
  assert.deepEqual(await f.read(principal,TENANT.toUpperCase(),signal()),{kind:'denied'});
  const c=new AbortController();c.abort();
  assert.deepEqual(await f.read(principal,TENANT,c.signal),{kind:'denied'});
  assert.deepEqual(f.logins,[]);
  assert.deepEqual(f.quarantines,[]);
});

test('physical LOGIN cannot be substituted and cannot be superuser or BYPASSRLS',async()=>{
  const mutants=[
    {session_login:'saas_principal_ci_b'},
    {active_role:'saas_runtime_reader'},
    {database_name:'production'},
    {staging_only:'false'},
    {backend_pid:0},
    {can_login:false},
    {superuser:true},{bypass_rls:true},{create_role:true},
    {create_db:true},{replication:true},{reader_member:false},
    {reader_member:true,writer_member:true},
  ];
  for(const m of mutants){
    const f=fixture({role:{...role,...m}});
    await failure(f.read(principal,TENANT,signal()));
    assert.equal(f.seen.some(x=>x.sql===SQL.exact),false);
    assert.deepEqual(f.discards,[true]);
    assert.deepEqual(f.quarantines,['query-uncertain']);
  }
});

test('writer-only principal may read, after exact SQL0008 also verifies role/grant revision',async()=>{
  const f=fixture({role:{...role,reader_member:false,writer_member:true}});
  const result=await f.read(principal,TENANT,signal());
  assert.equal(result.kind,'authorized');
});

test('extra SQL columns, missing role field and forged exact result refuse',async()=>{
  for(const opts of [
    {extraRole:true},
    {role:{...role,can_login:undefined}},
    {exact:'true'},
    {exact:null},
  ] as Cfg[]){
    const f=fixture(opts);
    await failure(f.read(principal,TENANT,signal()));
    assert.deepEqual(f.discards,[true]);
  }
});

test('a foreign RLS tenant row and missing tenant are unavailable, not success',async()=>{
  for(const opts of [
    {tenant:{tenant_id:FOREIGN}},
    {tenant:{tenant_id:TENANT,secret:'PRIVATE'}},
    {tenant:null},
  ] as Cfg[]){
    const f=fixture(opts);
    await failure(f.read(principal,TENANT,signal()));
    assert.equal(f.seen.some(x=>x.sql===SQL.projects),false);
    assert.deepEqual(f.discards,[true]);
  }
});

test('duplicate, malformed, excess or data-bearing project rows are refused',async()=>{
  const tooMany=Array.from({length:51},()=>({project_id:P1}));
  for(const projects of [
    [{project_id:P1},{project_id:P1}],
    [{project_id:'not-a-uuid'}],
    [{project_id:P1,token:'secret'}],
    tooMany,
  ]){
    const f=fixture({projects});
    await failure(f.read(principal,TENANT,signal()));
    assert.deepEqual(f.discards,[true]);
    assert.deepEqual(f.quarantines,['query-uncertain']);
  }
});

test('query exception after FOR SHARE must not send COMMIT or retry',async()=>{
  const f=fixture({wrong:SQL.projects});
  await failure(f.read(principal,TENANT,signal()));
  assert.equal(f.seen.filter(x=>x.sql===SQL.projects).length,1);
  assert.equal(f.seen.some(x=>x.sql===SQL.commit),false);
  assert.deepEqual(f.discards,[true]);
  assert.deepEqual(f.quarantines,['query-uncertain']);
});

test('lost COMMIT acknowledgement cancels, discards and never publishes',async()=>{
  const ctl=new AbortController();
  const f=fixture({onQuery(sql){if(sql===SQL.commit)ctl.abort();}});
  await failure(f.read(principal,TENANT,ctl.signal));
  assert.equal(f.seen.filter(x=>x.sql===SQL.commit).length,1);
  assert.deepEqual(f.logins,[principal.pgLogin]);
  assert.deepEqual(f.discards,[true]);
  assert.deepEqual(f.quarantines,['query-uncertain']);
});

test('cancellation just after exact gate must not read tenant/project or COMMIT',async()=>{
  const ctl=new AbortController();
  const f=fixture({onQuery(sql){if(sql===SQL.exact)ctl.abort();}});
  await failure(f.read(principal,TENANT,ctl.signal));
  assert.equal(f.seen.some(x=>x.sql===SQL.tenant),false);
  assert.equal(f.seen.some(x=>x.sql===SQL.commit),false);
  assert.deepEqual(f.discards,[true]);
});

test('session expires after lock acquisition but before COMMIT, so fail closed',async()=>{
  let clock=NOW;
  const f=fixture({nowMs:()=>clock,onQuery(sql){if(sql===SQL.projects)clock=NOW+150_000;}});
  await failure(f.read(principal,TENANT,signal()));
  assert.equal(f.seen.some(x=>x.sql===SQL.commit),false);
  assert.deepEqual(f.discards,[true]);
});

test('pool acquisition and release failures are quarantined with redacted errors',async()=>{
  const a=fixture({acquireFails:true});
  await failure(a.read(principal,TENANT,signal()));
  assert.deepEqual(a.quarantines,['acquire-uncertain']);
  assert.deepEqual(a.discards,[]);
  const b=fixture({releaseFails:true});
  await failure(b.read(principal,TENANT,signal()));
  assert.deepEqual(b.quarantines,['release-uncertain']);
  assert.deepEqual(b.discards,[false]);
});

test('backend is an explicit unmounted HTTP port; synthetic fixture cannot prove deployment',async()=>{
  const f=fixture();
  const handler=createBackend16PrivateReadHandler({
    enabled:()=>true,expectedOrigin:ORIGIN,
    authenticate:async()=>principal,readAuthorized:f.read,now:()=>NOW,
  });
  const request=new Request(ORIGIN+'/internal/saas/v1/tenants/'+TENANT+'/projects',{
    headers:{Authorization:'Bearer a.b.c'},
  });
  const result=await handler(request);
  assert.equal(result.status,200);
  assert.deepEqual(await result.json(),{tenantId:TENANT,projectIds:[P1,P2]});
  assert.equal(result.headers.get('Cache-Control')?.includes('no-store'),true);
  assert.equal(result.headers.has('Access-Control-Allow-Origin'),false);
  // authenticate is only a TEST DOUBLE here. No actual OIDC/PG driver/HTTP listener.
});

test('misconfigured or untrusted staging options cannot construct port',()=>{
  assert.throws(()=>createBackend16ExactSqlReadPort({
    pool:null as unknown as Backend16PhysicalPgPool,
    expectedDatabase:'saas_staging_ci',
  }),/configuration refused/);
  assert.throws(()=>createBackend16ExactSqlReadPort({
    pool:{quarantine(){},async acquirePrincipal(){throw Error('never');}},
    expectedDatabase:'production' as 'saas_staging_ci',
  }),/configuration refused/);
});
