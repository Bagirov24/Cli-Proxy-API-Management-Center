import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BACKEND16_PHYSICAL_PG_SQL as SQL,
  createBackend16PhysicalPgAdmission,
  type Backend16PhysicalPgPool,
  type Backend16PgRow,
} from '../src/features/saasBlueprint/controlApi/server/backend16PhysicalPgAdmission.ts';
import type {VerifiedPrincipal}
  from '../src/features/saasBlueprint/controlApi/server/backend16PrivateTenantProjectRead.ts';

const TENANT='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const FOREIGN='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOW=1_800_000_000_000;
const principal:VerifiedPrincipal={
  kind:'verified-server-session',
  issuer:'https://idp.saas-ci.example.net/tenant',
  subjectFingerprintSha256:'f'.repeat(64),
  pgLogin:'saas_principal_ci_a',
  sessionId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  bindingId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  sessionExpiresAtMs:NOW+300_000,
};
const role={
  active_role:principal.pgLogin,backend_pid:1729,
  bypass_rls:false,can_login:true,create_db:false,
  create_role:false,database_name:'saas_staging_ci',
  reader_member:true,replication:false,session_login:principal.pgLogin,
  staging_only:'true',superuser:false,
};
const statements=Object.values(SQL);
const signal=()=>new AbortController().signal;
type FailureReason=Parameters<Backend16PhysicalPgPool['quarantine']>[0];
type FixtureOptions={
  role?:Readonly<Record<string,unknown>>;
  acl?:unknown;
  tenant?:Readonly<Record<string,unknown>>;
  queryFailsAt?:string;
  loseCommitAck?:boolean;
  acquireFails?:boolean;
  releaseFails?:boolean;
  extraRole?:boolean;
  onQuery?:(sql:string)=>void;
  now?:()=>number;
};
function fixture(config:FixtureOptions={}){
  const events:{sql:string,params:readonly string[]}[]=[];
  const releases:boolean[]=[];
  const poisoned:FailureReason[]=[];
  const acquired:string[]=[];
  let createCount=0;
  const pool:Backend16PhysicalPgPool={
    quarantine(reason){poisoned.push(reason);},
    async acquirePrincipal(login,_signal){
      acquired.push(login);createCount++;
      if(config.acquireFails)throw new Error('private server vault password');
      return {
        async query(sql,params,_signal){
          events.push({sql,params});
          assert.ok(statements.includes(sql as (typeof statements)[number]),
            'query is not an allowlisted server-owned statement');
          config.onQuery?.(sql);
          if(config.queryFailsAt===sql)throw new Error('SQLSTATE 42501 secret password');
          if(config.loseCommitAck&&sql===SQL.commit)
            return await new Promise<never>(()=>{});
          if(sql===SQL.identity)
            return {rows:[{...(config.role??role),...(config.extraRole?{secret:'not-public'}:{})}]};
          if(sql===SQL.acl)return {rows:[{allowed:config.acl===undefined?true:config.acl}]};
          if(sql===SQL.tenant)return {rows:[config.tenant??{tenant_id:TENANT}]};
          return {rows:[]};
        },
        async release(discard){
          releases.push(discard);
          if(config.releaseFails)throw new Error('failed to destroy physical PG backend');
        },
      };
    },
  };
  const probe=createBackend16PhysicalPgAdmission({
    pool,expectedDatabase:'saas_staging_ci',nowMs:config.now??(()=>NOW),
  });
  return {probe,events,releases,poisoned,acquired,get creates(){return createCount;}};
}
const expectUnavailable=(promise:Promise<unknown>)=>
  assert.rejects(promise,error=>{
    assert.ok(error instanceof Error);
    assert.equal(error.message,'Backend16 physical PostgreSQL unavailable');
    assert.equal(error.message.includes('secret'),false);
    return true;
  });

test('source SQL is constant, only SELECT and transaction config, never SET ROLE/DML',()=>{
  assert.equal(SQL.begin,'BEGIN ISOLATION LEVEL READ COMMITTED');
  assert.ok(SQL.acl.includes('saas_acl.can_read_tenant'));
  assert.ok(SQL.tenant.includes('saas_data.tenants'));
  assert.ok(SQL.identity.includes('session_user::text'));
  assert.ok(SQL.identity.includes('pg_has_role'));
  for(const sql of Object.values(SQL)){
    assert.doesNotMatch(sql,/\b(?:INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|SET\s+(?:LOCAL\s+)?ROLE)\b/i);
    assert.doesNotMatch(sql,/\bREAD ONLY\b/i);
  }
  assert.equal(Object.keys(SQL).length,7);
});

test('a per-subject PG backend and SQL0007 RLS can be observed but not authorize API',async()=>{
  const f=fixture();
  const result=await f.probe(principal,TENANT,signal());
  assert.deepEqual(result,{kind:'physical-rls-observed'});
  assert.equal('projectIds' in result,false);
  assert.notEqual((result as {kind:string}).kind,'authorized');
  assert.deepEqual(f.acquired,[principal.pgLogin]);
  assert.deepEqual(f.releases,[false]);
  assert.deepEqual(f.poisoned,[]);
  assert.deepEqual(f.events.map(e=>e.sql),[
    SQL.begin,SQL.statementTimeout,SQL.lockTimeout,SQL.identity,
    SQL.acl,SQL.tenant,SQL.commit,
  ]);
  assert.deepEqual(f.events.filter(x=>x.params.length>0).map(x=>x.params),[
    [TENANT],[TENANT],
  ]);
});

test('ungranted tenant cannot be probed or distinguished by returned data',async()=>{
  const f=fixture({acl:false});
  const result=await f.probe(principal,FOREIGN,signal());
  assert.deepEqual(result,{kind:'denied'});
  assert.deepEqual(f.events.map(e=>e.sql),[
    SQL.begin,SQL.statementTimeout,SQL.lockTimeout,
    SQL.identity,SQL.acl,SQL.commit,
  ]);
  assert.deepEqual(f.events.find(x=>x.sql===SQL.acl)?.params,[FOREIGN]);
  assert.deepEqual(f.releases,[false]);
  assert.deepEqual(f.poisoned,[]);
});

test('expired/malformed principals, reserved roles and tenant spoofing fail before acquiring',async()=>{
  const broken:VerifiedPrincipal[]=[
    {...principal,sessionExpiresAtMs:NOW},
    {...principal,sessionExpiresAtMs:NOW+901_000},
    {...principal,sessionId:'bad'},
    {...principal,bindingId:'bad'},
    {...principal,pgLogin:'postgres'},
    {...principal,pgLogin:'saas_schema_migrator'},
    {...principal,pgLogin:'saas_runtime_reader'},
    {...principal,pgLogin:'saas_runtime_writer'},
    {...principal,pgLogin:'pg_operator'},
    {...principal,subjectFingerprintSha256:'untrusted'},
  ];
  const f=fixture();
  for(const p of broken)assert.deepEqual(
    await f.probe(p,TENANT,signal()),{kind:'denied'});
  assert.deepEqual(await f.probe(principal,'not-uuid',signal()),{kind:'denied'});
  assert.deepEqual(await f.probe(principal,TENANT.toUpperCase(),signal()),{kind:'denied'});
  const ctrl=new AbortController();ctrl.abort();
  assert.deepEqual(await f.probe(principal,TENANT,ctrl.signal),{kind:'denied'});
  assert.deepEqual(f.acquired,[]);
  assert.deepEqual(f.poisoned,[]);
});

test('unsafe physical identity is rejected before querying tenant ACL',async()=>{
  const mutations=[
    {session_login:'postgres'},{active_role:'saas_runtime_reader'},
    {database_name:'production'},{staging_only:'false'},
    {can_login:false},{superuser:true},{bypass_rls:true},
    {create_role:true},{create_db:true},{replication:true},
    {reader_member:false},{backend_pid:0},{backend_pid:'177'},
  ];
  for(const mutation of mutations){
    const f=fixture({role:{...role,...mutation}});
    await expectUnavailable(f.probe(principal,TENANT,signal()));
    assert.equal(f.events.some(x=>x.sql===SQL.acl),false,
      JSON.stringify(mutation));
    assert.deepEqual(f.releases,[true]);
    assert.deepEqual(f.poisoned,['query-uncertain']);
  }
});

test('extra/private/missing identity columns cause pool quarantine, not role guessing',async()=>{
  const extra=fixture({extraRole:true});
  await expectUnavailable(extra.probe(principal,TENANT,signal()));
  assert.deepEqual(extra.releases,[true]);
  const missing={...role} as Record<string,unknown>;
  delete missing.reader_member;
  const absent=fixture({role:missing});
  await expectUnavailable(absent.probe(principal,TENANT,signal()));
  assert.deepEqual(absent.releases,[true]);
});

test('malformed ACL and forged FORCE RLS rows fail closed and destroy backend',async()=>{
  const badCases:FixtureOptions[]=[
    {acl:'true'},{acl:null},{tenant:{tenant_id:FOREIGN}},
    {tenant:{tenant_id:TENANT,private_key:'SECRET'}},
  ];
  for(const args of badCases){
    const f=fixture(args);
    await expectUnavailable(f.probe(principal,TENANT,signal()));
    assert.deepEqual(f.releases,[true]);
    assert.deepEqual(f.poisoned,['query-uncertain']);
  }
});

test('lost COMMIT ACK never retries and quarantines actual physical login',async()=>{
  const ctrl=new AbortController();
  const f=fixture({
    loseCommitAck:true,
    onQuery(sql){
      if(sql===SQL.commit)ctrl.abort();
    },
  });
  await expectUnavailable(f.probe(principal,TENANT,ctrl.signal));
  assert.equal(f.events.filter(x=>x.sql===SQL.commit).length,1);
  assert.equal(f.creates,1);
  assert.deepEqual(f.releases,[true]);
  assert.deepEqual(f.poisoned,['query-uncertain']);
});

test('cancel after FOR SHARE SQL denies output and discards physical connection',async()=>{
  const ctrl=new AbortController();
  const f=fixture({onQuery(sql){if(sql===SQL.acl)ctrl.abort();}});
  await expectUnavailable(f.probe(principal,TENANT,ctrl.signal));
  assert.deepEqual(f.releases,[true]);
  assert.deepEqual(f.poisoned,['query-uncertain']);
  assert.equal(f.events.some(x=>x.sql===SQL.commit),false);
});

test('uncertain acquisition and broken release poison pool without revealing diagnostics',async()=>{
  const acquire=fixture({acquireFails:true});
  await expectUnavailable(acquire.probe(principal,TENANT,signal()));
  assert.deepEqual(acquire.poisoned,['acquire-uncertain']);
  assert.deepEqual(acquire.releases,[]);
  const release=fixture({releaseFails:true});
  await expectUnavailable(release.probe(principal,TENANT,signal()));
  assert.deepEqual(release.poisoned,['release-uncertain']);
  assert.deepEqual(release.releases,[false]);
});

test('any query failure retires whole pool without speculative SQL retry',async()=>{
  const f=fixture({queryFailsAt:SQL.tenant});
  await expectUnavailable(f.probe(principal,TENANT,signal()));
  assert.equal(f.events.filter(x=>x.sql===SQL.tenant).length,1);
  assert.equal(f.events.filter(x=>x.sql===SQL.commit).length,0);
  assert.deepEqual(f.releases,[true]);
  assert.deepEqual(f.poisoned,['query-uncertain']);
});

test('session expiring before publication never becomes an observed admission',async()=>{
  let now=NOW;
  const f=fixture({now:()=>now,onQuery(sql){if(sql===SQL.acl)now=NOW+310_000;}});
  await expectUnavailable(f.probe(principal,TENANT,signal()));
  assert.deepEqual(f.releases,[true]);
  assert.deepEqual(f.poisoned,['query-uncertain']);
});

test('separate per-principal physical acquisitions cannot substitute another login',async()=>{
  const other:{readonly id:string;readonly p:VerifiedPrincipal}={
    id:FOREIGN,p:{...principal,pgLogin:'saas_principal_ci_b'},
  };
  const a=fixture();
  assert.deepEqual(await a.probe(principal,TENANT,signal()),
    {kind:'physical-rls-observed'});
  const b=fixture({role:{...role,session_login:other.p.pgLogin,
    active_role:other.p.pgLogin},acl:false});
  assert.deepEqual(await b.probe(other.p,FOREIGN,signal()),{kind:'denied'});
  assert.deepEqual(a.acquired,[principal.pgLogin]);
  assert.deepEqual(b.acquired,[other.p.pgLogin]);
  assert.deepEqual(a.releases,[false]);
  assert.deepEqual(b.releases,[false]);
});

test('misconfigured pool/DB name cannot construct private boundary',()=>{
  assert.throws(()=>createBackend16PhysicalPgAdmission({
    pool:null as unknown as Backend16PhysicalPgPool,
    expectedDatabase:'saas_staging_ci',
  }),/configuration refused/);
  assert.throws(()=>createBackend16PhysicalPgAdmission({
    pool:{quarantine(){},acquirePrincipal:async()=>{throw Error('not used');}},
    expectedDatabase:'production' as 'saas_staging',
  }),/configuration refused/);
});
