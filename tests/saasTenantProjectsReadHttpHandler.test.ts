import {describe,expect,test} from 'bun:test';
import {createTenantProjectsReadHttpHandler} from
  '../src/features/saasBlueprint/controlApi/server/tenantProjectsReadHttpHandler';
import {CONTROL_READ_SELECT_SQL,SCOPED_READ_GATE_SQL} from
  '../src/features/saasBlueprint/controlApi/server/signedSqlBoundary';
import type {SecurityAuditDecision} from
  '../src/features/saasBlueprint/controlApi/server/securityAudit';

const ORIGIN='https://saas-control.invalid';
const BEARER='ok.token.signature';
const path='/control-api/v1/tenants/demo-north/projects';
const project={id:'north-project',tenant_id:'demo-north',
  name:'North Project',status:'active'};

function fixture(options: {
  signedRows?: readonly Record<string,unknown>[];
  dbAllowed?: boolean;
  revokeDuringSql?: boolean;
  denyAudit?: boolean;
  signerFails?: boolean;
} = {}){
  const stats={connections:0,selects:0,releases:0,quarantines:0,verification:0};
  const audited:SecurityAuditDecision[]=[];
  const actor={id:'actor-north',memberships:[{
    tenantId:'demo-north',role:'tenant-viewer' as const,
    status:'active' as 'active'|'revoked',
  }]};
  const deps={
    expectedOrigin:ORIGIN,
    tokens:{
      async verifyAccessToken(token:string){
        stats.verification++;
        return token === BEARER
          ? {issuer:'https://trusted-issuer.invalid/',subject:'north'}:null;
      },
    },
    actorDirectory:{
      async resolveActorId(identity:{issuer:string;subject:string}){
        return identity.issuer==='https://trusted-issuer.invalid/' &&
          identity.subject==='north'?'actor-north':null;
      },
    },
    actors:{
      async lookup(actorId:string){
        return actorId==='actor-north'?actor:null;
      },
    },
    signer:{
      async sign(){
        if (options.signerFails) throw new Error('DB_HMAC_SECRET_DO_NOT_DISCLOSE');
        return 'a'.repeat(64);
      },
    },
    revisions:{
      async readRevision(){
        return {revision:'1',notAfterMs:null};
      },
    },
    pool:{
      quarantine(){stats.quarantines++;},
      async connect(){
        stats.connections++;
        return {
          async query(sql:string){
            if (sql==='BEGIN'||sql==='COMMIT'||sql==='ROLLBACK'||
                sql==='SET LOCAL ROLE saas_rls_reader'||
                sql==='SELECT set_config($1::text, $2::text, true)') {
              return {rows:[]};
            }
            if (sql==='SELECT txid_current()::text AS transaction_id')
              return {rows:[{transaction_id:'17'}]};
            if (sql===SCOPED_READ_GATE_SQL)
              return {rows:[{allowed:options.dbAllowed!==false}]};
            if (sql===CONTROL_READ_SELECT_SQL.projects){
              stats.selects++;
              if (options.revokeDuringSql&&stats.selects===2)
                actor.memberships[0].status='revoked';
              return {rows:options.signedRows??[project]};
            }
            throw new Error('UNEXPECTED_SQL_TEXT_DO_NOT_DISCLOSE');
          },
          async release(){stats.releases++;},
        };
      },
    },
    audit:{
      record(decision:SecurityAuditDecision){
        if (options.denyAudit) throw new Error('AUDIT_SINK_SECRET');
        audited.push(Object.freeze({...decision}));
      },
    },
    newCorrelationId:()=> 'server-fixed-correlation',
  };
  const handler=createTenantProjectsReadHttpHandler(deps);
  function send(url=ORIGIN+path,init:RequestInit={}){
    const headers=new Headers(init.headers);
    if (!headers.has('authorization'))headers.set('Authorization','Bearer '+BEARER);
    return handler(new Request(url,{...init,headers}));
  }
  return {handler,send,stats,audited,actor,deps};
}

describe('SaaS server tenant/projects READ, no client-supplied authority',()=>{
  test('signed PG-shaped scoped GET returns fixed safe project summary',async()=>{
    const f=fixture({signedRows:[{...project,internal_secret:'not-visible'}]});
    const res=await f.send();
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toContain('no-store');
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
    expect(res.headers.get('x-correlation-id')).toBe('server-fixed-correlation');
    expect(await res.json()).toEqual({
      ok:true,status:200,apiVersion:1,source:'signed-postgresql',
      data:[{id:'north-project',name:'North Project',status:'active'}],
    });
    expect(f.stats.selects).toBe(2);
    expect(f.stats.releases).toBeGreaterThanOrEqual(2);
    expect(f.audited).toHaveLength(1);
    expect(f.audited[0]).toMatchObject({
      actorId:'actor-north',tenantId:'demo-north',
      result:'allow',reason:'read-allowed',collection:'projects',
    });
  });

  test('invalid bearer and tenant IDOR do not reserve a database connection',async()=>{
    const f=fixture();
    const missing=await f.handler(new Request(ORIGIN+path));
    expect(missing.status).toBe(401);
    const forbidden=await f.send(ORIGIN+
      '/control-api/v1/tenants/demo-orbit/projects');
    expect(forbidden.status).toBe(404);
    expect(f.stats.connections).toBe(0);
    expect(f.audited.every(a=>a.tenantId===null)).toBe(true);
    expect(JSON.stringify(await forbidden.json())).not.toContain('demo-orbit');
  });

  test('query limit and URL strictly allowlisted; no untrusted authority headers',async()=>{
    const f=fixture();
    const reject=[
      [ORIGIN+path+'?limit=0',{}],
      [ORIGIN+path+'?limit=51',{}],
      [ORIGIN+path+'?limit=02',{}],
      [ORIGIN+path+'?limit=10&limit=20',{}],
      [ORIGIN+path+'?role=tenant-owner',{}],
      [ORIGIN+path+'/',{}],
      [ORIGIN+path+'?limit=2#h',{}],
      ['https://evil.invalid'+path,{}],
      [ORIGIN+path,{headers:{'X-Role':'tenant-owner'}}],
      [ORIGIN+path,{headers:{Cookie:'session=forged'}}],
      [ORIGIN+path,{headers:{'X-Forwarded-Tenant':'demo-orbit'}}],
      [ORIGIN+path,{headers:{Origin:'https://evil.invalid'}}],
      [ORIGIN+path,{headers:{'Sec-Fetch-Site':'cross-site'}}],
    ] as const;
    for (const [url,init] of reject){
      const res=await f.send(url,init);
      expect([403,404]).toContain(res.status);
      expect(JSON.stringify(await res.json())).not.toContain('demo-orbit');
    }
    expect(f.stats.connections).toBe(0);
    expect((await f.send(ORIGIN+path,{method:'POST'})).status).toBe(405);
    expect(f.stats.connections).toBe(0);
  });

  test('DB-level denial is 404 and no SQL fields reach client',async()=>{
    const f=fixture({dbAllowed:false});
    const res=await f.send();
    expect(res.status).toBe(404);
    const text=await res.text();
    expect(text).not.toContain('north-project');
    expect(text).not.toContain('saas_rls');
    expect(f.audited.at(-1)?.result).toBe('deny');
  });

  test('server membership revoked after SQL read discards a stale response',async()=>{
    const f=fixture({revokeDuringSql:true});
    const res=await f.send();
    expect(res.status).toBe(404);
    expect(await res.text()).not.toContain('north-project');
    expect(f.stats.selects).toBe(2);
    expect(f.audited.at(-1)?.reason).toBe('authorization-changed');
  });

  test('unexpected tenant/duplicate/malformed database data is rejected before audit allow',async()=>{
    const sets=[
      [{...project,tenant_id:'demo-orbit'}],
      [{...project},{...project}],
      [{...project,name:null}],
      [{...project,id:'north!evil'}],
      [{...project,status:'secret'}],
    ];
    for(const rows of sets){
      const f=fixture({signedRows:rows});
      const res=await f.send();
      expect(res.status).toBe(503);
      const body=await res.text();
      expect(body).not.toContain('north-project');
      expect(body).not.toContain('demo-orbit');
      expect(f.audited.some(a=>a.result==='allow')).toBe(false);
    }
  });

  test('signer or audit failure gives 503 with no private data or secrets',async()=>{
    for(const mode of [{signerFails:true},{denyAudit:true}]){
      const f=fixture(mode);
      const res=await f.send();
      expect(res.status).toBe(503);
      const body=await res.text();
      for(const secret of ['North Project','DB_HMAC_SECRET','AUDIT_SINK_SECRET',
        'ok.token.signature','saas_rls'])expect(body).not.toContain(secret);
    }
  });

  test('required revision/token-fingerprint binding cannot be disabled by caller',()=>{
    const f=fixture();
    expect(()=>createTenantProjectsReadHttpHandler({
      ...f.deps,revisions:undefined as never,
    })).toThrow();
    expect(()=>createTenantProjectsReadHttpHandler({
      ...f.deps,expectedOrigin:'http://127.0.0.1:3333',
    })).toThrow();
    expect(()=>createTenantProjectsReadHttpHandler({
      ...f.deps,expectedOrigin:'https://evil.invalid/path',
    })).toThrow();
  });

  test('valid explicit limit never expands beyond 50',async()=>{
    const f=fixture();
    expect((await f.send(ORIGIN+path+'?limit=50')).status).toBe(200);
    expect((await f.send(ORIGIN+path+'?limit=1')).status).toBe(200);
  });
});
