import {describe,expect,test} from 'bun:test';
import {
  createTenantProjectsWriteHttpHandler,
  type TenantProjectWriteAttempt,
  type TenantProjectsWriteHttpDependencies,
} from '../src/features/saasBlueprint/controlApi/server/tenantProjectsWriteHttpHandler';
import type {M1ProjectMutation} from
  '../src/features/saasBlueprint/controlApi/server/m1ProjectCommandBoundary';

const ORIGIN='https://control.example.invalid';
const ROOT='/control-api/v1/tenants/demo-north/projects';
const TOKEN='valid.signed.token';
const V4=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
type State='active'|'revoked';
function fixture() {
  const attempts:TenantProjectWriteAttempt[]=[];
  const writes:Array<M1ProjectMutation & {attemptId:string}>=[];
  const actor={id:'actor-north',memberships:[{
    tenantId:'demo-north',role:'tenant-admin' as const,
    status:'active' as State,
  }]};
  let writerMode:'ok'|'deny'|'throw'|'abort'='ok';
  let journalMode:'ok'|'throw'|'wrong'|'invalid'='ok';
  let actorRotated=false;
  let tokenRotated=false;
  let writeAbort:AbortController|null=null;
  const deps:TenantProjectsWriteHttpDependencies={
    expectedOrigin:ORIGIN,
    tokens:{
      async verifyAccessToken(token){
        if (token!==TOKEN || tokenRotated) return null;
        return {issuer:'https://issuer.example.invalid/',subject:'north'};
      },
    },
    directory:{
      async resolveActorId(identity){
        return identity.issuer==='https://issuer.example.invalid/' &&
          identity.subject==='north' && !actorRotated?'actor-north':null;
      },
    },
    actors:{
      async lookup(id){return id===actor.id?actor:null;},
    },
    journal:{
      async prepare(entry){
        attempts.push(entry);
        if (journalMode==='throw') throw new Error('JOURNAL_SIGNER_KEY_SECRET');
        if (journalMode==='wrong') return {attemptId:crypto.randomUUID(),sequence:1};
        if (journalMode==='invalid') return {attemptId:entry.attemptId,sequence:0};
        return {attemptId:entry.attemptId,sequence:attempts.length};
      },
    },
    writer:{
      async execute(input){
        writes.push(input);
        if (writerMode==='abort') writeAbort?.abort();
        if (writerMode==='throw') throw new Error('PG_CONNECTION_PRIVATE_DETAIL');
        return writerMode==='ok';
      },
    },
    newCorrelationId:()=> 'backend-server-correlation',
  };
  const handler=createTenantProjectsWriteHttpHandler(deps);
  function send(method:string,path=ROOT,payload:unknown={name:'Project'},
    extras:{headers?:HeadersInit;signal?:AbortSignal;raw?:string;bearer?:string}={}){
    const headers = new Headers(extras.headers);
    if (extras.bearer!=='' && !headers.has('authorization'))
      headers.set('Authorization','Bearer '+(extras.bearer??TOKEN));
    if (!headers.has('content-type'))
      headers.set('Content-Type','application/json');
    return handler(new Request(ORIGIN+path,{
      method,headers,signal:extras.signal,
      body:extras.raw??JSON.stringify(payload),
    }));
  }
  return {attempts,writes,actor,deps,handler,send,
    setWriter(value:typeof writerMode){writerMode=value;},
    setJournal(value:typeof journalMode){journalMode=value;},
    rotateActor(){actorRotated=true;},
    revokeToken(){tokenRotated=true;},
    setAbort(ctrl:AbortController){writeAbort=ctrl;},
  };
}
describe('SaaS backend tenant projects mutation POST/PATCH (unmounted)',()=>{
  test('POST derives project UUID/attempt UUID server-only AFTER verified actor',async()=>{
    const f=fixture();
    const response=await f.send('POST');
    expect(response.status).toBe(201);
    expect(response.headers.get('Cache-Control')).toContain('no-store');
    expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull();
    expect(response.headers.get('Set-Cookie')).toBeNull();
    expect(response.headers.get('X-Correlation-Id')).toBe('backend-server-correlation');
    const body=await response.json();
    expect(body).toMatchObject({
      ok:true,status:201,source:'signed-postgresql',apiVersion:1,
    });
    expect(body.projectId).toMatch(V4);
    expect(f.writes).toHaveLength(1);
    expect(f.attempts).toHaveLength(1);
    expect(f.attempts[0]).toEqual({
      attemptId:f.writes[0].attemptId,actorId:'actor-north',
      tenantId:'demo-north',projectId:body.projectId,
      operation:'create',expectedVersion:null,
    });
    expect(f.attempts[0].attemptId).toMatch(V4);
    expect(f.writes[0].scope).toEqual({
      actorId:'actor-north',tenantId:'demo-north',
      role:'tenant-admin',correlationId:'backend-server-correlation',
    });
    expect(f.writes[0].name).toBe('Project');
    const text=JSON.stringify(body);
    for(const forbidden of ['valid.signed.token','actor-north','attemptId',
      'JOURNAL_SIGNER_KEY_SECRET','PG_CONNECTION_PRIVATE_DETAIL'])
      expect(text).not.toContain(forbidden);
  });

  test('PATCH sends exact optimistic CAS version and never echoes tenant',async()=>{
    const f=fixture();
    const response=await f.send('PATCH',ROOT+'/project-24',
      {name:'Renamed',expectedVersion:13});
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok:true,status:200,apiVersion:1,source:'signed-postgresql',
    });
    expect(f.writes).toHaveLength(1);
    expect(f.writes[0]).toMatchObject({
      operation:'rename',projectId:'project-24',name:'Renamed',
      expectedVersion:13,
    });
    expect(f.attempts).toHaveLength(1);
    expect(f.attempts[0].expectedVersion).toBe(13);
    expect(f.attempts[0].projectId).toBe('project-24');
    expect(f.attempts[0].attemptId).toBe(f.writes[0].attemptId);
  });

  test('viewer/auditor/foreign tenant/revoked actor/rotated directory do not sign attempts',async()=>{
    const f=fixture();
    f.actor.memberships[0].role='tenant-admin'; // already trusted admin
    const wrong=await f.send('POST',
      '/control-api/v1/tenants/demo-orbit/projects');
    expect(wrong.status).toBe(404);
    f.actor.memberships[0].status='revoked';
    expect((await f.send('POST')).status).toBe(404);
    f.actor.memberships[0].status='active';
    f.rotateActor();
    expect((await f.send('POST')).status).toBe(401);
    expect(f.attempts).toHaveLength(0);
    expect(f.writes).toHaveLength(0);
    const g=fixture();
    (g.actor.memberships[0] as {role:string}).role='tenant-viewer';
    expect((await g.send('POST')).status).toBe(404);
    expect(g.writes).toHaveLength(0);
  });

  test('unverified token and forged authority headers refuse before journal/PG',async()=>{
    const f=fixture();
    expect((await f.handler(new Request(ORIGIN+ROOT,{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({name:'X'}),
    }))).status).toBe(401);
    expect((await f.send('POST',ROOT,{name:'X'},{
      bearer:'tampered.not.a.signature',
    })).status).toBe(401);
    const headers=[
      {'X-Role':'tenant-owner'},
      {'X-Actor-ID':'actor-admin'},
      {'X-Tenant-ID':'demo-orbit'},
      {'X-Attempt-ID':crypto.randomUUID()},
      {'Idempotency-Key':crypto.randomUUID()},
      {'X-Correlation-ID':'forged'},
      {'X-Token-Fingerprint':'1'.repeat(64)},
      {'If-Match':'0'},
      {Cookie:'session=forged'},
      {Origin:'https://evil.invalid'},
      {'Sec-Fetch-Site':'cross-site'},
    ];
    for(const item of headers){
      const res=await f.send('POST',ROOT,{name:'X'},{headers:item});
      expect(res.status).toBe(403);
    }
    expect(f.attempts).toHaveLength(0);
    expect(f.writes).toHaveLength(0);
  });

  test('routes and unsupported methods deny without creating attempts',async()=>{
    const f=fixture();
    const paths=[
      ROOT+'/',ROOT+'/project-1/',
      ROOT+'?tenant=demo-orbit',
      ROOT+'?retry=1',
      ROOT.replace('demo-north','demo-north%2fother'),
      '/control-api/v1/tenants/demo-orbit/metadata/projects',
    ];
    for(const path of paths)
      expect((await f.send('POST',path)).status).toBe(404);
    expect((await f.send('POST',ROOT+'/project-1')).status).toBe(405);
    expect((await f.send('PATCH',ROOT)).status).toBe(405);
    expect((await f.send('DELETE',ROOT+'/project-1')).status).toBe(405);
    expect(f.writes).toHaveLength(0);
  });

  test('strict bounded JSON and CAS never permit client attempt/identity claims',async()=>{
    const f=fixture();
    const inputs:Array<[string,string,unknown]>=[
      ['POST',ROOT,{}],['POST',ROOT,{name:''}],
      ['POST',ROOT,{name:' leading'}],
      ['POST',ROOT,{name:'bad\nname'}],
      ['POST',ROOT,{name:'a'.repeat(121)}],
      ['POST',ROOT,{name:'Valid',role:'tenant-owner'}],
      ['POST',ROOT,{name:'Valid',projectId:'client-project'}],
      ['POST',ROOT,{name:'Valid',attemptId:crypto.randomUUID()}],
      ['POST',ROOT,{name:'Valid',expectedVersion:1}],
      ['PATCH',ROOT+'/target',{name:'Valid'}],
      ['PATCH',ROOT+'/target',{name:'Valid',expectedVersion:0}],
      ['PATCH',ROOT+'/target',{name:'Valid',expectedVersion:-2}],
      ['PATCH',ROOT+'/target',{name:'Valid',expectedVersion:1.2}],
      ['PATCH',ROOT+'/target',{name:'Valid',expectedVersion:Number.MAX_SAFE_INTEGER}],
      ['PATCH',ROOT+'/target',{name:'Valid',expectedVersion:1,attemptId:'forged'}],
    ];
    for(const [method,path,body] of inputs)
      expect((await f.send(method,path,body)).status).toBe(404);
    for(const raw of ['{','null','[]','{"name":"X","tenantId":"other"}',
      JSON.stringify({name:'X'.repeat(600)})]){
      expect((await f.send('POST',ROOT,{name:'X'},{raw})).status).toBe(404);
    }
    const badContent=await f.send('POST',ROOT,{name:'X'},{
      headers:{'Content-Type':'text/plain'},
    });
    expect(badContent.status).toBe(404);
    expect(f.attempts).toHaveLength(0);
    expect(f.writes).toHaveLength(0);
  });

  test('missing or corrupt durable intent never reserves a database writer',async()=>{
    for(const mode of ['throw','wrong','invalid'] as const){
      const f=fixture();
      f.setJournal(mode);
      const res=await f.send('POST');
      expect(res.status).toBe(503);
      expect(await res.text()).not.toContain('JOURNAL_SIGNER_KEY_SECRET');
      expect(f.attempts).toHaveLength(1);
      expect(f.writes).toHaveLength(0);
    }
  });

  test('writer deny/unknown-after-COMMIT cannot retry a spent attempt',async()=>{
    for(const mode of ['deny','throw'] as const){
      const f=fixture();
      f.setWriter(mode);
      const res=await f.send('POST');
      expect(res.status).toBe(mode==='deny'?404:503);
      const serialized=await res.text();
      expect(serialized).not.toContain('PG_CONNECTION_PRIVATE_DETAIL');
      expect(serialized).not.toContain('attemptId');
      expect(f.attempts).toHaveLength(1);
      expect(f.writes).toHaveLength(1);
      expect(f.attempts[0].attemptId).toBe(f.writes[0].attemptId);
      // The handler MUST NOT automatically reissue this UUID or SQL write.
    }
  });

  test('request aborted while private PG COMMIT unknown yields 503, one attempt',async()=>{
    const f=fixture();
    const controller=new AbortController();
    f.setAbort(controller);
    f.setWriter('abort');
    const res=await f.send('PATCH',ROOT+'/target',
      {name:'Still closed',expectedVersion:1},{signal:controller.signal});
    expect(res.status).toBe(503);
    expect(f.writes).toHaveLength(1);
    expect(f.attempts).toHaveLength(1);
  });

  test('unsafe origin and missing signer or writer fail at configuration',()=>{
    const f=fixture();
    for(const expectedOrigin of [
      'http://control.example.invalid','http://127.0.0.1:18620',
      'https://control.example.invalid/path',
      'https://evil.invalid/?token=x',
    ]){
      expect(()=>createTenantProjectsWriteHttpHandler({
        ...f.deps,expectedOrigin,
      })).toThrow();
    }
    expect(()=>createTenantProjectsWriteHttpHandler({
      ...f.deps,journal:undefined as never,
    })).toThrow();
    expect(()=>createTenantProjectsWriteHttpHandler({
      ...f.deps,writer:undefined as never,
    })).toThrow();
  });
});
