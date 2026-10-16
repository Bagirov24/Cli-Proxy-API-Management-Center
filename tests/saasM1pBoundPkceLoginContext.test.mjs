import {afterAll,afterEach,beforeAll,describe,expect,test} from 'bun:test';
import {createServer} from 'node:https';
import {createDisposableM1nTlsFixture} from '../scripts/saas-staging/m1n-ephemeral-tls-fixture.mjs';
import {createM1nPinnedHttpsTransport,loadM1nVerifiedOidc} from
  '../scripts/saas-staging/m1n-synthetic-https-trust.mjs';
import {createSyntheticPkceIssuer} from
  '../scripts/saas-staging/m1m-synthetic-pkce-code-flow.mjs';
import {createM1pBoundPkceClient} from
  '../scripts/saas-staging/m1p-bound-pkce-login-context.mjs';

const active=process.env.GITHUB_ACTIONS==='true' &&
  process.env.SAAS_EPHEMERAL_M1M_PKCE_CI==='true' &&
  process.env.SAAS_EPHEMERAL_M1N_TLS_CI==='true' &&
  process.env.SAAS_EPHEMERAL_M1O_TRUST_CI==='true' &&
  process.env.SAAS_EPHEMERAL_M1P_CONTEXT_CI==='true';
const ciTest=active?test:test.skip;
const ISSUER='https://m1p-only-disposable.invalid/realm';
const CLIENT_ID='m1p-client';
const AUD='m1p-ci';
const CALLBACK='http://127.0.0.1:18889/oauth/callback';
const NOW=1_800_000_000;
const DENY='M1p synthetic bound login context denied';
const live=[];
let tls,keys;
beforeAll(async()=>{
  if(!active)return;
  tls=createDisposableM1nTlsFixture();
  keys=await crypto.subtle.generateKey({
    name:'RSASSA-PKCS1-v1_5',modulusLength:2048,
    publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256',
  },true,['sign','verify']);
});
afterEach(async()=>{
  await Promise.all(live.splice(0).map(server=>new Promise(resolve=>{
    server.close(resolve);server.closeAllConnections?.();
  })));
});
afterAll(()=>tls?.dispose());

async function fixture(){
  let issuer=null,seen=0,hold=null;
  const server=createServer({
    cert:tls.primary.cert,key:tls.primary.key,minVersion:'TLSv1.2',
  },async(req,res)=>{
    seen++;
    try{
      const chunks=[];
      for await(const chunk of req)chunks.push(chunk);
      const origin='https://127.0.0.1:'+server.address().port;
      const request=new Request(origin+req.url,{
        method:req.method,
        headers:{'Content-Type':req.headers['content-type']||
          'application/json'},
        body:req.method==='POST'?Buffer.concat(chunks):undefined,
      });
      const reply=await issuer.handle(request);
      const data=Buffer.from(await reply.arrayBuffer());
      res.writeHead(reply.status,{
        ...Object.fromEntries(reply.headers),
        'Content-Length':String(data.length),Connection:'close',
      });
      res.end(data);
    }catch{
      const data=Buffer.from('{}');
      res.writeHead(503,{'Content-Type':'application/json',
        'Content-Length':String(data.length),Connection:'close'});
      res.end(data);
    }
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  live.push(server);
  const origin='https://127.0.0.1:'+server.address().port;
  const jwk=await crypto.subtle.exportKey('jwk',keys.publicKey);
  issuer=createSyntheticPkceIssuer({
    issuer:ISSUER,audience:AUD,origin,clientId:CLIENT_ID,
    redirectUri:CALLBACK,privateKey:keys.privateKey,publicJwk:jwk,
    nowSeconds:()=>NOW,kid:'M1p',
  });
  const transport=createM1nPinnedHttpsTransport({
    baseUrl:origin,callbackUri:CALLBACK,
    caPem:tls.trustedCaPem,spkiSha256:tls.primary.spkiSha256,
  });
  const verifier=await loadM1nVerifiedOidc({
    transport,issuer:ISSUER,audience:AUD,nowSeconds:()=>NOW,
  });
  const rows=[];
  const client=createM1pBoundPkceClient({
    issuer:ISSUER,clientId:CLIENT_ID,redirectUri:CALLBACK,
    authorizationUrl:origin+'/authorize',tokenUrl:origin+'/token',
    secureTransport:transport,nowSeconds:()=>NOW,
    tokenVerifier:{
      async verifyAccessToken(token){
        const identity=await verifier.verifyAccessToken(token);
        if(hold){hold.enter();await hold.resume;}
        return identity;
      },
    },
    async resolveActorId(identity){
      return identity.issuer===ISSUER&&identity.subject==='north'
        ?'actor-north':null;
    },
    provisionSessionSync({actorId,token}){
      expect(token).toContain('.');
      const row=Object.freeze({
        id:crypto.randomUUID(),revision:1,actorId,tenantId:'demo-north',
      });
      rows.push(row);
      return row;
    },
  });
  async function callbackFor(context){
    const start=client.begin(context);
    expect(start.authorizationUrl).not.toContain('code_verifier');
    const response=await transport.fetch(start.authorizationUrl);
    expect(response.status).toBe(302);
    return response.headers.get('location');
  }
  return {client,rows,issuer,origin,transport,callbackFor,
    seen:()=>seen,
    setHold(enter,resume){hold={enter,resume};},
    clearHold(){hold=null;},
  };
}

describe('M1p synthetic opaque browser login context and cancellation gate',()=>{
  test('default off outside explicit GitHub CI flags',()=>{
    if(!active)expect(()=>createM1pBoundPkceClient({}))
      .toThrow(DENY);
  });
  ciTest('parallel A/B real HTTPS callbacks cannot swap contexts or consume peer state',async()=>{
    const f=await fixture();
    const a=f.client.openContext(),b=f.client.openContext();
    const [ca,cb]=await Promise.all([
      f.callbackFor(a),f.callbackFor(b),
    ]);
    const before=f.issuer.stats().redeemedCodes;
    await expect(f.client.complete(a,cb)).rejects.toThrow(DENY);
    await expect(f.client.complete(b,ca)).rejects.toThrow(DENY);
    expect(f.issuer.stats().redeemedCodes).toBe(before);
    expect(f.rows).toHaveLength(0);
    const resultB=await f.client.complete(b,cb);
    const resultA=await f.client.complete(a,ca);
    expect(resultB.sessionId).not.toBe(resultA.sessionId);
    expect(f.rows).toHaveLength(2);
    await expect(f.client.complete(a,ca)).rejects.toThrow(DENY);
    await expect(f.client.complete(b,cb)).rejects.toThrow(DENY);
    expect(f.issuer.stats().redeemedCodes).toBe(before+2);
  });
  ciTest('terminal cancellation BEFORE callback never exchanges code or provisions PG session',async()=>{
    const f=await fixture();
    const a=f.client.openContext(),b=f.client.openContext();
    const ca=await f.callbackFor(a),cb=await f.callbackFor(b);
    const prior=f.issuer.stats().redeemedCodes;
    expect(f.client.cancelContext(a)).toBe(true);
    await expect(f.client.complete(a,ca)).rejects.toThrow(DENY);
    expect(()=>f.client.begin(a)).toThrow(DENY);
    expect(f.issuer.stats().redeemedCodes).toBe(prior);
    expect(f.rows).toHaveLength(0);
    expect((await f.client.complete(b,cb)).actorId).toBe('actor-north');
    expect(f.rows).toHaveLength(1);
  });
  ciTest('cancel WHILE pinned JWT verification is awaited, deny before registrar',async()=>{
    const f=await fixture();
    const a=f.client.openContext(),b=f.client.openContext();
    const ca=await f.callbackFor(a);
    let entered,release;
    const reached=new Promise(resolve=>{entered=resolve;});
    const resumed=new Promise(resolve=>{release=resolve;});
    f.setHold(entered,resumed);
    const task=f.client.complete(a,ca);
    try{
      await Promise.race([
        reached,new Promise((_,reject)=>setTimeout(
          ()=>reject(new Error('token verification hold not reached')),5000)),
      ]);
      expect(f.rows).toHaveLength(0);
      expect(f.client.cancelContext(a)).toBe(true);
    }finally{release();f.clearHold();}
    await expect(task).rejects.toThrow(DENY);
    expect(f.rows).toHaveLength(0);
    expect(f.issuer.stats().redeemedCodes).toBe(1); // spent once, NO retry
    await expect(f.client.complete(a,ca)).rejects.toThrow(DENY);
    const cb=await f.callbackFor(b);
    expect((await f.client.complete(b,cb)).tenantId).toBe('demo-north');
    expect(f.rows).toHaveLength(1);
    expect(f.issuer.stats().redeemedCodes).toBe(2);
  });
  ciTest('forged object, reused context and second outstanding login never activate',async()=>{
    const f=await fixture();
    const a=f.client.openContext();
    const callback=await f.callbackFor(a);
    expect(()=>f.client.begin(a)).toThrow(DENY);
    const fake=Object.freeze(Object.create(null));
    await expect(f.client.complete(fake,callback)).rejects.toThrow(DENY);
    expect(()=>f.client.cancelContext(fake)).toThrow(DENY);
    expect(f.rows).toHaveLength(0);
    expect((await f.client.complete(a,callback)).actorId).toBe('actor-north');
    expect(f.rows).toHaveLength(1);
    f.client.cancelContext(a);
    expect(()=>f.client.begin(a)).toThrow(DENY);
  });
  ciTest('bad callback with matching state consumes context state exactly once',async()=>{
    const f=await fixture();
    const a=f.client.openContext();
    const good=await f.callbackFor(a);
    const invalid=new URL(good);
    invalid.hash='access_token=forbidden';
    await expect(f.client.complete(a,invalid.href)).rejects.toThrow(DENY);
    await expect(f.client.complete(a,good)).rejects.toThrow(DENY);
    expect(f.rows).toHaveLength(0);
    expect(f.issuer.stats().redeemedCodes).toBe(0);
  });
  ciTest('bounded contexts and forbid asynchronous registration contract',async()=>{
    const f=await fixture();
    const sessions=Array.from({length:8},()=>f.client.openContext());
    expect(()=>f.client.openContext()).toThrow(DENY);
    f.client.cancelContext(sessions[0]);
    expect(f.client.stats()).toEqual({activeContexts:7});
    expect(f.client.openContext()).toBeDefined();
    expect(()=>createM1pBoundPkceClient({
      provisionSessionSync:async()=>null,
    })).toThrow(DENY);
  });
});
