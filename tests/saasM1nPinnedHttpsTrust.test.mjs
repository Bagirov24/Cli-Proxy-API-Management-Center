import { afterAll, afterEach, beforeAll, describe, expect, test } from 'bun:test';
import { createServer } from 'node:https';
import { createDisposableM1nTlsFixture } from
  '../scripts/saas-staging/m1n-ephemeral-tls-fixture.mjs';
import {
  createM1nPinnedHttpsTransport, loadM1nVerifiedOidc,
} from '../scripts/saas-staging/m1n-synthetic-https-trust.mjs';
import {
  createSyntheticPkceClient,createSyntheticPkceIssuer,
} from '../scripts/saas-staging/m1m-synthetic-pkce-code-flow.mjs';

const enabled=process.env.GITHUB_ACTIONS==='true'&&
  process.env.SAAS_EPHEMERAL_M1M_PKCE_CI==='true'&&
  process.env.SAAS_EPHEMERAL_M1N_TLS_CI==='true';
const ciTest=enabled?test:test.skip;
const ISSUER='https://m1n-disposable-oidc.invalid/realm';
const AUDIENCE='saas-m1n-test';
const CLIENT_ID='m1n-ephemeral-client';
const CALLBACK='http://127.0.0.1:18882/oauth/callback';
const NOW=1_800_000_000;
let tls,keys;
const live=[];
beforeAll(async()=>{
  if(!enabled)return;
  tls=createDisposableM1nTlsFixture();
  keys=await crypto.subtle.generateKey({
    name:'RSASSA-PKCS1-v1_5',modulusLength:2048,
    publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256',
  },true,['sign','verify']);
});
afterEach(async()=>{
  await Promise.all(live.splice(0).map(s=>new Promise(resolve=>{
    s.close(()=>resolve());
    s.closeAllConnections?.();
  })));
});
afterAll(()=>tls?.dispose());
async function fixture(leaf='primary',override) {
  let issuer=null;
  let seen=0;
  const server=createServer({
    cert:tls[leaf].cert,key:tls[leaf].key,
    minVersion:'TLSv1.2',
  },async(req,res)=>{
    seen++;
    try{
      const chunks=[];
      let size=0;
      for await (const chunk of req){
        size+=chunk.byteLength;
        if(size>4096)throw Error('oversized mocked form');
        chunks.push(chunk);
      }
      const origin='https://127.0.0.1:'+server.address().port;
      const input=new Request(origin+req.url,{
        method:req.method,
        headers:{'Content-Type':req.headers['content-type']||'application/json'},
        body:req.method==='POST'?Buffer.concat(chunks):undefined,
      });
      const reply=(await override?.(input))??await issuer.handle(input);
      // Strict M1n HTTP/1.1 test protocol always emits ONE exact-size
      // Content-Length frame. Never use implicit chunked encoding.
      const result=Buffer.from(await reply.arrayBuffer());
      const responseHeaders={
        ...Object.fromEntries(reply.headers),
        'Content-Length':String(result.byteLength),
        Connection:'close',
      };
      res.writeHead(reply.status,responseHeaders);
      res.end(result);
    }catch{
      res.writeHead(503,{'Content-Type':'application/json'});
      res.end('{"error":"CI-only mock transport denied"}');
    }
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  live.push(server);
  const origin='https://127.0.0.1:'+server.address().port;
  const publicJwk=await crypto.subtle.exportKey('jwk',keys.publicKey);
  issuer=createSyntheticPkceIssuer({
    issuer:ISSUER,audience:AUDIENCE,origin,
    clientId:CLIENT_ID,redirectUri:CALLBACK,
    privateKey:keys.privateKey,publicJwk,
    nowSeconds:()=>NOW,kid:'M1n',
  });
  const transport=createM1nPinnedHttpsTransport({
    baseUrl:origin,caPem:tls.trustedCaPem,
    spkiSha256:tls[leaf].spkiSha256,callbackUri:CALLBACK,
  });
  return {
    transport,issuer,origin,
    count:()=>seen,
    makeTransport(args={}){
      return createM1nPinnedHttpsTransport({
        baseUrl:origin,caPem:tls.trustedCaPem,
        spkiSha256:tls[leaf].spkiSha256,callbackUri:CALLBACK,
        ...args,
      });
    },
  };
}
async function mockLogin(f) {
  const verifier=await loadM1nVerifiedOidc({
    transport:f.transport,issuer:ISSUER,
    audience:AUDIENCE,nowSeconds:()=>NOW,
  });
  const sessions=[];
  const client=createSyntheticPkceClient({
    issuer:ISSUER,clientId:CLIENT_ID,redirectUri:CALLBACK,
    authorizationUrl:f.origin+'/authorize',
    tokenUrl:f.origin+'/token',secureTransport:f.transport,
    tokenVerifier:verifier,nowSeconds:()=>NOW,
    async resolveActorId(identity) {
      return identity.issuer===ISSUER&&identity.subject==='north'
        ? 'actor-north':null;
    },
    async provisionSession({token,actorId}){
      const s=Object.freeze({
        id:crypto.randomUUID(),revision:1,tenantId:'demo-north',actorId,
      });
      sessions.push({session:s,token});
      return s;
    },
  });
  const started=client.begin();
  const response=await f.transport.fetch(started.authorizationUrl);
  expect(response.status).toBe(302);
  const callback=response.headers.get('location');
  expect(callback?.startsWith(CALLBACK+'?')).toBe(true);
  expect(callback).not.toContain('access_token');
  expect(started.authorizationUrl).not.toContain('code_verifier');
  const result=await client.complete(callback);
  return {result,client,sessions,callback};
}
describe('M1n disposable CA+SAN+SPKI pinned HTTPS trust for mock OAuth/PKCE',()=>{
  test('default-off TLS fixture/transport without explicit opt-in GitHub flags',()=>{
    if(!enabled){
      expect(()=>createDisposableM1nTlsFixture()).toThrow();
      expect(()=>createM1nPinnedHttpsTransport({
        baseUrl:'https://127.0.0.1:1234',
        caPem:'untrusted',spkiSha256:'0'.repeat(64),callbackUri:CALLBACK,
      })).toThrow();
    }
  });
  ciTest('real HTTPS certificate validation + pinned OIDC discovery/JWKS + one-time PKCE code',async()=>{
    const f=await fixture();
    const x=await mockLogin(f);
    expect(x.result.actorId).toBe('actor-north');
    expect(x.result.tenantId).toBe('demo-north');
    expect(x.result.sessionId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(x.sessions).toHaveLength(1);
    expect(x.result.accessToken).toContain('.');
    expect(f.issuer.stats().redeemedCodes).toBe(1);
    await expect(x.client.complete(x.callback)).rejects.toThrow(
      'M1m synthetic OAuth authorization denied');
    expect(f.issuer.stats().redeemedCodes).toBe(1);
  });
  ciTest('trusted CA but DIFFERENT leaf SPKI denies BEFORE any issuer HTTP bytes',async()=>{
    const f=await fixture('rotated');
    const wrong=f.makeTransport({spkiSha256:tls.primary.spkiSha256});
    await expect(wrong.fetch(f.origin+'/jwks')).rejects.toThrow(
      'M1n verified HTTPS request denied');
    expect(f.count()).toBe(0);
    // An operator-provided explicit new pin can accept a new leaf.
    const correct=await f.transport.fetch(f.origin+'/jwks');
    expect(correct.status).toBe(200);
    expect(f.count()).toBe(1);
  });
  ciTest('untrusted CA chain denies despite attacker supplying matching leaf SPKI',async()=>{
    const f=await fixture('untrusted');
    await expect(f.transport.fetch(f.origin+'/jwks')).rejects.toThrow(
      'M1n verified HTTPS request denied');
    expect(f.count()).toBe(0);
  });
  ciTest('wrong cert SAN hostname denies even when chain and SPKI are pinned',async()=>{
    const f=await fixture('wrongHost');
    await expect(f.transport.fetch(f.origin+'/jwks')).rejects.toThrow(
      'M1n verified HTTPS request denied');
    expect(f.count()).toBe(0);
  });
  ciTest('redirect downgrade, open redirect and fragment tokens are NEVER followed',async()=>{
    const f=await fixture('primary',input=>{
      if(new URL(input.url).pathname==='/authorize'){
        return new Response(null,{status:302,headers:{
          Location:'http://attacker.invalid/oauth/callback?code=bad&state=bad',
        }});
      }
    });
    const bogus=f.origin+'/authorize?client_id=x';
    await expect(f.transport.fetch(bogus)).rejects.toThrow(
      'M1n verified HTTPS request denied');
    expect(f.count()).toBe(1);
    await expect(f.transport.fetch('http://127.0.0.1:9090/jwks'))
      .rejects.toThrow('M1n unpinned HTTPS request target');
    await expect(f.transport.fetch('https://localhost:9090/jwks'))
      .rejects.toThrow('M1n unpinned HTTPS request target');
  });
  ciTest('foreign pinned OIDC issuer or malicious JWKS URI refuses token trust',async()=>{
    const f=await fixture('primary',input=>{
      if(new URL(input.url).pathname==='/.well-known/openid-configuration'){
        return Response.json({
          issuer:ISSUER,id_token_signing_alg_values_supported:['RS256'],
          jwks_uri:'http://127.0.0.1:9999/jwks',
        });
      }
    });
    await expect(loadM1nVerifiedOidc({
      transport:f.transport,issuer:ISSUER,
      audience:AUDIENCE,nowSeconds:()=>NOW,
    })).rejects.toThrow('M1n HTTPS issuer/keyset denied');
  });
  ciTest('CSRF callback URI origin/scheme, untrusted headers and POST paths rejected',async()=>{
    const f=await fixture();
    await expect(f.transport.fetch(f.origin+'/token',{
      method:'POST',headers:{Cookie:'SESSION=forged'},body:new URLSearchParams(),
    })).rejects.toThrow('M1n cookies/bearer cannot accompany IdP transport');
    await expect(f.transport.fetch(f.origin+'/token',{
      method:'GET',
    })).rejects.toThrow('M1n invalid HTTPS method');
    await expect(f.transport.fetch(f.origin+'/jwks?target=http://evil.invalid'))
      .rejects.toThrow('M1n unpinned HTTPS request target');
    const x=await mockLogin(f);
    const callback=new URL(x.callback);
    callback.hostname='localhost';
    await expect(x.client.complete(callback.href)).rejects.toThrow(
      'M1m synthetic OAuth authorization denied');
    const next=new URL(x.callback);
    next.hash='access_token=stolen';
    await expect(x.client.complete(next.href)).rejects.toThrow(
      'M1m synthetic OAuth authorization denied');
    expect(x.sessions).toHaveLength(1);
  });
});
