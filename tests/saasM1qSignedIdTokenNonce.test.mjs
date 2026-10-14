import {afterAll,afterEach,beforeAll,describe,expect,test} from 'bun:test';
import {createServer} from 'node:https';
import {createDisposableM1nTlsFixture} from
  '../scripts/saas-staging/m1n-ephemeral-tls-fixture.mjs';
import {createM1nPinnedHttpsTransport,loadM1nVerifiedOidc} from
  '../scripts/saas-staging/m1n-synthetic-https-trust.mjs';
import {createSyntheticPkceIssuer} from
  '../scripts/saas-staging/m1m-synthetic-pkce-code-flow.mjs';
import {createM1pBoundPkceClient} from
  '../scripts/saas-staging/m1p-bound-pkce-login-context.mjs';
import {createM1qPinnedIdTokenVerifier,m1qCiEnabled} from
  '../scripts/saas-staging/m1q-signed-id-token-nonce.mjs';

const active=process.env.GITHUB_ACTIONS==='true' &&
  process.env.SAAS_EPHEMERAL_M1M_PKCE_CI==='true' &&
  process.env.SAAS_EPHEMERAL_M1N_TLS_CI==='true' &&
  process.env.SAAS_EPHEMERAL_M1O_TRUST_CI==='true' &&
  process.env.SAAS_EPHEMERAL_M1P_CONTEXT_CI==='true' &&
  process.env.SAAS_EPHEMERAL_M1Q_ID_TOKEN_CI==='true';
const ciTest=active?test:test.skip;
const ISSUER='https://m1q-disposable.invalid/realm';
const CLIENT='m1q-oidc-client';
const AUD='m1q-api-audience';
const CALLBACK='http://127.0.0.1:18919/oauth/callback';
const NOW=1_800_000_000;
const DENY='M1p synthetic bound login context denied';
const servers=[];
let tls,keys,rogueKeys;

beforeAll(async()=>{
  if(!active)return;
  tls=createDisposableM1nTlsFixture();
  const options={name:'RSASSA-PKCS1-v1_5',modulusLength:2048,
    publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'};
  keys=await crypto.subtle.generateKey(options,true,['sign','verify']);
  rogueKeys=await crypto.subtle.generateKey(options,true,['sign','verify']);
});
afterEach(async()=>{
  await Promise.all(servers.splice(0).map(s=>new Promise(resolve=>{
    s.close(resolve);s.closeAllConnections?.();
  })));
});
afterAll(()=>tls?.dispose());

async function signedModification(jwt,mode){
  if(mode==='omit')return undefined;
  if(mode==='badSig')return jwt.slice(0,-2)+'AA';
  const [a,b]=jwt.split('.');
  const h=JSON.parse(Buffer.from(a,'base64url').toString('utf8'));
  const c=JSON.parse(Buffer.from(b,'base64url').toString('utf8'));
  if(mode==='nonce')c.nonce='N'.repeat(43);
  if(mode==='subject')c.sub='other-actor';
  if(mode==='audience')c.aud='forged-client';
  if(mode==='issuer')c.iss='https://wrong.invalid/';
  if(mode==='expired')c.exp=NOW-1;
  if(mode==='future')c.iat=NOW+999;
  if(mode==='alg')h.alg='none';
  if(mode==='kid')h.kid='other-key';
  if(mode==='extra')c.role='owner';
  const head=Buffer.from(JSON.stringify(h)).toString('base64url');
  const body=Buffer.from(JSON.stringify(c)).toString('base64url');
  const value=head+'.'+body;
  const key=mode==='foreignSigner'?rogueKeys.privateKey:keys.privateKey;
  const sig=await crypto.subtle.sign('RSASSA-PKCS1-v1_5',
    key,new TextEncoder().encode(value));
  return value+'.'+Buffer.from(sig).toString('base64url');
}
async function fixture(mode='valid'){
  let issuer=null,swapped=null,seen=0;
  const server=createServer({
    cert:tls.primary.cert,key:tls.primary.key,minVersion:'TLSv1.2',
  },async(req,res)=>{
    seen++;
    try{
      const chunks=[];
      for await(const part of req)chunks.push(part);
      const origin='https://127.0.0.1:'+server.address().port;
      const input=new Request(origin+req.url,{
        method:req.method,
        headers:{'Content-Type':req.headers['content-type']||
          'application/json'},
        body:req.method==='POST'?Buffer.concat(chunks):undefined,
      });
      let response=await issuer.handle(input);
      if(req.method==='POST'&&req.url==='/token'&&
         response.status===200&&mode!=='valid'){
        const tokenBody=await response.json();
        if(mode==='replay'){
          if(swapped===null)swapped=tokenBody.id_token;
          else tokenBody.id_token=swapped;
        }else{
          const altered=await signedModification(tokenBody.id_token,mode);
          if(altered===undefined)delete tokenBody.id_token;
          else tokenBody.id_token=altered;
        }
        response=Response.json(tokenBody,{headers:{'Cache-Control':'no-store'}});
      }
      const body=Buffer.from(await response.arrayBuffer());
      res.writeHead(response.status,{
        ...Object.fromEntries(response.headers),
        'Content-Length':String(body.length),Connection:'close',
      });
      res.end(body);
    }catch{
      const body=Buffer.from('{}');
      res.writeHead(503,{'Content-Type':'application/json',
        'Content-Length':String(body.length),Connection:'close'});
      res.end(body);
    }
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  servers.push(server);
  const origin='https://127.0.0.1:'+server.address().port;
  const publicJwk=await crypto.subtle.exportKey('jwk',keys.publicKey);
  issuer=createSyntheticPkceIssuer({
    issuer:ISSUER,audience:AUD,origin,clientId:CLIENT,
    redirectUri:CALLBACK,privateKey:keys.privateKey,publicJwk,
    kid:'M1q',nonceMode:true,nowSeconds:()=>NOW,
  });
  const transport=createM1nPinnedHttpsTransport({
    baseUrl:origin,caPem:tls.trustedCaPem,
    spkiSha256:tls.primary.spkiSha256,callbackUri:CALLBACK,
  });
  const access=await loadM1nVerifiedOidc({
    transport,issuer:ISSUER,audience:AUD,nowSeconds:()=>NOW,
  });
  const proof=await createM1qPinnedIdTokenVerifier({
    transport,issuer:ISSUER,clientId:CLIENT,kid:'M1q',nowSeconds:()=>NOW,
  });
  const rows=[];
  const client=createM1pBoundPkceClient({
    issuer:ISSUER,clientId:CLIENT,redirectUri:CALLBACK,
    authorizationUrl:origin+'/authorize',tokenUrl:origin+'/token',
    secureTransport:transport,tokenVerifier:access,nonceVerifier:proof,
    nowSeconds:()=>NOW,
    async resolveActorId(identity){
      return identity.issuer===ISSUER&&identity.subject==='north'
        ?'actor-north':null;
    },
    provisionSessionSync({actorId,token}){
      const row=Object.freeze({
        id:crypto.randomUUID(),revision:1,actorId,tenantId:'demo-north',
      });
      expect(token).toContain('.');
      rows.push(row);
      return row;
    },
  });
  async function authorize(context){
    const start=client.begin(context);
    const url=new URL(start.authorizationUrl);
    const response=await transport.fetch(start.authorizationUrl);
    return {url,callback:response.headers.get('location'),response};
  }
  return {client,issuer,transport,proof,rows,origin,authorize,seen:()=>seen};
}
describe('M1q pinned HTTPS synthetic signed ID token nonce before PG session',()=>{
  test('default off without all prior CI flags + M1q switch',async()=>{
    if(!active){
      expect(m1qCiEnabled()).toBe(false);
      await expect(createM1qPinnedIdTokenVerifier({
        issuer:ISSUER,clientId:CLIENT,kid:'M1q',nowSeconds:()=>NOW,
      })).rejects.toThrow('M1q signed ID-token nonce trust denied');
    }
  });
  ciTest('real HTTPS PKCE nonce per opaque context, two independent RS256 token types',async()=>{
    const f=await fixture();
    const a=f.client.openContext(),b=f.client.openContext();
    const xa=await f.authorize(a),xb=await f.authorize(b);
    const nonceA=xa.url.searchParams.get('nonce');
    const nonceB=xb.url.searchParams.get('nonce');
    expect(nonceA).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(nonceB).not.toBe(nonceA);
    expect(xa.callback).not.toContain('nonce=');
    expect(xa.callback).not.toContain('id_token');
    expect(xa.url.href).not.toContain('code_verifier');
    await expect(f.client.complete(a,xb.callback)).rejects.toThrow(DENY);
    expect(f.rows).toHaveLength(0);
    const first=await f.client.complete(b,xb.callback);
    const second=await f.client.complete(a,xa.callback);
    expect(first.sessionId).not.toBe(second.sessionId);
    expect(f.rows).toHaveLength(2);
    expect(f.issuer.stats().redeemedCodes).toBe(2);
    await expect(f.client.complete(a,xa.callback)).rejects.toThrow(DENY);
    expect(f.rows).toHaveLength(2);
    expect(await f.proof.verifyIdToken(second.accessToken,{
      nonce:nonceA,subject:'north',
    })).toBeNull(); // at+jwt is NOT an OIDC ID token.
  });
  ciTest('malicious but VALIDLY SIGNED nonce/aud/subject/issuer/expiry/header denies enrollment',async()=>{
    const attacks=['nonce','subject','audience','issuer','expired',
      'future','alg','kid','foreignSigner','badSig','extra','omit'];
    for(const mode of attacks){
      const f=await fixture(mode);
      const context=f.client.openContext();
      const x=await f.authorize(context);
      await expect(f.client.complete(context,x.callback)).rejects.toThrow(DENY);
      expect(f.rows).toHaveLength(0);
      expect(f.issuer.stats().redeemedCodes).toBe(1);
      await expect(f.client.complete(context,x.callback)).rejects.toThrow(DENY);
      expect(f.issuer.stats().redeemedCodes).toBe(1);
      // Servers are closed by the test fixture after each full test,
      // so the next attack uses a distinct loopback port and key identity.
    }
  });
  ciTest('replaying correctly signed A ID token for B fails nonce after B code spent',async()=>{
    const f=await fixture('replay');
    const a=f.client.openContext(),b=f.client.openContext();
    const ca=await f.authorize(a),cb=await f.authorize(b);
    expect((await f.client.complete(a,ca.callback)).tenantId).toBe('demo-north');
    await expect(f.client.complete(b,cb.callback)).rejects.toThrow(DENY);
    expect(f.rows).toHaveLength(1);
    expect(f.issuer.stats().redeemedCodes).toBe(2);
  });
  ciTest('issuer rejects missing, duplicate or malformed authorization nonce',async()=>{
    const f=await fixture();
    const a=f.client.openContext(),started=f.client.begin(a);
    const url=new URL(started.authorizationUrl);
    url.searchParams.delete('nonce');
    expect((await f.transport.fetch(url.href)).status).toBe(400);
    url.searchParams.set('nonce','not-43-bytes');
    expect((await f.transport.fetch(url.href)).status).toBe(400);
    url.searchParams.set('nonce','N'.repeat(43));
    url.searchParams.append('nonce','N'.repeat(43));
    expect((await f.transport.fetch(url.href)).status).toBe(400);
    expect(f.issuer.stats().issuedCodes).toBe(0);
    expect(f.rows).toHaveLength(0);
  });
});
