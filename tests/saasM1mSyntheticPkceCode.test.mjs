import { beforeAll, afterEach, describe, expect, test } from 'bun:test';
import {
  createSyntheticPkceClient, createSyntheticPkceIssuer,
} from '../scripts/saas-staging/m1m-synthetic-pkce-code-flow.mjs';
import { createSyntheticOidcKeyRotation } from
  '../scripts/saas-staging/m1l-synthetic-oidc-rotation.mjs';

const ISSUER='https://m1m-ci-issuer.invalid/realm';
const AUDIENCE='saas-m1m-ci';
const CLIENT_ID='m1m-ephemeral-client';
const NOW=1_800_000_000;
const enabled=process.env.GITHUB_ACTIONS==='true' &&
  process.env.SAAS_EPHEMERAL_M1M_PKCE_CI==='true';
const ciTest=enabled?test:test.skip;
const servers=[];
let rsa;
beforeAll(async()=>{
  if(!enabled)return;
  rsa=await crypto.subtle.generateKey({
    name:'RSASSA-PKCS1-v1_5',modulusLength:2048,
    publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256',
  },true,['sign','verify']);
});
afterEach(()=>{
  for(const s of servers.splice(0))s.stop(true);
});
async function fixture(options={}) {
  let tick=NOW;
  let issuer;
  const server=Bun.serve({
    hostname:'127.0.0.1',port:0,
    fetch(request){
      return issuer?.handle(request) ?? new Response('unavailable',{status:503});
    },
  });
  servers.push(server);
  const origin='http://127.0.0.1:'+server.port;
  const redirectUri='http://127.0.0.1:18889/oauth/callback';
  const publicJwk=await crypto.subtle.exportKey('jwk',rsa.publicKey);
  issuer=createSyntheticPkceIssuer({
    issuer:ISSUER,audience:AUDIENCE,origin,clientId:CLIENT_ID,
    redirectUri,privateKey:rsa.privateKey,publicJwk,
    nowSeconds:()=>tick,
  });
  const oidc=createSyntheticOidcKeyRotation({
    issuer:ISSUER,audience:AUDIENCE,nowSeconds:()=>tick,
    discoveryUrl:origin+'/.well-known/openid-configuration',
    jwksUrl:origin+'/jwks',
  });
  await oidc.reload(1);
  const sessions=[];
  const client=createSyntheticPkceClient({
    issuer:ISSUER,clientId:CLIENT_ID,redirectUri,
    authorizationUrl:origin+'/authorize',tokenUrl:origin+'/token',
    nowSeconds:()=>tick,
    tokenVerifier:options.denyTokens
      ? {async verifyAccessToken(){return null;}}:oidc,
    async resolveActorId(identity){
      return identity.issuer===ISSUER&&identity.subject==='north'
        ? 'actor-north':null;
    },
    async provisionSession({token,actorId,identity}){
      expect(token).toContain('.');
      expect(actorId).toBe('actor-north');
      expect(identity.subject).toBe('north');
      const row=Object.freeze({
        id:crypto.randomUUID(),actorId,tenantId:'demo-north',revision:1,
      });
      sessions.push(row);
      return row;
    },
  });
  async function authorize({clientInstance=client}={}) {
    const started=clientInstance.begin();
    const response=await fetch(started.authorizationUrl,{redirect:'manual'});
    return {
      started,response,
      callback:response.headers.get('Location'),
    };
  }
  return {
    origin,redirectUri,client,issuer,oidc,sessions,
    authorize,setNow(value){tick=value;},
  };
}
const generic='M1m synthetic OAuth authorization denied';
describe('M1m opt-in synthetic OAuth authorization-code PKCE S256 with pinned JWKS',()=>{
  test('default-off: cannot construct login/issuer outside explicit GitHub CI',()=>{
    if(!enabled){
      expect(()=>createSyntheticPkceClient({
        issuer:ISSUER,clientId:CLIENT_ID,
        authorizationUrl:'http://127.0.0.1:1234/authorize',
        tokenUrl:'http://127.0.0.1:1234/token',
        redirectUri:'http://127.0.0.1:18889/oauth/callback',
        nowSeconds:()=>NOW,
      })).toThrow(/outside disposable CI/);
    }
  });
  ciTest('real loopback code exchange hides S256 verifier; server provisions trusted actor',async()=>{
    const f=await fixture();
    const {started,response,callback}=await f.authorize();
    expect(response.status).toBe(302);
    const u=new URL(started.authorizationUrl);
    expect(u.searchParams.get('response_type')).toBe('code');
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    expect(u.searchParams.get('scope')).toBe('openid');
    expect(u.searchParams.get('state')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(u.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(u.searchParams.get('code_verifier')).toBeNull();
    expect(callback).toStartWith(f.redirectUri+'?');
    expect(callback).not.toContain('access_token');
    expect(callback).not.toContain('id_token');
    expect(callback).not.toContain('code_verifier');
    const completed=await f.client.complete(callback);
    expect(completed.actorId).toBe('actor-north');
    expect(completed.tenantId).toBe('demo-north');
    expect(completed.revision).toBe(1);
    expect(completed.sessionId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(completed.accessToken).toContain('.');
    const jwtBody=JSON.parse(Buffer.from(completed.accessToken.split('.')[1],
      'base64url').toString('utf8'));
    expect(jwtBody.role).toBe('tenant-owner');
    expect(jwtBody.actorId).toBe('actor-orbit');
    expect(jwtBody.sid).toBe('FORGED_UNTRUSTED_JWT_SID');
    expect(f.sessions).toHaveLength(1);
    expect(f.issuer.stats()).toEqual({
      issuedCodes:1,redeemedCodes:1,rejectedRequests:0,outstandingCodes:0,
    });
    expect(f.client.stats()).toEqual({pendingStates:0});
    await expect(f.client.complete(callback)).rejects.toThrow(generic);
    expect(f.sessions).toHaveLength(1);
  });
  ciTest('CSRF state forgery, duplicate parameters and foreign redirect never provision',async()=>{
    const f=await fixture();
    const x=await f.authorize();
    const valid=x.callback;
    const forged=new URL(valid);
    forged.searchParams.set('state','a'.repeat(43));
    await expect(f.client.complete(forged.href)).rejects.toThrow(generic);
    expect(f.client.stats().pendingStates).toBe(1);
    const extra=new URL(valid);
    extra.searchParams.append('state',extra.searchParams.get('state'));
    await expect(f.client.complete(extra.href)).rejects.toThrow(generic);
    const foreign=new URL(valid);
    foreign.hostname='localhost';
    await expect(f.client.complete(foreign.href)).rejects.toThrow(generic);
    const fragment=new URL(valid);
    fragment.hash='access_token=stolen';
    await expect(f.client.complete(fragment.href)).rejects.toThrow(generic);
    expect(f.sessions).toHaveLength(0);
    await f.client.complete(valid);
    expect(f.sessions).toHaveLength(1);
  });
  ciTest('two parallel auth starts cannot swap state/code or redeem twice',async()=>{
    const f=await fixture();
    const [a,b]=await Promise.all([f.authorize(),f.authorize()]);
    const swapped=new URL(a.callback);
    swapped.searchParams.set('state',new URL(b.callback).searchParams.get('state'));
    await expect(f.client.complete(swapped.href)).rejects.toThrow(generic);
    await expect(f.client.complete(a.callback)).rejects.toThrow(generic);
    await expect(f.client.complete(b.callback)).rejects.toThrow(generic);
    expect(f.sessions).toHaveLength(0);
    expect(f.issuer.stats().redeemedCodes).toBe(0);
    expect(f.client.stats().pendingStates).toBe(0);
    const c=await f.authorize();
    const results=await Promise.allSettled([
      f.client.complete(c.callback),f.client.complete(c.callback),
    ]);
    expect(results.filter(x=>x.status==='fulfilled')).toHaveLength(1);
    expect(results.filter(x=>x.status==='rejected')).toHaveLength(1);
    expect(f.sessions).toHaveLength(1);
    expect(f.issuer.stats().redeemedCodes).toBe(1);
  });
  ciTest('wrong code_verifier burns code at issuer; callback cannot retry',async()=>{
    const f=await fixture();
    const x=await f.authorize();
    const code=new URL(x.callback).searchParams.get('code');
    const response=await fetch(f.origin+'/token',{
      method:'POST',redirect:'error',headers:{
        'Content-Type':'application/x-www-form-urlencoded'},
      body:new URLSearchParams({
        grant_type:'authorization_code',client_id:CLIENT_ID,
        redirect_uri:f.redirectUri,code,code_verifier:'x'.repeat(43),
      }),
    });
    expect(response.status).toBe(400);
    await expect(f.client.complete(x.callback)).rejects.toThrow(generic);
    expect(f.sessions).toHaveLength(0);
    expect(f.issuer.stats().redeemedCodes).toBe(0);
    expect(f.issuer.stats().outstandingCodes).toBe(0);
  });
  ciTest('IdP error callback consumes state and refuses the later valid callback',async()=>{
    const f=await fixture();
    const x=await f.authorize();
    const failure=new URL(f.redirectUri);
    failure.searchParams.set('error','access_denied');
    failure.searchParams.set('state',new URL(x.callback).searchParams.get('state'));
    await expect(f.client.complete(failure.href)).rejects.toThrow(generic);
    expect(f.client.stats().pendingStates).toBe(0);
    await expect(f.client.complete(x.callback)).rejects.toThrow(generic);
    expect(f.sessions).toHaveLength(0);
  });
  ciTest('strict authorize request denies plain PKCE, client switch and redirect mismatch',async()=>{
    const f=await fixture();
    const begin=f.client.begin().authorizationUrl;
    for(const [name,value] of [
      ['code_challenge_method','plain'],
      ['client_id','forged-client'],
      ['redirect_uri','https://attacker.invalid/callback'],
      ['response_type','token'],
      ['scope','openid offline_access'],
    ]){
      const u=new URL(begin);
      u.searchParams.set(name,value);
      const response=await fetch(u.href,{redirect:'manual'});
      expect(response.status).toBe(400);
    }
    const extra=new URL(begin);
    extra.searchParams.append('state',extra.searchParams.get('state'));
    expect((await fetch(extra,{redirect:'manual'})).status).toBe(400);
    expect(f.issuer.stats().issuedCodes).toBe(0);
  });
  ciTest('expired state or denied verified token never provisions a session',async()=>{
    const f=await fixture();
    const x=await f.authorize();
    f.setNow(NOW+91);
    await expect(f.client.complete(x.callback)).rejects.toThrow(generic);
    expect(f.client.stats().pendingStates).toBe(0);
    expect(f.sessions).toHaveLength(0);
    const g=await fixture({denyTokens:true});
    const y=await g.authorize();
    await expect(g.client.complete(y.callback)).rejects.toThrow(generic);
    expect(g.sessions).toHaveLength(0);
  });
  ciTest('refuses external auth/token URLs, wrong redirect, bad issuer config',async()=>{
    const f=await fixture();
    for(const changes of [
      {authorizationUrl:'https://external.invalid/authorize'},
      {tokenUrl:'http://localhost:9999/token'},
      {tokenUrl:'http://127.0.0.1:9999/token'},
      {redirectUri:'https://attacker.invalid/oauth/callback'},
      {issuer:'http://insecure.invalid/'},
    ]){
      expect(()=>createSyntheticPkceClient({
        issuer:ISSUER,clientId:CLIENT_ID,redirectUri:f.redirectUri,
        authorizationUrl:f.origin+'/authorize',tokenUrl:f.origin+'/token',
        tokenVerifier:f.oidc,
        nowSeconds:()=>NOW,
        async resolveActorId(){return 'actor-north';},
        async provisionSession(){return null;},
        ...changes,
      })).toThrow();
    }
  });
  ciTest('maximum eight outstanding states blocks unbounded memory and retries',async()=>{
    const f=await fixture();
    const states=new Set();
    for(let i=0;i<8;i++){
      const started=f.client.begin();
      states.add(new URL(started.authorizationUrl).searchParams.get('state'));
    }
    expect(states.size).toBe(8);
    expect(f.client.stats().pendingStates).toBe(8);
    expect(()=>f.client.begin()).toThrow(generic);
  });
});
