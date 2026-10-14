/**
 * M1m: synthetic OAuth2 authorization-code + PKCE S256 / state proof.
 * NOT an app route, real IdP, production OAuth/OIDC client, login, callback,
 * cookie, session store, refresh-token service or deployment.
 *
 * Both parties communicate exclusively over pinned 127.0.0.1 HTTP inside an
 * opt-in ephemeral GitHub CI job. Bearer tokens and PKCE verifier are held
 * only in this local test's server-side memory, never returned via redirect.
 */
import { createHash, randomBytes } from 'node:crypto';

const MAX_BODY=8192;
const STATE=/^[A-Za-z0-9_-]{43}$/;
const CODE=/^[A-Za-z0-9_-]{43}$/;
const SAFE_ID=/^[A-Za-z0-9_-]{1,128}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digest=value=>createHash('sha256').update(value,'utf8').digest('base64url');
const random=()=>randomBytes(32).toString('base64url');
const bytes=value=>new TextEncoder().encode(value);
const urlString=(input,pathname)=>{
  const url=new URL(input);
  if(url.protocol!=='http:'||url.hostname!=='127.0.0.1'||
     !/^[1-9][0-9]{0,4}$/.test(url.port)||
     Number(url.port)>65535||url.username||url.password||
     url.search||url.hash||url.pathname!==pathname) {
    throw new Error('M1m requires exact synthetic loopback URI');
  }
  return url.href;
};
function enabled(){
  return process.env.GITHUB_ACTIONS==='true' &&
    process.env.SAAS_EPHEMERAL_M1M_PKCE_CI==='true' &&
    process.env.NODE_ENV!=='production' &&
    !process.env.RAILWAY_PROJECT_ID &&
    !process.env.RAILWAY_ENVIRONMENT &&
    !process.env.RAILWAY_SERVICE_ID;
}
function insistEnabled(){
  if(!enabled())throw new Error('M1m mock authorization denied outside disposable CI');
}
// M1n never permits a public HTTPS endpoint; this is merely opt-in
// 127.0.0.1 with a separate pinned CA/hostname/SPKI trust transport.
function m1nEnabled(){
  return enabled() && process.env.SAAS_EPHEMERAL_M1N_TLS_CI==='true';
}
function m1qEnabled(){
  return m1nEnabled() &&
    process.env.SAAS_EPHEMERAL_M1O_TRUST_CI==='true' &&
    process.env.SAAS_EPHEMERAL_M1P_CONTEXT_CI==='true' &&
    process.env.SAAS_EPHEMERAL_M1Q_ID_TOKEN_CI==='true';
}
function issuerUrl(input,pathname,secure=false){
  const uri=new URL(input);
  if(uri.protocol==='http:'){
    if(secure)throw new Error('M1n cannot send OAuth codes over HTTP');
    return urlString(input,pathname);
  }
  if(!secure||!m1nEnabled()||uri.protocol!=='https:'||
     uri.hostname!=='127.0.0.1'||
     !/^[1-9][0-9]{0,4}$/.test(uri.port)||
     Number(uri.port)>65535||uri.username||uri.password||
     uri.search||uri.hash||uri.pathname!==pathname){
    throw new Error('M1n requires pinned opt-in HTTPS issuer transport');
  }
  return uri.href;
}
function exactParams(query,names){
  const all=[...query.keys()].sort().join(',');
  return all===names && [...query.values()].every(x=>typeof x==='string');
}
function exactObject(value,names){
  return value&&typeof value==='object'&&!Array.isArray(value)&&
    Object.keys(value).sort().join(',')===names;
}
function pinnedIssuer(value){
  const url=new URL(value);
  if(url.protocol!=='https:'||url.username||url.password||url.hash||
     url.search||url.origin==='null')throw new Error('M1m invalid pinned issuer');
  return value;
}
async function limitedText(response,limit){
  const len=response.headers.get('content-length');
  if(len&&(!/^(0|[1-9][0-9]{0,5})$/.test(len)||Number(len)>limit)){
    throw new Error('M1m oversized response');
  }
  if(!response.body)throw new Error('M1m empty body');
  const reader=response.body.getReader();
  let size=0;
  const chunks=[];
  try {
    while(true){
      const chunk=await reader.read();
      if(chunk.done)break;
      size+=chunk.value.byteLength;
      if(size>limit){await reader.cancel();throw new Error('M1m oversized response');}
      chunks.push(chunk.value);
    }
  } finally {reader.releaseLock();}
  const data=new Uint8Array(size);
  let at=0;
  for(const chunk of chunks){data.set(chunk,at);at+=chunk.byteLength;}
  return new TextDecoder('utf-8',{fatal:true}).decode(data);
}
function genericDeny(){
  return new Error('M1m synthetic OAuth authorization denied');
}

/**
 * Server-only client. begin() supplies PUBLIC authorization parameters
 * (S256 challenge/state, never verifier). complete() receives the simulated
 * browser redirect, consumes state ONCE, verifies the trusted access token
 * and provisions a PRIVATE server-held session before returning bearer.
 */
export function createSyntheticPkceClient({
  issuer,clientId,redirectUri,authorizationUrl,tokenUrl,
  tokenVerifier,resolveActorId,provisionSession,nowSeconds,
  secureTransport,nonceVerifier,
}){
  insistEnabled();
  pinnedIssuer(issuer);
  if(!SAFE_ID.test(clientId)||typeof nowSeconds!=='function'||
      typeof tokenVerifier?.verifyAccessToken!=='function'||
      typeof resolveActorId!=='function'||
      typeof provisionSession!=='function')throw new Error('M1m bad client config');
  const redirect=urlString(redirectUri,'/oauth/callback');
  const secure=secureTransport!==undefined;
  if(secure&&(!m1nEnabled()||typeof secureTransport?.fetch!=='function'))
    throw new Error('M1n HTTPS transport missing or disabled');
  const withNonce=nonceVerifier!==undefined;
  if(withNonce&&(!secure||!m1qEnabled()||
     typeof nonceVerifier?.verifyIdToken!=='function'))
    throw new Error('M1q signed ID token nonce verifier disabled');
  const auth=issuerUrl(authorizationUrl,'/authorize',secure);
  const tokenEndpoint=issuerUrl(tokenUrl,'/token',secure);
  if(new URL(auth).origin!==new URL(tokenEndpoint).origin||
     (secure&&secureTransport.origin!==new URL(auth).origin))
    throw new Error('M1m auth/token origins must match pinned transport');
  const pending=new Map();
  return Object.freeze({
    begin(){
      insistEnabled();
      if(pending.size>=8)throw genericDeny();
      const state=random(),verifier=random();
      const nonce=withNonce?random():null;
      const hash=digest(state);
      pending.set(hash,{verifier,nonce,expiresAt:nowSeconds()+90});
      const url=new URL(auth);
      url.searchParams.set('response_type','code');
      url.searchParams.set('client_id',clientId);
      url.searchParams.set('redirect_uri',redirect);
      url.searchParams.set('scope','openid');
      url.searchParams.set('state',state);
      url.searchParams.set('code_challenge',digest(verifier));
      url.searchParams.set('code_challenge_method','S256');
      if(withNonce)url.searchParams.set('nonce',nonce);
      return Object.freeze({authorizationUrl:url.href});
    },
    async complete(callbackUri){
      insistEnabled();
      try {
        if(typeof callbackUri!=='string'||callbackUri.length>2048)
          throw genericDeny();
        const callback=new URL(callbackUri);
        if(callback.origin!==new URL(redirect).origin||
           callback.pathname!=='/oauth/callback'||
           callback.username||callback.password||callback.hash)throw genericDeny();
        const isError=exactParams(callback.searchParams,'error,state');
        if(!isError&&!exactParams(callback.searchParams,'code,state'))
          throw genericDeny();
        const state=callback.searchParams.get('state');
        if(!STATE.test(state??''))throw genericDeny();
        const index=digest(state);
        const item=pending.get(index);
        if(!item)throw genericDeny();
        // Consume even an IdP error response, invalid code, network error
        // or expired state. A browser callback can NEVER trigger retry.
        pending.delete(index);
        if(isError||item.expiresAt<=nowSeconds())throw genericDeny();
        const code=callback.searchParams.get('code');
        if(!CODE.test(code??''))throw genericDeny();
        const response=await (secure?secureTransport.fetch:fetch)(tokenEndpoint,{
          method:'POST',redirect:'error',cache:'no-store',
          credentials:'omit',signal:AbortSignal.timeout(4000),
          headers:{'Content-Type':'application/x-www-form-urlencoded',
            Accept:'application/json'},
          body:new URLSearchParams({
            grant_type:'authorization_code',code,client_id:clientId,
            redirect_uri:redirect,code_verifier:item.verifier,
          }),
        });
        if(response.status!==200||response.redirected||
           !/^application\/json(?:;\s*charset=utf-8)?$/i.test(
             response.headers.get('content-type')??''))throw genericDeny();
        const tokenBody=JSON.parse(await limitedText(response,MAX_BODY));
        if(!exactObject(tokenBody,withNonce
          ?'access_token,expires_in,id_token,token_type'
          :'access_token,expires_in,token_type')||
           tokenBody.token_type!=='Bearer'||
           !Number.isSafeInteger(tokenBody.expires_in)||
           tokenBody.expires_in<1||tokenBody.expires_in>900||
           typeof tokenBody.access_token!=='string'||
           tokenBody.access_token.length>8192)throw genericDeny();
        const identity=await tokenVerifier.verifyAccessToken(tokenBody.access_token);
        if(!identity||identity.issuer!==issuer||!SAFE_ID.test(identity.subject))
          throw genericDeny();
        if(withNonce){
          if(typeof tokenBody.id_token!=='string'||
             tokenBody.id_token.length>4096)throw genericDeny();
          // Require a second pinned RS256 token proving this exact login's
          // nonce, OAuth client audience and access-token subject BEFORE
          // resolving the actor or enrolling a server-owned PG16 session.
          const proof=await nonceVerifier.verifyIdToken(tokenBody.id_token,{
            nonce:item.nonce,subject:identity.subject,
          });
          if(!proof||proof.issuer!==issuer||
             proof.subject!==identity.subject)throw genericDeny();
        }
        const actorId=await resolveActorId(identity);
        if(!SAFE_ID.test(actorId??''))throw genericDeny();
        const session=await provisionSession({
          token:tokenBody.access_token,actorId,identity,
        });
        if(!session||!UUID.test(session.id)||session.actorId!==actorId||
           !SAFE_ID.test(session.tenantId)||
           session.revision!==1)throw genericDeny();
        // PRIVATE server-side result, never an HTTP redirect response.
        return Object.freeze({
          accessToken:tokenBody.access_token,actorId,sessionId:session.id,
          tenantId:session.tenantId,revision:session.revision,
        });
      } catch {
        throw genericDeny(); // No code/verifier/token/SQL/IdP data leaks.
      }
    },
    stats(){
      return Object.freeze({pendingStates:pending.size});
    },
  });
}

/**
 * Disposable mock issuer with TRUE one-time authorization code storage and
 * S256 verification. Its RSA key is ephemeral in the test harness.
 */
export function createSyntheticPkceIssuer({
  issuer,audience,origin,clientId,redirectUri,privateKey,publicJwk,
  nowSeconds,subject='north',kid='M1m',nonceMode=false,
}){
  insistEnabled();
  pinnedIssuer(issuer);
  const auth=issuerUrl(origin+'/authorize','/authorize',
    new URL(origin).protocol==='https:');
  if(nonceMode&&(!m1qEnabled()||new URL(origin).protocol!=='https:'))
    throw new Error('M1q synthetic ID-token issuer disabled');
  const base=new URL(auth).origin;
  const redirect=urlString(redirectUri,'/oauth/callback');
  if(!SAFE_ID.test(clientId)||!SAFE_ID.test(subject)||!SAFE_ID.test(kid)||
     !SAFE_ID.test(audience)||typeof nowSeconds!=='function'||
     privateKey?.type!=='private'||privateKey.algorithm?.name!=='RSASSA-PKCS1-v1_5'||
     !publicJwk?.n||publicJwk?.kty!=='RSA')throw new Error('M1m bad issuer config');
  const codes=new Map();
  let minted=0,spent=0,rejected=0;
  const fail=()=>{
    rejected++;
    return Response.json({error:'invalid_request'},{status:400,headers:{
      'Cache-Control':'no-store',
    }});
  };
  return Object.freeze({
    async handle(req){
      if(!enabled())return new Response('',{status:503});
      const url=new URL(req.url);
      if(url.origin!==base||req.headers.has('cookie'))return fail();
      if(req.method==='GET'&&url.pathname==='/.well-known/openid-configuration'){
        return Response.json({issuer,id_token_signing_alg_values_supported:['RS256'],
          jwks_uri:base+'/jwks'});
      }
      if(req.method==='GET'&&url.pathname==='/jwks'){
        return Response.json({keys:[{
          alg:'RS256',kty:'RSA',use:'sig',key_ops:['verify'],
          kid,e:'AQAB',n:publicJwk.n,
        }]});
      }
      if(req.method==='GET'&&url.pathname==='/authorize'){
        if(!exactParams(url.searchParams,nonceMode
           ?'client_id,code_challenge,code_challenge_method,nonce,redirect_uri,response_type,scope,state'
           :'client_id,code_challenge,code_challenge_method,redirect_uri,response_type,scope,state')||
           url.searchParams.get('client_id')!==clientId||
           url.searchParams.get('response_type')!=='code'||
           url.searchParams.get('scope')!=='openid'||
           url.searchParams.get('redirect_uri')!==redirect||
           url.searchParams.get('code_challenge_method')!=='S256'||
           !STATE.test(url.searchParams.get('state')??'')||
           !STATE.test(url.searchParams.get('code_challenge')??'')||
           (nonceMode&&!STATE.test(url.searchParams.get('nonce')??''))||
           codes.size>=16) return fail();
        const code=random();
        codes.set(digest(code),{
          challenge:url.searchParams.get('code_challenge'),
          ...(nonceMode?{nonce:url.searchParams.get('nonce')}:{}),
          expiresAt:nowSeconds()+90,
        });
        minted++;
        const callback=new URL(redirect);
        callback.searchParams.set('code',code);
        callback.searchParams.set('state',url.searchParams.get('state'));
        return new Response(null,{status:302,headers:{
          Location:callback.href,'Cache-Control':'no-store',
          'Referrer-Policy':'no-referrer',
        }});
      }
      if(req.method==='POST'&&url.pathname==='/token'&&!url.search){
        try{
          if(!/^application\/x-www-form-urlencoded(?:;\s*charset=utf-8)?$/i.test(
            req.headers.get('content-type')??''))return fail();
          const body=new URLSearchParams(await limitedText(
            req,1024));
          if(!exactParams(body,
             'client_id,code,code_verifier,grant_type,redirect_uri')||
             body.get('client_id')!==clientId||
             body.get('redirect_uri')!==redirect||
             body.get('grant_type')!=='authorization_code'||
             !CODE.test(body.get('code')??'')||
             !STATE.test(body.get('code_verifier')??''))return fail();
          const index=digest(body.get('code'));
          const entry=codes.get(index);
          if(!entry)return fail();
          // Consume BEFORE validating PKCE and BEFORE returning bearer.
          // Wrong code_verifier forfeits the code; no redemption retry.
          codes.delete(index);
          if(entry.expiresAt<=nowSeconds()||
             digest(body.get('code_verifier'))!==entry.challenge)return fail();
          const head=Buffer.from(JSON.stringify({
            alg:'RS256',typ:'at+jwt',kid,
          })).toString('base64url');
          const claims=Buffer.from(JSON.stringify({
            iss:issuer,aud:audience,sub:subject,
            iat:nowSeconds()-10,exp:nowSeconds()+120,
            jti:crypto.randomUUID(),
            role:'tenant-owner',actorId:'actor-orbit',
            tenantId:'demo-orbit',sid:'FORGED_UNTRUSTED_JWT_SID',
          })).toString('base64url');
          const input=head+'.'+claims;
          const signature=await crypto.subtle.sign(
            'RSASSA-PKCS1-v1_5',privateKey,bytes(input));
          let idToken;
          if(nonceMode){
            // Distinct signed CI-only ID token. OAuth client audience,
            // original authorization nonce and access token subject
            // are verified separately before mock PG enrollment.
            const idHeader=Buffer.from(JSON.stringify({
              alg:'RS256',kid,typ:'JWT',
            })).toString('base64url');
            const idClaims=Buffer.from(JSON.stringify({
              iss:issuer,aud:clientId,sub:subject,nonce:entry.nonce,
              iat:nowSeconds()-10,exp:nowSeconds()+120,
            })).toString('base64url');
            const idSigningInput=idHeader+'.'+idClaims;
            const idSignature=await crypto.subtle.sign(
              'RSASSA-PKCS1-v1_5',privateKey,bytes(idSigningInput));
            idToken=idSigningInput+'.'+
              Buffer.from(idSignature).toString('base64url');
          }
          spent++;
          return Response.json({
            access_token:input+'.'+Buffer.from(signature).toString('base64url'),
            ...(nonceMode?{id_token:idToken}:{}),
            token_type:'Bearer',expires_in:120,
          },{headers:{'Cache-Control':'no-store'}});
        }catch{return fail();}
      }
      return fail();
    },
    stats(){return Object.freeze({
      issuedCodes:minted,redeemedCodes:spent,
      rejectedRequests:rejected,outstandingCodes:codes.size,
    });},
  });
}
