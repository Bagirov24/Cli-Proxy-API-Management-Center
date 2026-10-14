/**
 * M1n disposable CI-only HTTPS *client*, NO real IdP or Railway TLS.
 *
 * Connect ONLY to literal 127.0.0.1; verify a pinned ephemeral CA chain,
 * SAN DNS:localhost and exact leaf SPKI-SHA256 on EVERY fresh TLS session.
 * Never disable Node TLS verification, follow redirects, reuse a connection,
 * accept browser cookies, allow DNS/SSRF or send sensitive data to HTTP.
 */
import https from 'node:https';
import { checkServerIdentity } from 'node:tls';
import { createHash, X509Certificate } from 'node:crypto';
import { m1nCiEnabled } from './m1n-ephemeral-tls-fixture.mjs';
import { createPinnedAccessTokenVerifier } from
  '../../src/features/saasBlueprint/controlApi/server/trustedAccessToken.ts';

const HEX64=/^[a-f0-9]{64}$/;
const SAFE_AUD=/^[A-Za-z0-9_-]{1,128}$/;
const KID=/^[A-Za-z0-9_-]{1,64}$/;
const B64=/^[A-Za-z0-9_-]+$/;
const ALLOWED=new Set([
  '/.well-known/openid-configuration','/jwks','/authorize','/token',
]);
const MAX_RESPONSE=16384;
const HEADER_CONTENT=/^application\/json(?:;\s*charset=utf-8)?$/i;

function exact(value,names) {
  return value&&typeof value==='object'&&!Array.isArray(value) &&
    Object.keys(value).sort().join(',')===names;
}
function originOf(url) {
  const parsed=new URL(url);
  if(parsed.protocol!=='https:'||parsed.hostname!=='127.0.0.1'||
     !/^[1-9][0-9]{0,4}$/.test(parsed.port)||
     Number(parsed.port)>65535||
     parsed.username||parsed.password||parsed.search||parsed.hash||
     parsed.pathname!=='/')throw new Error('M1n must pin exact CI loopback HTTPS origin');
  return parsed.origin;
}
/**
 * The mock issuer is a pinned *string* over ephemeral HTTPS. Real OIDC
 * issuer identity, anchor management and cert rotation need separate review.
 */
export function createM1nPinnedHttpsTransport({
  baseUrl,caPem,spkiSha256,callbackUri,
}) {
  if(!m1nCiEnabled())throw new Error('M1n trusted HTTPS disabled outside GitHub CI');
  const origin=originOf(baseUrl.endsWith('/')?baseUrl:baseUrl+'/');
  if(typeof caPem!=='string'||!caPem.includes('BEGIN CERTIFICATE')||
     !HEX64.test(spkiSha256))throw new Error('M1n CA/SPKI trust pin absent');
  const callback=new URL(callbackUri);
  if(callback.protocol!=='http:'||callback.hostname!=='127.0.0.1'||
     callback.pathname!=='/oauth/callback'||callback.search||
     callback.hash||callback.username||callback.password||
     !/^[1-9][0-9]{0,4}$/.test(callback.port)) {
    throw new Error('M1n CI callback allowlist invalid');
  }
  function checkPeer(_host,peer) {
    // Node first validates the CA/chain with rejectUnauthorized:true,
    // then invokes checkServerIdentity. Never override a chain failure.
    const hostError=checkServerIdentity('localhost',peer);
    if(hostError)return hostError;
    try {
      const cert=new X509Certificate(peer.raw);
      const actual=createHash('sha256')
        .update(cert.publicKey.export({format:'der',type:'spki'}))
        .digest('hex');
      if(actual!==spkiSha256)return new Error('M1n pinned TLS SPKI mismatch');
    }catch{return new Error('M1n pinned TLS certificate rejected');}
    return undefined;
  }
  return Object.freeze({
    origin,
    async fetch(url,options={}) {
      if(!m1nCiEnabled())throw new Error('M1n TLS CI guard disabled');
      const target=new URL(url);
      if(target.origin!==origin||target.protocol!=='https:'||
         target.username||target.password||target.hash||
         !ALLOWED.has(target.pathname) ||
         (target.pathname!=='/authorize'&&target.search)) {
        throw new Error('M1n unpinned HTTPS request target');
      }
      const method=options.method||'GET';
      if(!['GET','POST'].includes(method)||
         (method==='POST'&&target.pathname!=='/token')||
         (method==='GET'&&target.pathname==='/token')) {
        throw new Error('M1n invalid HTTPS method');
      }
      const outgoing=new Headers(options.headers??{});
      if(outgoing.has('cookie')||outgoing.has('authorization')||
         outgoing.has('host')||outgoing.has('proxy-authorization')) {
        throw new Error('M1n cookies/bearer cannot accompany IdP transport');
      }
      const payload=method==='POST'?
        (options.body instanceof URLSearchParams
          ?options.body.toString():null):null;
      if(method==='POST'&&
         (payload===null||Buffer.byteLength(payload)>2048||
           outgoing.get('content-type')!=='application/x-www-form-urlencoded')){
        throw new Error('M1n POST must be bounded PKCE form');
      }
      const headers={
        Accept:outgoing.get('accept')||'application/json',
        ...(payload!==null?{'Content-Type':'application/x-www-form-urlencoded',
          'Content-Length':Buffer.byteLength(payload)}:{}),
      };
      return await new Promise((resolve,reject)=>{
        let completed=false;
        const finish=(error,response)=>{
          if(completed)return;
          completed=true;
          if(error)reject(new Error('M1n verified HTTPS request denied'));
          else resolve(response);
        };
        const req=https.request(target,{
          method,headers,agent:false,servername:'localhost',
          ca:caPem,rejectUnauthorized:true,
          minVersion:'TLSv1.2',checkServerIdentity:checkPeer,
        },res=>{
          const status=res.statusCode;
          const loc=res.headers.location;
          // Authorization-code redirect is a LOCATION *value* only.
          // NEVER follow it, nor let it escape the pinned callback host.
          if(status===302) {
            let okay=false;
            try {
              const x=new URL(loc);
              okay=target.pathname==='/authorize'&&
                x.origin===callback.origin&&
                x.pathname===callback.pathname&&
                !x.hash&&!x.username&&!x.password&&
                [...x.searchParams.keys()].sort().join(',')==='code,state';
            }catch{}
            if(!okay){
              res.destroy();
              finish(new Error('M1n rejected redirect target'));return;
            }
          } else if(status>=300&&status<400){
            res.destroy();
            finish(new Error('M1n HTTP downgrade or redirect denied'));return;
          }
          if(res.headers['set-cookie']){
            res.destroy();finish(new Error('M1n IdP cookie denied'));return;
          }
          const declared=res.headers['content-length'];
          if(declared&&(!/^(0|[1-9][0-9]{0,5})$/.test(declared)||
             Number(declared)>MAX_RESPONSE)){
            res.destroy();finish(new Error('M1n oversized body'));return;
          }
          let size=0;
          const chunks=[];
          res.on('data',chunk=>{
            size+=chunk.length;
            if(size>MAX_RESPONSE) {
              res.destroy();finish(new Error('M1n HTTPS body overflow'));
            } else chunks.push(chunk);
          });
          res.on('error',err=>finish(err));
          res.on('end',()=>{
            if(completed)return;
            const responseHeaders=new Headers();
            for(const name of ['content-type','cache-control','location']){
              if(typeof res.headers[name]==='string')
                responseHeaders.set(name,res.headers[name]);
            }
            // 302 and 204 cannot carry a Web Response body.
            const body=status===302||status===204?null:Buffer.concat(chunks);
            try {
              finish(null,new Response(body,{
                status,headers:responseHeaders,
              }));
            }catch(e){finish(e);}
          });
        });
        req.setTimeout(4000,()=>req.destroy(new Error('M1n HTTPS timeout')));
        req.on('error',e=>finish(e));
        if(payload!==null)req.write(payload);
        req.end();
      });
    },
  });
}
/**
 * CI-only pinned HTTPS metadata/JWKS verification. One issuer+JWKS snapshot;
 * invalid fetch never publishes a verifier. No real discovery CA policy.
 */
export async function loadM1nVerifiedOidc({
  transport,issuer,audience,nowSeconds,
}){
  if(!m1nCiEnabled()||!transport?.origin||
     typeof nowSeconds!=='function'||typeof issuer!=='string'||
     !issuer.startsWith('https://')||!SAFE_AUD.test(audience)) {
    throw new Error('M1n HTTPS OIDC disabled');
  }
  const fetchObject=async(path)=>{
    const response=await transport.fetch(transport.origin+path,{
      method:'GET',headers:{Accept:'application/json'},
    });
    if(response.status!==200||!HEADER_CONTENT.test(
      response.headers.get('content-type')??'')) {
      throw new Error('M1n HTTPS OIDC response rejected');
    }
    const json=await response.json();
    return json;
  };
  try{
    const doc=await fetchObject('/.well-known/openid-configuration');
    if(!exact(doc,'id_token_signing_alg_values_supported,issuer,jwks_uri')||
       doc.issuer!==issuer||doc.jwks_uri!==transport.origin+'/jwks'||
       !Array.isArray(doc.id_token_signing_alg_values_supported)||
       doc.id_token_signing_alg_values_supported.length!==1||
       doc.id_token_signing_alg_values_supported[0]!=='RS256') {
      throw new Error('M1n pinned HTTPS issuer/JWKS conflict');
    }
    const jwks=await fetchObject('/jwks');
    if(!exact(jwks,'keys')||!Array.isArray(jwks.keys)||
       jwks.keys.length<1||jwks.keys.length>3) {
      throw new Error('M1n invalid JWKS cardinality');
    }
    const publicKeys=new Map();
    for(const item of jwks.keys){
      if(!exact(item,'alg,e,key_ops,kid,kty,n,use')||
         item.kty!=='RSA'||item.alg!=='RS256'||item.use!=='sig'||
         item.e!=='AQAB'||!KID.test(item.kid??'')||
         !Array.isArray(item.key_ops)||item.key_ops.length!==1||
         item.key_ops[0]!=='verify'||typeof item.n!=='string'||
         item.n.length<342||item.n.length>684||!B64.test(item.n)||
         publicKeys.has(item.kid)) {
        throw new Error('M1n HTTPS JWKS key rejected');
      }
      const key=await crypto.subtle.importKey('jwk',item,{
        name:'RSASSA-PKCS1-v1_5',hash:'SHA-256',
      },false,['verify']);
      if(key.algorithm.modulusLength<2048||
         key.algorithm.modulusLength>4096) {
        throw new Error('M1n RSA key size rejected');
      }
      publicKeys.set(item.kid,key);
    }
    return createPinnedAccessTokenVerifier({
      issuer,audience,publicKeys,nowSeconds,
    });
  }catch{
    throw new Error('M1n HTTPS issuer/keyset denied; no token trust published');
  }
}
