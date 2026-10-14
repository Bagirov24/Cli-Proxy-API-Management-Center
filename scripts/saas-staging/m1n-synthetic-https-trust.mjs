/**
 * M1n disposable CI-only HTTPS *client*, NO real IdP or Railway TLS.
 *
 * Connect ONLY to literal 127.0.0.1; verify a pinned ephemeral CA chain,
 * SAN DNS:localhost and exact leaf SPKI-SHA256 on EVERY fresh TLS session.
 * Never disable Node TLS verification, follow redirects, reuse a connection,
 * accept browser cookies, allow DNS/SSRF or send sensitive data to HTTP.
 */
import { connect, checkServerIdentity } from 'node:tls';
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
      // Critical ordering: never let an HTTP client buffer/send OAuth
      // verifier/code before CA+SAN+SPKI have ALL been checked. Node's
      // HTTPS automatic HTTP writes can precede an extra SPKI rejection.
      // Complete a standalone TLS handshake and pin the live peer first,
      // then bind a one-use HTTP/1.1 Agent to that SAME encrypted socket.
      const socket=await new Promise((resolve,reject)=>{
        const peerSocket=connect({
          host:'127.0.0.1',port:Number(target.port),
          servername:'localhost',ca:caPem,rejectUnauthorized:true,
          minVersion:'TLSv1.2',
        });
        const deny=()=>{
          peerSocket.destroy();
          reject(new Error('M1n verified HTTPS request denied'));
        };
        peerSocket.setTimeout(4000,deny);
        peerSocket.once('error',deny);
        peerSocket.once('secureConnect',()=>{
          peerSocket.off('error',deny);
          if(!peerSocket.authorized ||
             checkPeer('localhost',peerSocket.getPeerCertificate(true))){
            deny();return;
          }
          peerSocket.setTimeout(0);
          resolve(peerSocket);
        });
      });
      return await new Promise((resolve,reject)=>{
        let completed=false,size=0;
        const chunks=[];
        const finish=(error,response)=>{
          if(completed)return;
          completed=true;
          socket.destroy();
          if(error)reject(new Error('M1n verified HTTPS request denied'));
          else resolve(response);
        };
        const decode=()=>{
          const buffer=Buffer.concat(chunks);
          const headerEnd=buffer.indexOf('\r\n\r\n');
          if(headerEnd<0||headerEnd>4096)throw Error('M1n invalid HTTP header frame');
          const raw=buffer.subarray(0,headerEnd).toString('latin1');
          const lines=raw.split('\r\n');
          if(!/^HTTP\/1\.[01] [1-5][0-9]{2}(?: |$)/.test(lines[0]))
            throw Error('M1n invalid HTTP status line');
          const status=Number(lines[0].slice(9,12));
          const responseHeaders=new Map();
          for(const line of lines.slice(1)){
            const colon=line.indexOf(':');
            if(colon<1||!/^[A-Za-z0-9-]+$/.test(line.slice(0,colon)))
              throw Error('M1n malformed HTTP response header');
            const k=line.slice(0,colon).toLowerCase();
            const v=line.slice(colon+1).trim();
            if(responseHeaders.has(k)||v.length>1024||/[\x00-\x1f\x7f]/.test(v))
              throw Error('M1n duplicate/unsafe HTTP header');
            responseHeaders.set(k,v);
          }
          if(responseHeaders.has('transfer-encoding')||
             responseHeaders.has('set-cookie'))
            throw Error('M1n chunked or cookie response forbidden');
          const declared=responseHeaders.get('content-length');
          if(declared===undefined||
             !/^(0|[1-9][0-9]{0,5})$/.test(declared)||
             Number(declared)>MAX_RESPONSE)
            throw Error('M1n response must have exact bounded length');
          const body=buffer.subarray(headerEnd+4);
          if(body.length!==Number(declared))
            throw Error('M1n response length mismatch');
          if(status===302){
            const loc=responseHeaders.get('location');
            const targetCallback=new URL(loc);
            if(target.pathname!=='/authorize'||
               targetCallback.origin!==callback.origin||
               targetCallback.pathname!==callback.pathname||
               targetCallback.username||targetCallback.password||
               targetCallback.hash||
               [...targetCallback.searchParams.keys()].sort().join(',')!=='code,state')
              throw Error('M1n redirect target denied');
          }else if(status>=300&&status<400)
            throw Error('M1n redirect and HTTP downgrade forbidden');
          const resultHeaders=new Headers();
          for(const k of ['content-type','cache-control','location']){
            if(responseHeaders.has(k))resultHeaders.set(k,responseHeaders.get(k));
          }
          const bodyValue=status===302||status===204?null:new Uint8Array(body);
          return new Response(bodyValue,{status,headers:resultHeaders});
        };
        socket.setTimeout(4000,()=>finish(new Error('M1n TLS response timed out')));
        socket.on('data',data=>{
          size+=data.length;
          if(size>MAX_RESPONSE+8192){
            finish(new Error('M1n response beyond total budget'));
            return;
          }
          chunks.push(data);
        });
        socket.on('error',err=>finish(err));
        socket.on('end',()=>{
          if(completed)return;
          try{finish(null,decode());}
          catch(e){finish(e);}
        });
        socket.on('close',()=>{
          if(!completed)finish(new Error('M1n premature TLS close'));
        });
        // HTTP is sent only AFTER secureConnect, CA+SAN validation and
        // mandatory leaf SPKI verification on the SAME encrypted socket.
        // We request Connection: close and require one exact-length frame.
        const requestLines=[
          method+' '+target.pathname+target.search+' HTTP/1.1',
          'Host: '+target.host,
          'Accept: '+headers.Accept,
          'Connection: close',
          ...(payload===null?[]:[
            'Content-Type: application/x-www-form-urlencoded',
            'Content-Length: '+Buffer.byteLength(payload),
          ]),
          '', '',
        ];
        socket.write(Buffer.from(requestLines.join('\r\n')+(payload??''),'utf8'));

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
