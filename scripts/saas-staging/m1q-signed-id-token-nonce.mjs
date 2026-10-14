/**
 * M1q: disposable CI-only OIDC ID-token verifier over M1n CA/SAN/SPKI
 * pinned HTTPS JWKS. Separate from the access-token JWT verifier.
 * No dynamic jwks_uri/jku/x5u, no remote DNS, no production IAM/cookies.
 */
import {m1pCiEnabled} from './m1p-bound-pkce-login-context.mjs';

export function m1qCiEnabled(){
  return m1pCiEnabled() &&
    process.env.SAAS_EPHEMERAL_M1Q_ID_TOKEN_CI==='true';
}

const B64=/^[A-Za-z0-9_-]+$/;
const TEXT=/^[A-Za-z0-9_-]{1,128}$/;
const NONCE=/^[A-Za-z0-9_-]{43}$/;
const KID=/^[A-Za-z0-9_-]{1,64}$/;
const JSON_CONTENT=/^application\/json(?:;\s*charset=utf-8)?$/i;
const deny=()=>new Error('M1q signed ID-token nonce trust denied');

function exact(value,names){
  return value!==null&&typeof value==='object'&&!Array.isArray(value)&&
    Object.keys(value).sort().join(',')===names;
}
function parsePart(part){
  if(typeof part!=='string'||part.length>2048||!B64.test(part))
    throw deny();
  const encoded=Buffer.from(part,'base64url');
  if(encoded.toString('base64url')!==part)throw deny();
  const text=new TextDecoder('utf-8',{fatal:true}).decode(encoded);
  const decoded=JSON.parse(text);
  // Canonical fixture JSON: no duplicate or ambiguous JSON property names.
  if(JSON.stringify(decoded)!==text)throw deny();
  return decoded;
}
/**
 * Read ONLY the pinned issuer's fixed /jwks over the prevalidated M1n
 * transport. Caller must separately call loadM1nVerifiedOidc for access JWT,
 * discovery document, issuer identity and its own pinned JWKS verification.
 */
export async function createM1qPinnedIdTokenVerifier({
  transport,issuer,clientId,kid,nowSeconds,
}){
  if(!m1qCiEnabled()||typeof transport?.fetch!=='function'||
     typeof transport.origin!=='string'||
     !/^https:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(transport.origin)||
     typeof issuer!=='string'||!issuer.startsWith('https://')||
     !TEXT.test(clientId)||!KID.test(kid)||typeof nowSeconds!=='function')
    throw deny();
  try{
    const response=await transport.fetch(transport.origin+'/jwks',{
      method:'GET',headers:{Accept:'application/json'},
    });
    if(response.status!==200||!JSON_CONTENT.test(
      response.headers.get('content-type')??''))throw deny();
    const document=await response.json();
    if(!exact(document,'keys')||!Array.isArray(document.keys)||
       document.keys.length!==1)throw deny();
    const jwk=document.keys[0];
    if(!exact(jwk,'alg,e,key_ops,kid,kty,n,use')||
       jwk.kid!==kid||jwk.alg!=='RS256'||jwk.kty!=='RSA'||
       jwk.use!=='sig'||jwk.e!=='AQAB'||
       !Array.isArray(jwk.key_ops)||jwk.key_ops.length!==1||
       jwk.key_ops[0]!=='verify'||typeof jwk.n!=='string'||
       jwk.n.length<342||jwk.n.length>684||!B64.test(jwk.n))
      throw deny();
    const key=await crypto.subtle.importKey('jwk',jwk,{
      name:'RSASSA-PKCS1-v1_5',hash:'SHA-256',
    },false,['verify']);
    if(key.algorithm.modulusLength<2048||
       key.algorithm.modulusLength>4096)throw deny();
    return Object.freeze({
      async verifyIdToken(token,expectation){
        if(!m1qCiEnabled()||!exact(expectation,'nonce,subject')||
           !NONCE.test(expectation.nonce??'')||
           !TEXT.test(expectation.subject??'')||
           typeof token!=='string'||token.length>4096)return null;
        try{
          const pieces=token.split('.');
          if(pieces.length!==3||!B64.test(pieces[2]))return null;
          const header=parsePart(pieces[0]);
          const claims=parsePart(pieces[1]);
          if(!exact(header,'alg,kid,typ')||header.alg!=='RS256'||
             header.kid!==kid||header.typ!=='JWT'||
             !exact(claims,'aud,exp,iat,iss,nonce,sub')||
             claims.iss!==issuer||claims.aud!==clientId||
             claims.nonce!==expectation.nonce||
             claims.sub!==expectation.subject||
             !TEXT.test(claims.sub??'')||
             !Number.isSafeInteger(claims.iat)||
             !Number.isSafeInteger(claims.exp))return null;
          const now=nowSeconds();
          if(!Number.isSafeInteger(now)||
             claims.iat>now+30||claims.iat<now-300||
             claims.exp<=now||claims.exp>now+300||
             claims.exp<=claims.iat)return null;
          const raw=Buffer.from(pieces[2],'base64url');
          if(raw.toString('base64url')!==pieces[2]||
             raw.length!==key.algorithm.modulusLength/8)return null;
          const valid=await crypto.subtle.verify(
            'RSASSA-PKCS1-v1_5',key,raw,
            new TextEncoder().encode(pieces[0]+'.'+pieces[1]));
          return valid?Object.freeze({
            issuer:claims.iss,subject:claims.sub,
          }):null;
        }catch{return null;} // No token, JWKS or nonce diagnostics.
      },
    });
  }catch{
    throw deny(); // Invalid HTTPS key material publishes no trusted verifier.
  }
}
