/**
 * Backend16.15 — UNMOUNTED private mTLS secret-broker client implementing
 * Backend16.11's exact-id + immutable-version secret-reader interface.
 *
 * A broker endpoint and its policy are NOT provisioned by this module.
 * The caller must independently approve both public DER digests, the private
 * PKI and a broker-side get-only IAM policy before any staging connection.
 * No bearer, DB URL, login, tenant, HTTP request or arbitrary host selects
 * secret locations. No client error, response, password or PEM is logged.
 *
 * The strict HTTPS response is a single canonical JSON snapshot:
 *   {"username": "...", "password": "...",
 *    "version": "...", "expiresAtMs": <integer>}
 * Exactly one request per acquisition; no redirect, retry, list or cache.
 */
// @ts-expect-error Backend-only Node https, excluded from frontend tsconfig.
import {request as nativeHttpsRequest} from 'node:https';
// @ts-expect-error Backend-only Node TLS, excluded from frontend tsconfig.
import {checkServerIdentity as nativeCheckServerIdentity} from 'node:tls';
// @ts-expect-error Backend-only Node crypto, excluded from frontend tsconfig.
import {
  createHash,createPrivateKey,createPublicKey,timingSafeEqual,X509Certificate,
} from 'node:crypto';
import type {Backend16StagingVersionedSecretReader}
  from './backend16StagingVersionedPrincipalVault.ts';

const PROJECT='a9703851-6eb1-406c-bb15-7d3a89359fb7';
const ENVIRONMENT='b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const CONTROL_API='a0ff5420-95e8-4fab-88f6-623f75dd03c6';
const HOST='saas-secret-broker.railway.internal';
const PORT=443;
const FETCH_DEADLINE_MS=4_200;
const MAX_BODY_BYTES=2_048;
const MIN_ROOT_REMAINING_MS=7*24*60*60_000;
const MIN_CLIENT_REMAINING_MS=60_000;
const MIN_SECRET_LEASE_MS=60_000;
const MAX_SECRET_LEASE_MS=5*60_000;
const ID=/^b16-stg-pg-[a-z0-9_-]{16,80}$/;
const VERSION=/^[a-f0-9]{32,64}$/;
const SHA=/^[a-f0-9]{64}$/;
const LOGIN=/^[a-z][a-z0-9_]{2,62}$/;
const PASSWORD=/^[\x21-\x7e]{32,256}$/;
const SINGLE_PEM=
  /^-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]{1,76}\r?\n)+-----END CERTIFICATE-----\r?\n?$/;
const PRIVATE_PEM=
  /^-----BEGIN PRIVATE KEY-----\r?\n(?:[A-Za-z0-9+/=]{1,76}\r?\n)+-----END PRIVATE KEY-----\r?\n?$/;
const CONFIG_KEYS='approvedCaDerSha256,approvedClientCertDerSha256,caPem,clientCertPem,clientPrivateKeyPem';
const RESPONSE_KEYS='expiresAtMs,password,username,version';
const FORBIDDEN=new Set([
  'postgres','saas_schema_migrator','saas_runtime_reader','saas_runtime_writer',
]);

const env=()=>(globalThis as unknown as {
  process?:{env:Record<string,string|undefined>};
}).process?.env??{};

export type Backend16OperatorApprovedSecretBrokerMtls=Readonly<{
  /** Independently authenticated and SHA-pinned public root CA. */
  caPem:string;
  approvedCaDerSha256:string;
  /** Operator-pinned service identity; short-lived clientAuth leaf only. */
  clientCertPem:string;
  approvedClientCertDerSha256:string;
  /** PKCS#8, sourced out-of-band; never committed, logged or serialized. */
  clientPrivateKeyPem:string;
}>;

type ResponseLike={
  statusCode?:number;
  headers:Record<string,string|string[]|undefined>;
  on(event:string,handler:(arg?:Uint8Array)=>void):unknown;
  destroy():void;
};
type RequestLike={
  on(event:string,handler:()=>void):unknown;
  end():void;
  destroy():void;
};
const httpsRequest=nativeHttpsRequest as unknown as (
  options:Readonly<Record<string,unknown>>,
  onResponse:(response:ResponseLike)=>void,
)=>RequestLike;

function refuse():never{
  throw new Error('Backend16 private versioned secret service unavailable');
}
function plain(value:unknown,keys:string):boolean{
  if(!value||typeof value!=='object'||Array.isArray(value))return false;
  if(Object.getPrototypeOf(value)!==Object.prototype &&
     Object.getPrototypeOf(value)!==null)return false;
  const descriptors=Object.getOwnPropertyDescriptors(value);
  return Object.keys(descriptors).sort().join(',')===keys &&
    Object.values(descriptors).every(x=>'value' in x);
}
function strongKey(key:{asymmetricKeyType?:string;
  asymmetricKeyDetails?:{modulusLength?:number;namedCurve?:string}}):boolean{
  return (key.asymmetricKeyType==='rsa' &&
    (key.asymmetricKeyDetails?.modulusLength??0)>=3072)||
    (key.asymmetricKeyType==='ec' &&
      ['prime256v1','secp384r1','secp521r1'].includes(
        key.asymmetricKeyDetails?.namedCurve??''));
}
function isTime(value:unknown):value is number{
  return typeof value==='number'&&Number.isSafeInteger(value)&&value>0;
}
function binaryPin(input:string,raw:Uint8Array):boolean{
  if(!SHA.test(input))return false;
  const digest=createHash('sha256').update(raw).digest();
  const pairs=input.match(/.{2}/g)??[];
  const pin=Uint8Array.from(pairs,part=>Number.parseInt(part,16));
  return pin.length===digest.length&&timingSafeEqual(pin,digest);
}
function validateIdentity(input:unknown){
  if(!plain(input,CONFIG_KEYS))refuse();
  const config=input as Backend16OperatorApprovedSecretBrokerMtls;
  if(typeof config.caPem!=='string'||
     config.caPem.length<300||config.caPem.length>8192||
     !SINGLE_PEM.test(config.caPem)||
     typeof config.clientCertPem!=='string'||
     config.clientCertPem.length<300||config.clientCertPem.length>8192||
     !SINGLE_PEM.test(config.clientCertPem)||
     typeof config.clientPrivateKeyPem!=='string'||
     config.clientPrivateKeyPem.length<600||
     config.clientPrivateKeyPem.length>12_288||
     !PRIVATE_PEM.test(config.clientPrivateKeyPem)||
     typeof config.approvedCaDerSha256!=='string'||
     typeof config.approvedClientCertDerSha256!=='string')refuse();
  try{
    const root=new X509Certificate(config.caPem);
    const client=new X509Certificate(config.clientCertPem);
    const privateKey=createPrivateKey(config.clientPrivateKeyPem);
    const key=createPublicKey(privateKey);
    const expected=client.publicKey.export({format:'der',type:'spki'});
    const actual=key.export({format:'der',type:'spki'});
    const now=Date.now();
    const rootStart=Date.parse(root.validFrom),rootEnd=Date.parse(root.validTo);
    const clientStart=Date.parse(client.validFrom);
    const clientEnd=Date.parse(client.validTo);
    if(!isTime(now)||
       !binaryPin(config.approvedCaDerSha256,root.raw)||
       !binaryPin(config.approvedClientCertDerSha256,client.raw)||
       root.ca!==true||!root.checkIssued(root)||
       !root.verify(root.publicKey)||!strongKey(root.publicKey)||
       client.ca!==false||!client.checkIssued(root)||
       !client.verify(root.publicKey)||!strongKey(client.publicKey)||
       !client.keyUsage?.includes('1.3.6.1.5.5.7.3.2')||
       expected.length!==actual.length||
       !timingSafeEqual(expected,actual)||
       !Number.isFinite(rootStart)||!Number.isFinite(rootEnd)||
       !Number.isFinite(clientStart)||!Number.isFinite(clientEnd)||
       now<rootStart||now+MIN_ROOT_REMAINING_MS>=rootEnd||
       now<clientStart||now+MIN_CLIENT_REMAINING_MS>=clientEnd)
      refuse();
    // Keep private key only inside the returned closure, not in an exposed
    // public options or branded identity object. JS cannot zeroize strings.
    return Object.freeze({
      ca:config.caPem,cert:config.clientCertPem,
      key:config.clientPrivateKeyPem,
      rootValidFrom:rootStart,rootValidUntil:rootEnd,
      clientValidFrom:clientStart,clientValidUntil:clientEnd,
    });
  }catch{refuse();}
}
function validRuntime():boolean{
  const x=env();
  return x.RAILWAY_PROJECT_ID===PROJECT&&
    x.RAILWAY_ENVIRONMENT_ID===ENVIRONMENT&&
    x.RAILWAY_ENVIRONMENT_NAME==='staging'&&
    x.RAILWAY_SERVICE_ID===CONTROL_API&&
    x.SAAS_B16_STAGING_PRIVATE_ONLY==='true'&&
    x.SAAS_B16_SECRET_BROKER_APPROVED==='true'&&
    x.GITHUB_ACTIONS!=='true'&&x.SAAS_B16_EPHEMERAL_CI!=='true'&&
    x.NODE_TLS_REJECT_UNAUTHORIZED!=='0';
}
function validCi():boolean{
  const x=env();
  return x.GITHUB_ACTIONS==='true'&&
    x.SAAS_B16_EPHEMERAL_CI==='true'&&
    x.SAAS_B16_BROKER_MTLS_CI==='true'&&
    x.NODE_ENV!=='production'&&
    !x.RAILWAY_PROJECT_ID&&!x.RAILWAY_ENVIRONMENT_ID&&
    !x.RAILWAY_SERVICE_ID&&!x.RAILWAY_ENVIRONMENT&&
    x.NODE_TLS_REJECT_UNAUTHORIZED!=='0';
}

function readCanonicalSnapshot(data:Uint8Array,version:string):unknown{
  try{
    const text=new TextDecoder('utf-8',{fatal:true}).decode(data);
    const record:unknown=JSON.parse(text);
    if(!plain(record,RESPONSE_KEYS))refuse();
    const x=record as Record<string,unknown>;
    const username=x.username,password=x.password;
    const expiry=x.expiresAtMs;
    const now=Date.now();
    if(typeof username!=='string'||!LOGIN.test(username)||
       FORBIDDEN.has(username)||username.startsWith('pg_')||
       typeof password!=='string'||!PASSWORD.test(password)||
       x.version!==version||!isTime(now)||!isTime(expiry)||
       expiry-now<=MIN_SECRET_LEASE_MS||
       expiry-now>MAX_SECRET_LEASE_MS)refuse();
    // Exactly one canonical JSON record in a fixed field order: prevents
    // duplicate / escaped shadow fields and ambiguous parser overrides.
    if(text!==JSON.stringify({
      username,password,version,expiresAtMs:expiry,
    }))refuse();
    return Object.freeze({username,password,version,expiresAtMs:expiry});
  }catch{refuse();}
}

function buildReader(
  input:Backend16OperatorApprovedSecretBrokerMtls,
  address:typeof HOST|'127.0.0.1',
  port:number,
  permitted:()=>boolean,
):Backend16StagingVersionedSecretReader{
  if(!permitted())refuse();
  const identity=validateIdentity(input);
  return Object.freeze({
    async readVersion(secretId:string,version:string,signal:AbortSignal){
      try{
        if(!permitted()||typeof secretId!=='string'||!ID.test(secretId)||
           typeof version!=='string'||!VERSION.test(version)||
           !signal||signal.aborted)refuse();
        const now=Date.now();
        if(!isTime(now)||now<identity.rootValidFrom||
           now+MIN_ROOT_REMAINING_MS>=identity.rootValidUntil||
           now<identity.clientValidFrom||
           now+MIN_CLIENT_REMAINING_MS>=identity.clientValidUntil)refuse();
        return await new Promise<unknown>((resolve,reject)=>{
          let done=false,total=0;
          const chunks:Uint8Array[]=[];
          let req:RequestLike|undefined;
          const deadline=setTimeout(()=>finish(),FETCH_DEADLINE_MS);
          const onAbort=()=>finish();
          function finish(record?:unknown){
            if(done)return;
            done=true;
            clearTimeout(deadline);
            signal.removeEventListener('abort',onAbort);
            try{req?.destroy();}catch{/* fail closed */}
            if(record!==undefined&&!signal.aborted)resolve(record);
            else reject(new Error(
              'Backend16 private versioned secret service unavailable'));
          }
          signal.addEventListener('abort',onAbort,{once:true});
          try{
            if(signal.aborted){finish();return;}
            req=httpsRequest({
              protocol:'https:',hostname:address,port,servername:HOST,
              method:'GET',agent:false,
              path:'/v1/staging/principals/'+secretId+'/versions/'+version,
              ca:identity.ca,cert:identity.cert,key:identity.key,
              rejectUnauthorized:true,minVersion:'TLSv1.2',
              maxVersion:'TLSv1.3',timeout:3_900,
              checkServerIdentity:(hostname:string,peer:{raw?:Uint8Array})=>{
                try{
                  if(hostname!==HOST||!peer?.raw||
                     !new X509Certificate(peer.raw).checkHost(
                       HOST,{subject:'never'}))
                    return new Error('Backend16 broker DNS SAN refused');
                  // Use builtin hostname verification *in addition* to
                  // mandatory DNS SAN; custom callback never bypasses it.
                  return nativeCheckServerIdentity(hostname,peer);
                }catch{
                  return new Error('Backend16 broker DNS SAN refused');
                }
              },
              headers:Object.freeze({
                Accept:'application/json',
                'Cache-Control':'no-store',
                Connection:'close',
              }),
            },response=>{
              try{
                if(response.statusCode!==200||
                   response.headers['content-type']!=='application/json'||
                   response.headers['cache-control']!=='no-store'||
                   (response.headers['content-encoding']!==undefined&&
                    response.headers['content-encoding']!=='identity')||
                   (response.headers['content-length']!==undefined&&
                    (!/^[1-9][0-9]{0,3}$/.test(
                      String(response.headers['content-length']))||
                     Number(response.headers['content-length'])>MAX_BODY_BYTES))){
                  response.destroy();finish();return;
                }
                response.on('aborted',()=>finish());
                response.on('error',()=>finish());
                response.on('data',(chunk?:Uint8Array)=>{
                  if(done)return;
                  if(!(chunk instanceof Uint8Array)||
                     total+chunk.byteLength>MAX_BODY_BYTES){
                    response.destroy();finish();return;
                  }
                  total+=chunk.byteLength;
                  chunks.push(chunk);
                });
                response.on('end',()=>{
                  if(done||signal.aborted||total===0){finish();return;}
                  try{
                    const bytes=new Uint8Array(total);
                    let position=0;
                    for(const piece of chunks){
                      bytes.set(piece,position);position+=piece.length;
                    }
                    finish(readCanonicalSnapshot(bytes,version));
                  }catch{finish();}
                });
              }catch{finish();}
            });
            req.on('error',()=>finish());
            req.on('timeout',()=>finish());
            if(signal.aborted){finish();return;}
            req.end(); // only GET; no request body, secrets, or bearer
          }catch{finish();}
        });
      }catch{refuse();}
    },
  });
}

/** Fixed staging physical service: no arbitrary TLS or provider URL. */
export function createBackend16StagingMtlsSecretReader(
  trust:Backend16OperatorApprovedSecretBrokerMtls,
):Backend16StagingVersionedSecretReader{
  return buildReader(trust,HOST,PORT,validRuntime);
}

/**
 * Independent disposable CI-only localhost route; the TLS SNI and mandatory
 * DNS SAN stay the fixed private broker name, never loopback/localhost.
 */
export function createBackend16DisposableCiMtlsSecretReader(
  trust:Backend16OperatorApprovedSecretBrokerMtls,
  localPort:number,
):Backend16StagingVersionedSecretReader{
  if(!Number.isSafeInteger(localPort)||localPort<1024||
     localPort>65535||!validCi())refuse();
  return buildReader(trust,'127.0.0.1',localPort,validCi);
}
