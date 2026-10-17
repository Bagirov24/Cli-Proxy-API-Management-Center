/**
 * Backend16.14: unmounted verify-full PostgreSQL SSLRequest/TLS evidence.
 *
 * Unlike the Backend16.12 unauthenticated certificate inspection, this
 * verifies the live TLS chain against an independently approved, branded
 * Backend16.10 CA and requires a matching private DNS SAN. NO PostgreSQL
 * StartupMessage, LOGIN, password, JWT, SQL or network listener is sent.
 *
 * This does NOT approve a root CA or authorize database/production access.
 * Operator release approval and an authenticated least-privileged PG LOGIN
 * remain separate mandatory steps.
 */
// @ts-expect-error Backend-only Node net, excluded from frontend tsconfig.
import {createConnection} from 'node:net';
// @ts-expect-error Backend-only Node TLS, excluded from frontend tsconfig.
import {connect as tlsConnect} from 'node:tls';
// @ts-expect-error Backend-only Node crypto, excluded from frontend tsconfig.
import {createHash,X509Certificate} from 'node:crypto';
import {
  BACKEND16_STAGING_PG_TLS_HOST as HOST,
  backend16IsApprovedStagingPgTlsTrust,
  type Backend16StagingPgTlsTrust,
} from './backend16StagingPgTlsTrust';

const PROJECT='a9703851-6eb1-406c-bb15-7d3a89359fb7';
const ENV='b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const STAGING_SERVICE='saas-b16-pg-verified-tls-once';
const PORT=5432;
const SSL_REQUEST=Uint8Array.from([0,0,0,8,4,210,22,47]);
const TIMEOUT_MS=8_000;
const MIN_LEAF_BYTES=256;
const MAX_LEAF_BYTES=32_768;
const MIN_LEAF_REMAINING_MS=60_000;
const runtimeEnv=()=>(globalThis as unknown as {
  process?:{env:Record<string,string|undefined>};
}).process?.env??{};

export type Backend16VerifiedPrivatePgTlsEvidence=Readonly<{
  result:'B16_PINNED_CA_VERIFY_FULL_NO_DATABASE_AUTH';
  hostname:typeof HOST;
  leafDerSha256:string;
  approvedRootDerSha256:string;
  dnsSanMatchesPrivateHostname:true;
  tlsChainAuthorized:true;
  leafValidAtObservation:true;
  tlsVersion:'TLSv1.2'|'TLSv1.3';
  observedAtMs:number;
  noPostgresqlCredentialsOrSql:true;
  productionAuthorized:false;
}>;

function refuse():never{
  throw new Error('Backend16 pinned private PostgreSQL TLS verification refused');
}
function sha(buffer:Uint8Array):string{
  return createHash('sha256').update(buffer).digest('hex');
}
function validTrust(value:unknown):value is Backend16StagingPgTlsTrust{
  return backend16IsApprovedStagingPgTlsTrust(value) &&
    (value as Backend16StagingPgTlsTrust).serverName===HOST &&
    (value as Backend16StagingPgTlsTrust).rejectUnauthorized===true;
}

/** Internal dialer: caller cannot select a hostname or relax TLS policy. */
function handshake(
  address:typeof HOST|'127.0.0.1',port:number,
  trust:Backend16StagingPgTlsTrust,signal:AbortSignal,
):Promise<Backend16VerifiedPrivatePgTlsEvidence>{
  if(!validTrust(trust)||!signal||signal.aborted)refuse();
  return new Promise<Backend16VerifiedPrivatePgTlsEvidence>((resolve,reject)=>{
    let stopped=false;
    let plain:ReturnType<typeof createConnection>|undefined;
    let secure:ReturnType<typeof tlsConnect>|undefined;
    const timeout=setTimeout(()=>finish(),TIMEOUT_MS);
    const onAbort=()=>finish();
    signal.addEventListener('abort',onAbort,{once:true});

    function finish(value?:Backend16VerifiedPrivatePgTlsEvidence){
      if(stopped)return;
      stopped=true;
      clearTimeout(timeout);
      signal.removeEventListener('abort',onAbort);
      try{secure?.destroy();}catch{/* fail closed */}
      try{plain?.destroy();}catch{/* fail closed */}
      if(value)resolve(value);
      else reject(new Error(
        'Backend16 pinned private PostgreSQL TLS verification refused'));
    }
    if(signal.aborted){finish();return;}
    try{
      plain=createConnection({host:address,port});
      const socket=plain;
      socket.once('error',()=>finish());
      socket.once('connect',()=>{
        if(signal.aborted){finish();return;}
        try{socket.write(SSL_REQUEST);}catch{finish();}
      });
      socket.once('data',(response:Uint8Array)=>{
        // PostgreSQL's SSLResponse must be exactly the one-byte 'S'.
        // Refuse plaintext N, malformed/ambiguous replies and downgrade.
        if(stopped||response.length!==1||response[0]!==83){
          finish();return;
        }
        try{
          const verified=tlsConnect({
            socket,servername:HOST,ca:trust.ca,rejectUnauthorized:true,
            minVersion:'TLSv1.2',maxVersion:'TLSv1.3',
            checkServerIdentity:(hostname:string,cert:{raw?:Uint8Array})=>{
              try{
                if(hostname!==HOST||!cert?.raw||
                   !(new X509Certificate(cert.raw).checkHost(
                     HOST,{subject:'never'})))
                  return new Error('Backend16 strict DNS SAN refused');
                return undefined;
              }catch{
                return new Error('Backend16 strict DNS SAN refused');
              }
            },
          });
          secure=verified;
          verified.once('error',()=>finish());
          verified.once('secureConnect',()=>{
            try{
              if(stopped||signal.aborted||verified.authorized!==true||
                 verified.authorizationError||!validTrust(trust))
                refuse();
              const peer=verified.getPeerCertificate(true);
              if(!peer?.raw||peer.raw.length<MIN_LEAF_BYTES||
                 peer.raw.length>MAX_LEAF_BYTES)refuse();
              const cert=new X509Certificate(peer.raw);
              const now=Date.now();
              const before=Date.parse(cert.validFrom);
              const after=Date.parse(cert.validTo);
              if(!Number.isSafeInteger(now)||
                 !Number.isFinite(before)||!Number.isFinite(after)||
                 now<before||now+MIN_LEAF_REMAINING_MS>=after||
                 !cert.checkHost(HOST,{subject:'never'}))refuse();
              const version=verified.getProtocol();
              if(version!=='TLSv1.2'&&version!=='TLSv1.3')refuse();
              // Public digests only. The root fingerprint is an observation
              // of the operator-supplied CA, not independent CA approval.
              const root=new X509Certificate(trust.ca);
              finish(Object.freeze({
                result:'B16_PINNED_CA_VERIFY_FULL_NO_DATABASE_AUTH',
                hostname:HOST,
                leafDerSha256:sha(cert.raw),
                approvedRootDerSha256:sha(root.raw),
                dnsSanMatchesPrivateHostname:true,
                tlsChainAuthorized:true,
                leafValidAtObservation:true,
                tlsVersion:version,
                observedAtMs:now,
                noPostgresqlCredentialsOrSql:true,
                productionAuthorized:false,
              }));
            }catch{finish();}
          });
        }catch{finish();}
      });
    }catch{finish();}
  });
}

/**
 * Staging-only, zero-credential handshake. A separately reviewed operator
 * must first construct the branded trust from a public root CA and an
 * independently pinned release-manifest DER digest. There is no CA download,
 * TOFU, arbitrary host, env-provided fingerprint or fallback to 'require'.
 */
export function verifyBackend16StagingPrivatePgTls(
  trust:Backend16StagingPgTlsTrust,signal:AbortSignal,
):Promise<Backend16VerifiedPrivatePgTlsEvidence>{
  const env=runtimeEnv();
  if(env.RAILWAY_PROJECT_ID!==PROJECT||
     env.RAILWAY_ENVIRONMENT_ID!==ENV||
     env.RAILWAY_ENVIRONMENT_NAME!=='staging'||
     env.RAILWAY_SERVICE_NAME!==STAGING_SERVICE||
     env.SAAS_B16_VERIFIED_TLS_EXPLICIT_ENABLE!=='true'||
     env.GITHUB_ACTIONS==='true'||env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
     !validTrust(trust))refuse();
  return handshake(HOST,PORT,trust,signal);
}

/**
 * Distinct disposable GitHub CI entrypoint; never a Railway fallback.
 * Allows local fake-PostgreSQL SSLRequest servers only; TLS SNI and DNS
 * SAN stay fixed to the private hostname even though TCP is loopback.
 */
export function verifyBackend16DisposableCiPrivatePgTls(
  trust:Backend16StagingPgTlsTrust,signal:AbortSignal,localPort:number,
):Promise<Backend16VerifiedPrivatePgTlsEvidence>{
  const env=runtimeEnv();
  if(env.GITHUB_ACTIONS!=='true'||
     env.SAAS_B16_EPHEMERAL_CI!=='true'||
     env.SAAS_B16_VERIFYFULL_CI!=='true'||
     env.NODE_ENV==='production'||
     env.RAILWAY_PROJECT_ID||env.RAILWAY_ENVIRONMENT_ID||
     env.RAILWAY_SERVICE_ID||env.RAILWAY_ENVIRONMENT||
     !Number.isSafeInteger(localPort)||localPort<1024||localPort>65535||
     !validTrust(trust))refuse();
  return handshake('127.0.0.1',localPort,trust,signal);
}
