/**
 * Backend16.12 — certificate-only PostgreSQL16 private staging TLS observation.
 *
 * NO PostgreSQL StartupMessage, username, password, SQL, HTTP listener,
 * migration, writable transaction, retry, public proxy, volume or cron.
 * The single 8-byte PostgreSQL SSLRequest is followed by a TLS ClientHello.
 *
 * CA verification is deliberately disabled ONLY to observe public peer
 * certificates on a no-credential connection. It is NEVER an authenticated
 * database connection and NEVER proof of a trusted server/approved CA.
 * The real data-publishing Backend16.10 driver MUST keep verify-full.
 * See docs/saas/BACKEND_16_12_TLS_PEER_OBSERVATION.md.
 */
import {createConnection, type Socket} from 'node:net';
import {connect as tlsConnect, type TLSSocket} from 'node:tls';
import {createHash, X509Certificate} from 'node:crypto';

const PROJECT='a9703851-6eb1-406c-bb15-7d3a89359fb7';
const ENV='b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const SERVICE='saas-b16-pg-tls-peer-probe';
const HOST='postgres.railway.internal';
const PORT=5432;
const MAX_WAIT_MS=8_000;
const MAX_CERT_BYTES=32_768;
const SSL_REQUEST=Buffer.from([0,0,0,8,4,210,22,47]);
type PublicPeerEvidence=Readonly<{
  observation:'B16_TLS_PEER_ONLY_NOT_AUTHENTICATED';
  hostname:'postgres.railway.internal';
  leafDerSha256:string;
  issuerDerSha256:string|null;
  leafHasDnsSan:boolean;
  leafDnsSanMatchesPrivateHostname:boolean;
  leafValidAtObservation:boolean;
  leafNotAfterUtc:string;
  leafIsCa:boolean;
  tlsVersion:string;
  unverifiedChain:true;
  noCredentialsOrSql:true;
}>;
function refused():never{
  throw new Error('B16_TLS_PEER_PROBE_REFUSED_NO_DATABASE_AUTH');
}
function sha(data:Uint8Array):string{
  return createHash('sha256').update(data).digest('hex');
}
function exactRailwayContext():void{
  const env=process.env;
  if(env.RAILWAY_PROJECT_ID!==PROJECT||
     env.RAILWAY_ENVIRONMENT_ID!==ENV||
     env.RAILWAY_ENVIRONMENT_NAME!=='staging'||
     env.RAILWAY_SERVICE_NAME!==SERVICE||
     env.SAAS_B16_TLS_PEER_PROBE_EXPLICIT_ENABLE!=='true'||
     env.GITHUB_ACTIONS==='true')refused();
}

/** No SQL/credentials. No downgrade/fallback after any network failure. */
async function observePublicTlsCertificate():Promise<PublicPeerEvidence>{
  return new Promise<PublicPeerEvidence>((resolve,reject)=>{
    let complete=false;
    let tlsSocket:TLSSocket|undefined;
    const tcp:Socket=createConnection({host:HOST,port:PORT});
    const timeout=setTimeout(()=>fail(),MAX_WAIT_MS);
    function finish(evidence?:PublicPeerEvidence){
      if(complete)return;
      complete=true;
      clearTimeout(timeout);
      try{tlsSocket?.destroy();}catch{/* close anyway */}
      try{tcp.destroy();}catch{/* close anyway */}
      if(evidence)resolve(evidence);
      else reject(new Error('B16_TLS_PEER_PROBE_STOP_NO_TRUST_DECISION'));
    }
    function fail(){finish();}
    tcp.once('error',fail);
    tcp.once('connect',()=>{
      try{tcp.write(SSL_REQUEST);}catch{fail();}
    });
    tcp.once('data',(reply:Buffer)=>{
      // PostgreSQL SSLResponse is *exactly one byte* 'S' or 'N'.
      // Never proceed to a plaintext authentication or StartupMessage.
      if(reply.length!==1||reply[0]!==83){fail();return;}
      try{
        tlsSocket=tlsConnect({
          socket:tcp,servername:HOST,
          // INTROSPECTION ONLY: no password, user name, or SQL sent.
          // See driver Backend16.10: it requires a pinned CA and verify-full.
          rejectUnauthorized:false,
          minVersion:'TLSv1.2',
        });
        tlsSocket.once('error',fail);
        tlsSocket.once('secureConnect',()=>{
          try{
            if(!tlsSocket)refused();
            const cert=tlsSocket.getPeerCertificate(true);
            if(!cert?.raw||cert.raw.length<256||
               cert.raw.length>MAX_CERT_BYTES)refused();
            const leaf=new X509Certificate(cert.raw);
            const notBefore=Date.parse(leaf.validFrom);
            const notAfter=Date.parse(leaf.validTo);
            if(!Number.isFinite(notBefore)||!Number.isFinite(notAfter))
              refused();
            const clock=Date.now();
            const issuer=cert.issuerCertificate;
            const issuerHash=issuer?.raw&&issuer.raw.length<=MAX_CERT_BYTES?
              sha(issuer.raw):null;
            const dnsSan=typeof leaf.subjectAltName==='string'&&
              /(?:^|,\s*)DNS:/i.test(leaf.subjectAltName);
            // CN fallback is intentionally disallowed for new releases.
            const sanMatch=dnsSan&&
              Boolean(leaf.checkHost(HOST,{subject:'never'}));
            const version=tlsSocket.getProtocol();
            if(typeof version!=='string'||!/^TLSv1\.[23]$/.test(version))
              refused();
            finish(Object.freeze({
              observation:'B16_TLS_PEER_ONLY_NOT_AUTHENTICATED',
              hostname:HOST,
              leafDerSha256:sha(leaf.raw),
              issuerDerSha256:issuerHash,
              leafHasDnsSan:dnsSan,
              leafDnsSanMatchesPrivateHostname:sanMatch,
              leafValidAtObservation:clock>=notBefore&&clock<notAfter,
              leafNotAfterUtc:new Date(notAfter).toISOString(),
              leafIsCa:leaf.ca,
              tlsVersion:version,
              unverifiedChain:true,
              noCredentialsOrSql:true,
            }));
          }catch{fail();}
        });
      }catch{fail();}
    });
  });
}

async function main():Promise<void>{
  exactRailwayContext();
  const result=await observePublicTlsCertificate();
  // Only public digest/boolean/time evidence. Never log PEM, passwords,
  // connection strings, SQL rows, user names or full raw error diagnostics.
  console.info(JSON.stringify(result));
  console.info('B16_TLS_PEER_OBSERVED_CERTIFICATE_ONLY_NO_SQL');
  if(!result.leafDnsSanMatchesPrivateHostname||
     !result.leafValidAtObservation)
    console.info('B16_TLS_PEER_HOST_OR_VALIDITY_MISMATCH_STOP_RUNTIME');
  else
    console.info('B16_TLS_PEER_HOST_AND_VALIDITY_OBSERVED_CA_UNAPPROVED');
}
await main();
