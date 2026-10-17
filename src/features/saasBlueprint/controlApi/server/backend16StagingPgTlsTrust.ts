/**
 * Backend16.10: operator-pinned CA trust for the UNMOUNTED staging PG16 driver.
 *
 * This validates a separately approved CA certificate before exposing Bun.SQL
 * TLS options. It is NOT a CA discovery mechanism or proof that the running
 * Railway Postgres server presents a matching, unexpired SAN certificate.
 *
 * Never source BOTH the CA and its approved digest from the same untrusted
 * HTTP request, JWT, tenant, discovery endpoint, dynamic DNS, or DB response.
 * The digest belongs to a reviewed operator release policy. The CA PEM is
 * public trust material, NOT a credential; no embedded CI root is approved.
 */
import {createHash, timingSafeEqual, X509Certificate} from 'node:crypto';

export const BACKEND16_STAGING_PG_TLS_HOST = 'postgres.railway.internal';
const HEX = /^[a-f0-9]{64}$/;
const SINGLE_PEM =
  /^-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]{1,76}\r?\n)+-----END CERTIFICATE-----\r?\n?$/;
const MIN_REMAINING_MS = 7 * 24 * 60 * 60_000;

export type Backend16StagingPgTlsTrust = Readonly<{
  ca: string;
  serverName: typeof BACKEND16_STAGING_PG_TLS_HOST;
  rejectUnauthorized: true;
}>;

export type Backend16OperatorApprovedPgCa = Readonly<{
  /** Exactly one PEM-encoded, self-signed CA certificate (never a key). */
  caPem: string;
  /** Independently reviewed SHA256 of that certificate's binary DER bytes. */
  approvedCaDerSha256: string;
}>;

const approved = new WeakMap<object,{notBefore:number;notAfter:number}>();
function refuse():never{
  throw new Error('Backend16 staging PostgreSQL TLS trust refused');
}

/**
 * No environment lookup or dynamic CA download. At this point the operator
 * must have pinned a fingerprint through a separate code/release review.
 * Bun.SQL recognizes a TLS object with CA as verify-full (CA + hostname).
 */
export function createBackend16StagingPgTlsTrust(
  input:Backend16OperatorApprovedPgCa,
  nowMs:number=Date.now(),
):Backend16StagingPgTlsTrust {
  if(!input||typeof input.caPem!=='string'||
     input.caPem.length<300||input.caPem.length>8192||
     !SINGLE_PEM.test(input.caPem)||
     typeof input.approvedCaDerSha256!=='string'||
     !HEX.test(input.approvedCaDerSha256)||
     !Number.isSafeInteger(nowMs)||nowMs<=0)refuse();
  try{
    const cert=new X509Certificate(input.caPem);
    const candidate=createHash('sha256').update(cert.raw).digest();
    const pin=Buffer.from(input.approvedCaDerSha256,'hex');
    const notBefore=Date.parse(cert.validFrom);
    const notAfter=Date.parse(cert.validTo);
    const key=cert.publicKey;
    const strongRsa=key.asymmetricKeyType==='rsa' &&
      (key.asymmetricKeyDetails?.modulusLength??0)>=3072;
    const strongEc=key.asymmetricKeyType==='ec' &&
      ['prime256v1','secp384r1','secp521r1'].includes(
        key.asymmetricKeyDetails?.namedCurve??'');
    if(pin.length!==candidate.length||
       !timingSafeEqual(pin,candidate)||
       cert.ca!==true||
       !cert.checkIssued(cert)||!cert.verify(key)||
       (!strongRsa&&!strongEc)||
       !Number.isSafeInteger(notBefore)||!Number.isSafeInteger(notAfter)||
       nowMs<notBefore||nowMs+MIN_REMAINING_MS>=notAfter)refuse();

    // The hostname is hardcoded and cannot be selected by client inputs.
    // No "rejectUnauthorized:false", TLS downgrade or public proxy fallback.
    const tls=Object.freeze({
      ca:input.caPem,
      serverName:BACKEND16_STAGING_PG_TLS_HOST,
      rejectUnauthorized:true as const,
    });
    approved.set(tls,{notBefore,notAfter});
    return tls;
  }catch{refuse();}
}

/**
 * Only freshly approved objects produced by this module may reach Bun.SQL.
 * Revalidate certificate lifetime at every staging pool construction.
 */
export function backend16IsApprovedStagingPgTlsTrust(
  value:unknown,
):value is Backend16StagingPgTlsTrust {
  if(!value||typeof value!=='object')return false;
  const time=approved.get(value);
  const now=Date.now();
  return time!==undefined && now>=time.notBefore &&
    now+MIN_REMAINING_MS<time.notAfter;
}
