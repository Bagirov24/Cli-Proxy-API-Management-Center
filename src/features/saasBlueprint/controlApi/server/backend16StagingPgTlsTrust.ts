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
// @ts-expect-error Backend-only Bun Node API; frontend tsconfig intentionally excludes Node types.
import {createHash, timingSafeEqual, X509Certificate} from 'node:crypto';
// @ts-expect-error Backend-only Node TLS; frontend tsconfig excludes Node types.
import {checkServerIdentity as nodeCheckServerIdentity} from 'node:tls';

export const BACKEND16_STAGING_PG_TLS_HOST = 'postgres.railway.internal';
const HEX = /^[a-f0-9]{64}$/;
const SINGLE_PEM =
  /^-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]{1,76}\r?\n)+-----END CERTIFICATE-----\r?\n?$/;
const MIN_REMAINING_MS = 7 * 24 * 60 * 60_000;

export type Backend16StagingPgTlsTrust = Readonly<{
  ca: string;
  serverName: typeof BACKEND16_STAGING_PG_TLS_HOST;
  rejectUnauthorized: true;
  /** Exact DNS SAN, not Node's normally valid wildcard-host matching. */
  checkServerIdentity: (hostname:string,cert:unknown)=>Error|undefined;
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
 * Bun.SQL calls this on the *authenticated SQL connection* after chain
 * verification and before sending the PostgreSQL LOGIN/password. This is
 * stricter than Node's wildcard-compatible ordinary hostname verification.
 * Fail closed on missing DER, absent SAN, CN-only or wildcard SAN.
 */
function exactPrivatePgServerIdentity(hostname:string,peer:unknown):Error|undefined {
  const denied=()=>new Error('Backend16 private PostgreSQL DNS SAN refused');
  if(hostname!==BACKEND16_STAGING_PG_TLS_HOST||!peer||
     typeof peer!=='object')return denied();
  try{
    const raw=(peer as {raw?:unknown}).raw;
    if(!(raw instanceof Uint8Array)||raw.length<256||
       raw.length>32768)return denied();
    const leaf=new X509Certificate(raw);
    const san=leaf.subjectAltName;
    if(typeof san!=='string'||
       !san.split(/,\s*/).includes('DNS:'+BACKEND16_STAGING_PG_TLS_HOST)||
       leaf.checkHost(BACKEND16_STAGING_PG_TLS_HOST,{
         subject:'never',wildcards:false,
       })!==BACKEND16_STAGING_PG_TLS_HOST)return denied();
    if(nodeCheckServerIdentity(
      BACKEND16_STAGING_PG_TLS_HOST,
      peer as Parameters<typeof nodeCheckServerIdentity>[1],
    ))return denied();
    return undefined;
  }catch{return denied();}
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
  // Validate data descriptors and snapshot before any certificate check.
  // Re-reading caller accessors after pinning could substitute another CA.
  if(!input||typeof input!=='object'||Array.isArray(input))refuse();
  const prototype=Object.getPrototypeOf(input);
  const props=Object.getOwnPropertyDescriptors(input);
  if((prototype!==Object.prototype&&prototype!==null)||
     Object.keys(props).sort().join(',')!=='approvedCaDerSha256,caPem'||
     !Object.values(props).every(d=>'value' in d))refuse();
  const caPem=props.caPem.value;
  const approvedCaDerSha256=props.approvedCaDerSha256.value;
  if(typeof caPem!=='string'||
     caPem.length<300||caPem.length>8192||
     !SINGLE_PEM.test(caPem)||
     typeof approvedCaDerSha256!=='string'||
     !HEX.test(approvedCaDerSha256)||
     !Number.isSafeInteger(nowMs)||nowMs<=0)refuse();
  try{
    const cert=new X509Certificate(caPem);
    const candidate=createHash('sha256').update(cert.raw).digest();
    const pairs=approvedCaDerSha256.match(/[a-f0-9]{2}/g)??[];
    const pin=Uint8Array.from(pairs,hex=>Number.parseInt(hex,16));
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
      ca:caPem,
      serverName:BACKEND16_STAGING_PG_TLS_HOST,
      rejectUnauthorized:true as const,
      checkServerIdentity:exactPrivatePgServerIdentity,
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
