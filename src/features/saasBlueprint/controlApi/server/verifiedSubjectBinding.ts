/**
 * Backend15: private preparation of an issuer+subject binding fingerprint.
 *
 * Only a trusted, operator-pinned RS256 access-token verifier may supply
 * issuer/subject. The resulting domain-separated digest is an operator INPUT,
 * NOT evidence to the database that any OIDC signature was verified.
 *
 * No database login creation, session issuance, tenant selection, HTTP route,
 * ID-token-as-access-token acceptance, secret persistence or network fetch.
 * Caller must independently approve a specific PG login, grant revision,
 * tenant membership, issuer policy and operator audit before enrollment.
 */
import type {AccessTokenVerifier} from './trustedAccessToken';

export interface SubjectBindingFingerprint {
  /** SHA-256 of "saas:issuer-subject:v1\\0" + issuer + "\\0" + subject (UTF-8). */
  readonly fingerprint: string;
  /** Verified access-token expiry in UNIX seconds. Not a DB session TTL. */
  readonly expiresAtSeconds: number;
}

export interface VerifiedSubjectFingerprintGate {
  verify(token: string): Promise<SubjectBindingFingerprint | null>;
}

const PREFIX = 'saas:issuer-subject:v1\0';
function safeIssuer(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 12 || value.length > 512 ||
      value.includes('\0')) return false;
  try {
    const u=new URL(value);
    return u.protocol==='https:' && u.href===value &&
      Boolean(u.hostname) && !u.username && !u.password && !u.search && !u.hash &&
      !['localhost','127.0.0.1','[::1]'].includes(u.hostname) &&
      !['.invalid','.example','.test','.localhost'].some(x=>u.hostname.endsWith(x));
  } catch { return false; }
}
function safeSubject(value: unknown): value is string {
  if (typeof value!=='string' || value.length<1 || value.length>256 ||
      value.includes('\0') || value.normalize('NFC')!==value) return false;
  for(let i=0;i<value.length;i++){
    const n=value.charCodeAt(i);
    if(n<32 || n===127) return false;
    // Unpaired UTF-16 surrogates would become U+FFFD under TextEncoder,
    // potentially making different subject strings hash identically.
    if(n>=0xD800 && n<=0xDBFF){
      const next=value.charCodeAt(i+1);
      if(!(next>=0xDC00 && next<=0xDFFF)) return false;
      i++;
    } else if(n>=0xDC00 && n<=0xDFFF) return false;
  }
  return true;
}
export function createOperatorVerifiedSubjectFingerprintGate(
  verifier: AccessTokenVerifier,
  nowSeconds: () => number = () => Math.floor(Date.now()/1000),
): VerifiedSubjectFingerprintGate {
  if(!verifier || typeof verifier.verifyAccessToken!=='function' ||
     typeof nowSeconds!=='function')
    throw new Error('Backend15 subject verifier unavailable');
  return Object.freeze({
    async verify(token: string): Promise<SubjectBindingFingerprint | null> {
      try {
        if(typeof token!=='string' || !token || token.length>8192) return null;
        const identity=await verifier.verifyAccessToken(token);
        if(!identity || !safeIssuer(identity.issuer) ||
           !safeSubject(identity.subject)) return null;
        const now=nowSeconds();
        const expiresAtSeconds=identity.expiresAtSeconds;
        if(!Number.isSafeInteger(now) ||
           !Number.isSafeInteger(expiresAtSeconds) ||
           expiresAtSeconds===undefined || expiresAtSeconds<=now ||
           expiresAtSeconds>now+900) return null;

        // Deliberately do not hash the raw JWT, access_token jti, requested
        // tenant ID, actor role, HTTP header or self-asserted OIDC subject.
        const bytes=new TextEncoder().encode(
          PREFIX+identity.issuer+'\0'+identity.subject
        );
        const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',bytes));
        const fingerprint=Array.from(hash,b=>b.toString(16).padStart(2,'0')).join('');
        return Object.freeze({fingerprint,expiresAtSeconds});
      } catch {
        // No raw bearer, issuer, subject or key material in errors/logs.
        return null;
      }
    },
  });
}
