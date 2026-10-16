/**
 * Operator-pinned OAuth 2.0 JWT access-token trust, suitable as one part of a
 * production SaaS identity boundary.
 *
 * No network discovery, JWKS URL, fallback key, dynamic issuance, OAuth
 * callback, cookies or self-asserted actor/role. A trusted operator obtains
 * the issuer's RSA public keys out-of-band, approves the exact keyset, and
 * passes a versioned deployment configuration. Rotation is an explicit
 * config release; missing/invalid keys fail to initialize.
 *
 * This ONLY authenticates issuer+subject. The server must separately bind
 * that verified identity to tenant memberships and a durable session.
 */
import {
  createPinnedAccessTokenVerifier,
  type AccessTokenVerifier,
} from './trustedAccessToken';

export interface OperatorPinnedOidcAccessConfig {
  /** Exact HTTPS issuer published by the approved external IdP. */
  readonly issuer: string;
  /** OAuth access-token resource/audience, NEVER an ID-token client ID. */
  readonly audience: string;
  /**
   * Curated PUBLIC JWKS JSON document. No URLs, x5u/jku, x5c, private RSA
   * members, HMAC secrets, asymmetric algorithm switching or fetch.
   */
  readonly pinnedPublicJwksJson: string;
}

export interface OperatorPinnedOidcEnvironment {
  readonly SAAS_OIDC_ISSUER?: string;
  readonly SAAS_OIDC_AUDIENCE?: string;
  readonly SAAS_OIDC_PINNED_PUBLIC_JWKS_JSON?: string;
}

const KID = /^[A-Za-z0-9_-]{1,64}$/;
const B64U = /^[A-Za-z0-9_-]+$/;
const AUDIENCE = /^[A-Za-z0-9][A-Za-z0-9._~:/-]{0,255}$/;
const MAX_JWKS_BYTES = 24 * 1024;
const MAX_KEYS = 4;
const MIN_RSA_BYTES = 256;
const MAX_RSA_BYTES = 512;
const REQUIRED = ['alg','e','kid','kty','n','use'];
const WITH_KEY_OPS = [...REQUIRED,'key_ops'].sort().join(',');

type JsonObject = Record<string, unknown>;
function record(value: unknown): JsonObject | null {
  return value !== null && typeof value === 'object' &&
    !Array.isArray(value) ? value as JsonObject : null;
}
function invalid(): never {
  // Deliberately do NOT echo configuration, tokens, keys, issuers or URLs.
  throw new Error('Operator-pinned access-token trust configuration refused');
}
function exactIssuer(value: string): boolean {
  if (value.length < 12 || value.length > 512) return false;
  try {
    const u = new URL(value);
    const hostname = u.hostname.toLowerCase();
    return u.protocol === 'https:' && u.href === value &&
      !u.username && !u.password && !u.search && !u.hash &&
      !!hostname && !hostname.includes('..') &&
      !['localhost','127.0.0.1','[::1]'].includes(hostname) &&
      !['.test','.invalid','.example','.localhost'].some(
        suffix => hostname.endsWith(suffix)
      );
  } catch { return false; }
}
function decodeModulus(value: unknown): Uint8Array | null {
  if (typeof value !== 'string' || !B64U.test(value) ||
      value.length < 340 || value.length > 700 ||
      value.includes('=')) return null;
  try {
    const raw = atob(value.replace(/-/g,'+').replace(/_/g,'/') +
      '='.repeat((4 - value.length % 4) % 4));
    const bytes = Uint8Array.from(raw,c=>c.charCodeAt(0));
    // Minimal canonical RSA modulus; no leading zero or weak key length.
    if (bytes.length < MIN_RSA_BYTES || bytes.length > MAX_RSA_BYTES ||
        (bytes[0] & 0x80) === 0 || (bytes[bytes.length-1] & 1) === 0) {
      return null;
    }
    const canonical = btoa(String.fromCharCode(...bytes))
      .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
    return canonical === value ? bytes : null;
  } catch { return null; }
}
function exactJwkKeys(value: JsonObject): boolean {
  const keys=Object.keys(value).sort().join(',');
  return keys === REQUIRED.sort().join(',') || keys === WITH_KEY_OPS;
}

/**
 * Import RSA public keys as NON-extractable WebCrypto verification keys.
 * The absence of real operator-provided keys is a *startup error*, never a
 * fallback to the synthetic GitHub keys or a remotely discovered JWKS.
 */
export async function createOperatorPinnedOidcAccessVerifier(
  config: OperatorPinnedOidcAccessConfig
): Promise<AccessTokenVerifier> {
  if (!config || typeof config.issuer !== 'string' ||
      !exactIssuer(config.issuer) ||
      typeof config.audience !== 'string' ||
      !AUDIENCE.test(config.audience) ||
      typeof config.pinnedPublicJwksJson !== 'string' ||
      config.pinnedPublicJwksJson.length < 20 ||
      config.pinnedPublicJwksJson.length > MAX_JWKS_BYTES) invalid();

  let parsed: JsonObject | null;
  try { parsed=record(JSON.parse(config.pinnedPublicJwksJson)); }
  catch { return invalid(); }
  if (!parsed || Object.keys(parsed).join(',') !== 'keys' ||
      !Array.isArray(parsed.keys) || parsed.keys.length < 1 ||
      parsed.keys.length > MAX_KEYS) invalid();

  const publicKeys=new Map<string,CryptoKey>();
  const seenModuli=new Set<string>();
  for (const raw of parsed.keys) {
    const jwk=record(raw);
    if (!jwk || !exactJwkKeys(jwk) ||
        jwk.kty !== 'RSA' || jwk.alg !== 'RS256' ||
        jwk.use !== 'sig' || jwk.e !== 'AQAB' ||
        typeof jwk.kid !== 'string' || !KID.test(jwk.kid) ||
        publicKeys.has(jwk.kid) ||
        (jwk.key_ops !== undefined &&
         (!Array.isArray(jwk.key_ops) || jwk.key_ops.length !== 1 ||
          jwk.key_ops[0] !== 'verify')) ||
        !decodeModulus(jwk.n) ||
        seenModuli.has(jwk.n as string)) invalid();
    seenModuli.add(jwk.n as string);
    let imported: CryptoKey;
    try {
      imported=await crypto.subtle.importKey(
        'jwk',{
          kty:'RSA',n:jwk.n as string,e:'AQAB',
          alg:'RS256',use:'sig',key_ops:['verify'],ext:false,
        },
        {name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},
        false,['verify'],
      );
    } catch { return invalid(); }
    if (imported.type !== 'public' || imported.extractable ||
        imported.usages.length !== 1 ||
        imported.usages[0] !== 'verify' ||
        imported.algorithm.name !== 'RSASSA-PKCS1-v1_5' ||
        (imported.algorithm as RsaHashedKeyAlgorithm).modulusLength < 2048) {
      invalid();
    }
    publicKeys.set(jwk.kid,imported);
  }
  // The existing token verifier enforces typ:at+jwt, RS256, key ID,
  // signature, exact iss/aud, nbf/iat/exp and <=15min token lifetime.
  return createPinnedAccessTokenVerifier({
    issuer:config.issuer,audience:config.audience,publicKeys,
  });
}

/** Explicit source allowlist; caller is responsible for private server env. */
export function pinnedOidcConfigFromServerEnvironment(
  env: OperatorPinnedOidcEnvironment
): OperatorPinnedOidcAccessConfig {
  if (!env || typeof env.SAAS_OIDC_ISSUER !== 'string' ||
      typeof env.SAAS_OIDC_AUDIENCE !== 'string' ||
      typeof env.SAAS_OIDC_PINNED_PUBLIC_JWKS_JSON !== 'string') invalid();
  return Object.freeze({
    issuer:env.SAAS_OIDC_ISSUER,
    audience:env.SAAS_OIDC_AUDIENCE,
    pinnedPublicJwksJson:env.SAAS_OIDC_PINNED_PUBLIC_JWKS_JSON,
  });
}
