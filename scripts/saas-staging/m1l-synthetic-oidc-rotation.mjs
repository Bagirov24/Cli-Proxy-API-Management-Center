/**
 * M1l synthetic OIDC metadata/JWKS rotation, DISPOSABLE GITHUB CI ONLY.
 *
 * Real bounded loopback HTTP GET + pinned HTTPS issuer string, immutable RSA
 * key identity per kid, monotone local snapshot revision, no stale-key
 * fallback after an invalid refresh. This is NOT discovery over production
 * HTTPS, SSO login, refresh-token issuance, ID token acceptance, global IAM,
 * external durable key pin, or a general-purpose network fetcher.
 */
import { createPinnedAccessTokenVerifier } from
  '../../src/features/saasBlueprint/controlApi/server/trustedAccessToken.ts';

const B64URL = /^[A-Za-z0-9_-]+$/;
const KID = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_JSON_BYTES = 16 * 1024;
const MAX_KEYS = 3;

function ciOnly() {
  return process.env.GITHUB_ACTIONS === 'true' &&
    process.env.SAAS_EPHEMERAL_M1L_OIDC_CI === 'true' &&
    process.env.NODE_ENV !== 'production' &&
    !process.env.RAILWAY_PROJECT_ID &&
    !process.env.RAILWAY_ENVIRONMENT &&
    !process.env.RAILWAY_SERVICE_ID;
}
function exactKeys(input, expected) {
  return input && typeof input === 'object' &&
    !Array.isArray(input) &&
    Object.keys(input).sort().join(',') === expected;
}
function pinnedLoopbackUrl(value, pathname) {
  const uri = new URL(value);
  if (uri.protocol !== 'http:' ||
      uri.hostname !== '127.0.0.1' ||
      !/^[1-9][0-9]{0,4}$/.test(uri.port) ||
      Number(uri.port) > 65535 ||
      uri.username || uri.password || uri.search || uri.hash ||
      uri.pathname !== pathname) {
    throw new Error('M1l synthetic metadata/JWKS URL must be exact loopback');
  }
  return uri.href;
}
async function boundedJson(url) {
  const response = await fetch(url, {
    method: 'GET', redirect: 'error', cache: 'no-store',
    credentials: 'omit', headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(4000),
  });
  if (!response.ok || response.redirected ||
      !/^application\/json(?:;\s*charset=utf-8)?$/i.test(
        response.headers.get('content-type') || '')) {
    throw new Error('M1l synthetic OIDC document rejected');
  }
  const claimedSize = response.headers.get('content-length');
  if (claimedSize &&
      (!/^(0|[1-9][0-9]{0,5})$/.test(claimedSize) ||
        Number(claimedSize) > MAX_JSON_BYTES)) {
    throw new Error('M1l oversized synthetic OIDC response');
  }
  if (!response.body) throw new Error('M1l OIDC body absent');
  const reader = response.body.getReader();
  const bytes = new Uint8Array(MAX_JSON_BYTES);
  let size = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      if (chunk.value.byteLength > MAX_JSON_BYTES - size) {
        await reader.cancel();
        throw new Error('M1l OIDC response exceeds bound');
      }
      bytes.set(chunk.value, size);
      size += chunk.value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  if (!size) throw new Error('M1l OIDC empty document');
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true })
      .decode(bytes.subarray(0, size)));
  } catch {
    throw new Error('M1l invalid JSON document');
  }
}

/**
 * This deliberately accepts only tiny CI fixture JSON shapes. No URL can be
 * derived from an untrusted JWT header or an untrusted discovery response.
 */
export function createSyntheticOidcKeyRotation({
  issuer, audience, discoveryUrl, jwksUrl, nowSeconds,
}) {
  if (!ciOnly() ||
      typeof issuer !== 'string' || typeof audience !== 'string' ||
      !issuer.startsWith('https://') ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(audience) ||
      typeof nowSeconds !== 'function') {
    throw new Error('M1l synthetic key rotation denied outside opt-in CI');
  }
  const discovery = pinnedLoopbackUrl(
    discoveryUrl, '/.well-known/openid-configuration');
  const jwks = pinnedLoopbackUrl(jwksUrl, '/jwks');
  if (new URL(discovery).origin !== new URL(jwks).origin) {
    throw new Error('M1l synthetic OIDC endpoints must share pinned loopback');
  }
  // A HTTPS issuer is only a pinned STRING; no authority is inferred from
  // synthetic loopback metadata. This is NOT real TLS issuer validation.
  const parsedIssuer = new URL(issuer);
  if (parsedIssuer.protocol !== 'https:' || parsedIssuer.username ||
      parsedIssuer.password || parsedIssuer.hash || parsedIssuer.search) {
    throw new Error('M1l synthetic issuer must be pinned HTTPS');
  }

  let active = null;
  let highestRevision = 0;
  const history = new Map();
  const retired = new Set();
  let priorIds = new Set();
  let quarantined = false;

  return Object.freeze({
    async reload(revision) {
      if (!ciOnly()) throw new Error('M1l OIDC disabled by CI guard');
      try {
        if (!Number.isSafeInteger(revision) || revision < 1 ||
            revision <= highestRevision) {
          throw new Error('M1l non-monotone issuer keyset epoch');
        }
        const metadata = await boundedJson(discovery);
        if (!exactKeys(metadata,
            'id_token_signing_alg_values_supported,issuer,jwks_uri') ||
            metadata.issuer !== issuer || metadata.jwks_uri !== jwks ||
            !Array.isArray(metadata.id_token_signing_alg_values_supported) ||
            metadata.id_token_signing_alg_values_supported.length !== 1 ||
            metadata.id_token_signing_alg_values_supported[0] !== 'RS256') {
          throw new Error('M1l discovery issuer/JWKS binding mismatch');
        }
        const document = await boundedJson(jwks);
        if (!exactKeys(document, 'keys') ||
            !Array.isArray(document.keys) ||
            document.keys.length < 1 || document.keys.length > MAX_KEYS) {
          throw new Error('M1l synthetic JWKS key count invalid');
        }
        const publicKeys = new Map();
        const finger = new Map();
        for (const item of document.keys) {
          if (!exactKeys(item, 'alg,e,key_ops,kid,kty,n,use') ||
              item.alg !== 'RS256' || item.kty !== 'RSA' ||
              item.use !== 'sig' || item.e !== 'AQAB' ||
              !Array.isArray(item.key_ops) || item.key_ops.length !== 1 ||
              item.key_ops[0] !== 'verify' ||
              typeof item.kid !== 'string' || !KID.test(item.kid) ||
              typeof item.n !== 'string' ||
              item.n.length < 342 || item.n.length > 684 ||
              !B64URL.test(item.n) ||
              publicKeys.has(item.kid) || retired.has(item.kid)) {
            throw new Error('M1l malformed/retired/duplicate JWKS key');
          }
          const fingerprint = item.n + '.' + item.e;
          if (history.has(item.kid) &&
              history.get(item.kid) !== fingerprint) {
            throw new Error('M1l kid reused for different signing key');
          }
          const key = await crypto.subtle.importKey('jwk', item,
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            false, ['verify']);
          if (key.algorithm.name !== 'RSASSA-PKCS1-v1_5' ||
              key.algorithm.modulusLength < 2048 ||
              key.algorithm.modulusLength > 4096) {
            throw new Error('M1l RSA modulus outside CI policy');
          }
          finger.set(item.kid, fingerprint);
          publicKeys.set(item.kid, key);
        }
        const verifier = createPinnedAccessTokenVerifier({
          issuer, audience, publicKeys, nowSeconds,
        });
        // All validation/imports occur BEFORE publishing the new atomic
        // snapshot. Old keys removed from an accepted snapshot cannot
        // return; an invalid refresh quarantines *all* token verification.
        for (const old of priorIds) {
          if (!publicKeys.has(old)) retired.add(old);
        }
        for (const [kid, value] of finger) history.set(kid, value);
        priorIds = new Set(publicKeys.keys());
        highestRevision = revision;
        active = Object.freeze({ revision, verifier });
        quarantined = false;
        return Object.freeze({ revision, keyIds: [...publicKeys.keys()].sort() });
      } catch {
        active = null;
        quarantined = true;
        throw new Error('M1l synthetic OIDC refresh denied; tokens quarantined');
      }
    },
    async verifyAccessToken(token) {
      if (!ciOnly() || quarantined || !active) return null;
      const snapshot = active;
      const identity = await snapshot.verifier.verifyAccessToken(token);
      // Catch a key rotation that landed during crypto verification.
      return !quarantined && active === snapshot ? identity : null;
    },
    status() {
      return Object.freeze({
        enabled: ciOnly() && !quarantined && !!active,
        revision: active?.revision ?? null,
        quarantined,
      });
    },
  });
}
