/**
 * Stage 2E / STAGING CONTRACT: pinned RS256 JWT access-token verifier.
 *
 * Requires a trusted access-token issuer and pre-provisioned public keys.
 * No OIDC discovery, dynamic JWKS fetch, cookies, login, or production keys.
 * NEVER accept ID tokens as API bearer tokens; typ must be "at+jwt".
 */
export interface VerifiedAccessIdentity {
  readonly issuer: string;
  readonly subject: string;
}

export interface AccessTokenVerifier {
  verifyAccessToken(token: string): Promise<VerifiedAccessIdentity | null>;
}

export interface PinnedAccessTokenOptions {
  readonly issuer: string;
  readonly audience: string;
  readonly publicKeys: ReadonlyMap<string, CryptoKey>;
  readonly nowSeconds?: () => number;
}

const BASE64URL = /^[A-Za-z0-9_-]+$/;
function safeSubject(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 1 || value.length > 256) return false;
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i);
    if (c < 32 || c === 127) return false;
  }
  return true;
}
const MAX_TOKEN_LENGTH = 8192;
const MAX_LIFETIME_SECONDS = 900;
const MAX_IAT_SKEW_SECONDS = 30;

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function decode(segment: string): Uint8Array | null {
  if (!BASE64URL.test(segment) || segment.length > MAX_TOKEN_LENGTH) return null;
  try {
    const raw = atob(segment.replace(/-/g, '+').replace(/_/g, '/') +
      '='.repeat((4 - segment.length % 4) % 4));
    return Uint8Array.from(raw, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

function json(segment: string): Record<string, unknown> | null {
  const bytes = decode(segment);
  if (!bytes || bytes.byteLength > 4096) return null;
  try {
    return object(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
  } catch {
    return null;
  }
}

function int(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value);
}

export function createPinnedAccessTokenVerifier(
  opts: PinnedAccessTokenOptions
): AccessTokenVerifier {
  const url = new URL(opts.issuer);
  if (url.protocol !== 'https:' || url.username || url.password || url.search ||
      url.hash || !opts.audience || opts.audience.length > 256 ||
      opts.publicKeys.size === 0) {
    throw new Error('Invalid pinned issuer / audience / public-key configuration');
  }
  const keys = new Map(opts.publicKeys);
  for (const [kid, key] of keys) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(kid) || key.type !== 'public' ||
        key.algorithm.name !== 'RSASSA-PKCS1-v1_5' ||
        !key.usages.includes('verify') ||
        (key.algorithm as RsaHashedKeyAlgorithm).hash.name !== 'SHA-256' ||
        (key.algorithm as RsaHashedKeyAlgorithm).modulusLength < 2048) {
      throw new Error('Only pinned RSA public verify keys are permitted');
    }
  }

  return {
    async verifyAccessToken(token) {
      if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH) return null;
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      const [encodedHeader, encodedClaims, encodedSignature] = parts;
      const header = json(encodedHeader);
      if (!header || header.alg !== 'RS256' || header.typ !== 'at+jwt' ||
          typeof header.kid !== 'string' || !keys.has(header.kid) ||
          'jwk' in header || 'jku' in header || 'x5u' in header ||
          'x5c' in header || 'crit' in header || 'b64' in header) return null;
      const claims = json(encodedClaims);
      const signature = decode(encodedSignature);
      if (!claims || !signature || signature.byteLength < 128 ||
          signature.byteLength > 512) return null;
      const key = keys.get(header.kid)!;
      let verified: boolean;
      try {
        verified = await crypto.subtle.verify(
          'RSASSA-PKCS1-v1_5', key, Uint8Array.from(signature),
          new TextEncoder().encode(encodedHeader + '.' + encodedClaims)
        );
      } catch {
        return null;
      }
      if (!verified) return null;

      const now = (opts.nowSeconds ?? (() => Math.floor(Date.now() / 1000)))();
      if (!int(now) || !int(claims.exp) || !int(claims.iat) ||
          !safeSubject(claims.sub) ||
          claims.iss !== opts.issuer || claims.exp <= now ||
          claims.iat > now + MAX_IAT_SKEW_SECONDS ||
          claims.exp <= claims.iat ||
          claims.exp - claims.iat > MAX_LIFETIME_SECONDS ||
          (claims.nbf !== undefined && (!int(claims.nbf) || claims.nbf > now))) {
        return null;
      }

      const aud = claims.aud;
      const hasAudience = aud === opts.audience ||
        (Array.isArray(aud) && aud.length >= 1 && aud.length <= 8 &&
          aud.every((item): item is string => typeof item === 'string') &&
          aud.includes(opts.audience) && claims.azp === opts.audience);
      if (!hasAudience) return null;
      return { issuer: opts.issuer, subject: claims.sub as string };
    },
  };
}

/**
 * Bridge a verified identity to the existing server-side actor directory.
 * The access token NEVER supplies actor IDs, memberships or roles.
 */
export function createVerifiedSubjectSessionBridge(
  verifier: AccessTokenVerifier,
  directory: {
    resolveActorId(identity: VerifiedAccessIdentity): Promise<string | null>;
  }
): { verify(token: string): Promise<{ readonly actorId: string } | null> } {
  return {
    async verify(token) {
      const identity = await verifier.verifyAccessToken(token);
      if (!identity) return null;
      const actorId = await directory.resolveActorId(identity);
      return actorId && /^[A-Za-z0-9_-]{1,128}$/.test(actorId)
        ? { actorId } : null;
    },
  };
}
