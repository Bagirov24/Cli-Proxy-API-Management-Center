/**
 * 2G.4d.7b — staging-only, server-owned session provisioning contract.
 *
 * Inbound bearer: signed pinned RS256 access token verified by the injected
 * AccessTokenVerifier. No JWT jti, role, actorId or client session ID is
 * treated as database authority. The entire bearer is hashed AFTER verify.
 * An independent pinned issuer-subject directory must already be enrolled
 * in migration 011 by the separate directory-admin capability.
 *
 * This is NOT a public endpoint, production issuer, token minting service,
 * network client, or a production PostgreSQL adapter.
 */
import type {
  AccessTokenVerifier, VerifiedAccessIdentity,
} from './trustedAccessToken';

export interface VerifiedIssuerTokenBinding {
  readonly issuer: string;
  readonly subject: string;
  readonly actorId: string;
  /** SHA-256 of the FULL verified JWT, lowercase hex; never raw bearer/jti. */
  readonly fingerprint: string;
  /** Server-verifier-validated JWT exp in UNIX seconds. */
  readonly expiresAtSeconds: number;
}

/** Dedicated private writer using migration-011 function privileges only. */
export interface VerifiedIssuerSessionWriter {
  enrollVerifiedToken(input: Readonly<VerifiedIssuerTokenBinding>): Promise<boolean>;
  revokeVerifiedToken(input: Readonly<VerifiedIssuerTokenBinding>): Promise<boolean>;
}

export interface TrustedIssuerSessionProvisioningDependencies {
  readonly tokens: AccessTokenVerifier;
  readonly actorDirectory: {
    resolveActorId(identity: VerifiedAccessIdentity): Promise<string | null>;
  };
  readonly writer: VerifiedIssuerSessionWriter;
  /** CI clock injection only; production must pin one trusted time source. */
  readonly nowSeconds?: () => number;
}

const ACTOR = /^[A-Za-z0-9_-]{1,128}$/;
function verifiedIssuer(issuer: string): boolean {
  try {
    const parsed = new URL(issuer);
    return parsed.protocol === 'https:' && !!parsed.hostname &&
      !parsed.username && !parsed.password && !parsed.search && !parsed.hash &&
      issuer.length <= 256 && parsed.href === issuer;
  } catch { return false; }
}
function safeSubject(subject: string): boolean {
  return subject.length >= 1 && subject.length <= 256 &&
    !/[\x00-\x1f\x7f]/.test(subject);
}

/**
 * Both methods return only a boolean; no actor/fingerprint/token is exposed
 * to the caller, including on crypto, directory or database failure.
 *
 * A verified bearer holder can request enrollment/revocation ONLY for the
 * permanently pre-pinned issuer+subject+actor. The PG registry is the final
 * authority and rejects subject mismatch, token recycling and stale status.
 */
export function createTrustedIssuerSessionProvisioner(
  deps: TrustedIssuerSessionProvisioningDependencies
) {
  if (!deps || !deps.tokens || !deps.actorDirectory || !deps.writer ||
      typeof deps.tokens.verifyAccessToken !== 'function' ||
      typeof deps.actorDirectory.resolveActorId !== 'function' ||
      typeof deps.writer.enrollVerifiedToken !== 'function' ||
      typeof deps.writer.revokeVerifiedToken !== 'function') {
    throw new Error('Invalid trusted issuer provisioning configuration');
  }

  async function verifyAndBind(token: string): Promise<VerifiedIssuerTokenBinding | null> {
    try {
      if (typeof token !== 'string' || !token || token.length > 8192) return null;
      const verified = await deps.tokens.verifyAccessToken(token);
      if (!verified || typeof verified.issuer !== 'string' ||
          typeof verified.subject !== 'string' ||
          !verifiedIssuer(verified.issuer) || !safeSubject(verified.subject)) {
        return null;
      }
      const now = (deps.nowSeconds ?? (() => Math.floor(Date.now() / 1000)))();
      const exp = verified.expiresAtSeconds;
      if (!Number.isSafeInteger(now) || !Number.isSafeInteger(exp) ||
          exp === undefined || exp <= now || exp > now + 900) return null;

      const actorId = await deps.actorDirectory.resolveActorId(verified);
      if (!actorId || !ACTOR.test(actorId)) return null;
      const hash = new Uint8Array(await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(token)
      ));
      const fingerprint = Array.from(hash, byte =>
        byte.toString(16).padStart(2, '0')).join('');

      // Stale in-memory issuer/subject->actor mapping must not authorize a
      // changed actor across the digest await. True serialization is in PG.
      const currentActor = await deps.actorDirectory.resolveActorId(verified);
      if (currentActor !== actorId) return null;
      return Object.freeze({
        issuer: verified.issuer, subject: verified.subject,
        actorId, fingerprint, expiresAtSeconds: exp,
      });
    } catch { return null; }
  }

  return Object.freeze({
    async enrollBearer(token: string): Promise<boolean> {
      const input = await verifyAndBind(token);
      if (!input) return false;
      try {
        return await deps.writer.enrollVerifiedToken(input) === true;
      } catch { return false; }
    },
    async revokeBearer(token: string): Promise<boolean> {
      const input = await verifyAndBind(token);
      if (!input) return false;
      try {
        return await deps.writer.revokeVerifiedToken(input) === true;
      } catch { return false; }
    },
  });
}
