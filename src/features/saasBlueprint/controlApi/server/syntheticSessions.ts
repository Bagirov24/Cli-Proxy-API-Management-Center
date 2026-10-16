/**
 * TEST/STAGING-ONLY opaque session registry. Not an OIDC provider or
 * production session store. Tokens are random, expire and can be revoked.
 * Only trusted server/test code can call issue(); there is no login endpoint.
 */
export interface VerifiedSyntheticSession {
  readonly actorId: string;
}

const TOKEN_PREFIX = 'sbv1_';
const TOKEN_FORMAT = /^sbv1_[A-Za-z0-9_-]{43}$/;
const MAX_TTL_MS = 15 * 60_000;

function encodeBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/** Store only a one-way hash of bearer values, never raw tokens. */
async function tokenHash(token: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

interface StoredSession {
  readonly actorId: string;
  readonly expiresAtMs: number;
}

export class SyntheticSessionRegistry {
  private readonly sessions = new Map<string, StoredSession>();

  constructor(private readonly nowMs: () => number = () => Date.now()) {}

  /** Called ONLY by trusted local fixture bootstrap, never by HTTP routes. */
  async issue(actorId: string, ttlMs = 5 * 60_000): Promise<string> {
    const now = this.nowMs();
    if (!/^[a-zA-Z0-9_-]{1,128}$/.test(actorId) ||
        !Number.isFinite(now) ||
        !Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > MAX_TTL_MS) {
      throw new Error('Invalid synthetic session parameters');
    }
    const random = crypto.getRandomValues(new Uint8Array(32));
    const token = TOKEN_PREFIX + encodeBase64Url(random);
    this.sessions.set(await tokenHash(token), { actorId, expiresAtMs: now + ttlMs });
    return token;
  }

  /** Checks cryptographically random opaque token against server-held state. */
  async verify(token: string): Promise<VerifiedSyntheticSession | null> {
    if (!TOKEN_FORMAT.test(token)) return null;
    const record = this.sessions.get(await tokenHash(token));
    const now = this.nowMs();
    if (!record || !Number.isFinite(now)) return null;
    if (now >= record.expiresAtMs) {
      this.sessions.delete(await tokenHash(token));
      return null;
    }
    return { actorId: record.actorId };
  }

  async revoke(token: string): Promise<void> {
    if (TOKEN_FORMAT.test(token)) this.sessions.delete(await tokenHash(token));
  }
}
