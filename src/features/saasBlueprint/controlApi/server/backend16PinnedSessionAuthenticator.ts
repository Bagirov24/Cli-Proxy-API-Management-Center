/**
 * Backend16.2: pinned access JWT -> operator-enrolled subject -> live session
 * lookup. No HTTP listener, credentials, migration, SQL driver or fallback.
 *
 * A trust-verified subject fingerprint is NOT tenant authorization. The
 * injected authority must read durable, current operator enrollment and
 * bearer-bound session state from an independently reviewed private source.
 * The subsequent readAuthorized port must REVALIDATE PG session_user,
 * tenant ACL/revision, session, subject binding and FORCE RLS on one physical
 * per-principal login in a read-only transaction; no SET ROLE impersonation.
 */
import {
  createOperatorPinnedOidcAccessVerifier,
  type OperatorPinnedOidcAccessConfig,
} from './operatorPinnedOidcAccessVerifier';
import {createOperatorVerifiedSubjectFingerprintGate}
  from './verifiedSubjectBinding';
import type {Backend16PrivateReadPorts, VerifiedPrincipal}
  from './backend16PrivateTenantProjectRead';

const SHA256 = /^[a-f0-9]{64}$/;
const LOGIN = /^[a-z][a-z0-9_]{2,62}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const JWT = /^[A-Za-z0-9_-]{1,2048}\.[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,2048}$/;
const FORBIDDEN_LOGINS = new Set([
  'postgres','saas_schema_migrator','saas_runtime_reader','saas_runtime_writer',
]);
const MAX_SESSION_MS = 15 * 60_000;
const encoder = new TextEncoder();

export interface Backend16PinnedSessionLookupKey {
  /** Exact operator-pinned HTTPS token issuer. */
  readonly issuer: string;
  /** Digest of verified (issuer, subject), NOT proof of an active DB grant. */
  readonly subjectFingerprintSha256: string;
  /** SHA256 of the exact, cryptographically verified raw bearer JWT. */
  readonly tokenFingerprintSha256: string;
  /** Maximum token validity as a verified integer UNIX timestamp. */
  readonly tokenExpiresAtSeconds: number;
}

/**
 * Operator-owned session snapshot. This shape is NOT an attestation by itself.
 * Resolve only against the private CURRENT enrollment/session authority, never
 * user claims, JWT tenant_id/roles, stale cache, or a synthetic fixture.
 */
export interface Backend16CurrentSessionSnapshot {
  readonly issuer: string;
  readonly subjectFingerprintSha256: string;
  readonly tokenFingerprintSha256: string;
  readonly pgLogin: string;
  readonly sessionId: string;
  readonly bindingId: string;
  readonly sessionExpiresAtMs: number;
}

export interface Backend16AuthoritativeSessionLookup {
  resolveCurrent(
    key: Backend16PinnedSessionLookupKey,
    signal: AbortSignal,
  ): Promise<Backend16CurrentSessionSnapshot | null>;
}

export interface Backend16PinnedSessionOptions {
  readonly oidc: OperatorPinnedOidcAccessConfig;
  readonly sessionAuthority: Backend16AuthoritativeSessionLookup;
  /** Server-controlled clock. Tests may supply a deterministic value. */
  readonly nowMs?: () => number;
}

function positiveNow(now: unknown): now is number {
  return typeof now === 'number' && Number.isSafeInteger(now) && now > 0;
}
function currentSession(
  snapshot: Backend16CurrentSessionSnapshot | null,
  key: Backend16PinnedSessionLookupKey,
  now: number,
): snapshot is Backend16CurrentSessionSnapshot {
  if (!snapshot || !positiveNow(now) || snapshot.issuer !== key.issuer ||
      snapshot.subjectFingerprintSha256 !== key.subjectFingerprintSha256 ||
      snapshot.tokenFingerprintSha256 !== key.tokenFingerprintSha256 ||
      !SHA256.test(snapshot.subjectFingerprintSha256) ||
      !SHA256.test(snapshot.tokenFingerprintSha256) ||
      typeof snapshot.pgLogin !== 'string' || !LOGIN.test(snapshot.pgLogin) ||
      FORBIDDEN_LOGINS.has(snapshot.pgLogin) ||
      typeof snapshot.sessionId !== 'string' || !UUID.test(snapshot.sessionId) ||
      typeof snapshot.bindingId !== 'string' || !UUID.test(snapshot.bindingId) ||
      !Number.isSafeInteger(snapshot.sessionExpiresAtMs) ||
      snapshot.sessionExpiresAtMs <= now ||
      snapshot.sessionExpiresAtMs > now + MAX_SESSION_MS) return false;
  return true;
}

async function sha256(value: string): Promise<string> {
  const bytes = new Uint8Array(await crypto.subtle.digest(
    'SHA-256', encoder.encode(value),
  ));
  return Array.from(bytes, b => b.toString(16).padStart(2,'0')).join('');
}

/**
 * Fail-closed startup and authentication port only. Nothing is mounted.
 * No raw bearer is handed to the database/session source, logged, retained
 * in principal output or decoded to select actor/tenant/PG LOGIN.
 */
export async function createBackend16PinnedSessionAuthenticator(
  options: Backend16PinnedSessionOptions,
): Promise<Backend16PrivateReadPorts['authenticate']> {
  if (!options || !options.sessionAuthority ||
      typeof options.sessionAuthority.resolveCurrent !== 'function' ||
      (options.nowMs !== undefined && typeof options.nowMs !== 'function')) {
    throw new Error('Backend16 server session authority unavailable');
  }
  // The pinned-JWKS verifier fails startup for absent, malformed or unapproved
  // RSA trust. Never replace this with a token decoder or dynamic JWKS fetch.
  const verifier = await createOperatorPinnedOidcAccessVerifier(options.oidc);
  const fingerprint = createOperatorVerifiedSubjectFingerprintGate(verifier,
    () => Math.floor((options.nowMs ?? Date.now)() / 1000));
  const nowMs = options.nowMs ?? Date.now;
  const issuer = options.oidc.issuer;
  const authority = options.sessionAuthority;

  return async function authenticate(
    rawBearer: string, signal: AbortSignal,
  ): Promise<VerifiedPrincipal | null> {
    try {
      if (!signal || signal.aborted || typeof rawBearer !== 'string' ||
          rawBearer.length > 6144 || !JWT.test(rawBearer)) return null;
      const verified = await fingerprint.verify(rawBearer);
      if (!verified || signal.aborted) return null;
      const tokenExpiresAtMs = verified.expiresAtSeconds * 1000;
      const before = nowMs();
      if (!positiveNow(before) || !Number.isSafeInteger(tokenExpiresAtMs) ||
          tokenExpiresAtMs <= before ||
          tokenExpiresAtMs > before + MAX_SESSION_MS) return null;
      const tokenFingerprintSha256 = await sha256(rawBearer);
      if (signal.aborted) return null;
      const lookupKey: Backend16PinnedSessionLookupKey = Object.freeze({
        issuer,
        subjectFingerprintSha256: verified.fingerprint,
        tokenFingerprintSha256,
        tokenExpiresAtSeconds: verified.expiresAtSeconds,
      });
      const snapshot = await authority.resolveCurrent(lookupKey, signal);
      const after = nowMs();
      if (signal.aborted || !currentSession(snapshot, lookupKey, after) ||
          tokenExpiresAtMs <= after) return null;
      // Never extend a PostgreSQL session beyond the lifetime of its bearer.
      const expires = Math.min(snapshot.sessionExpiresAtMs,tokenExpiresAtMs);
      if (expires <= after) return null;
      return Object.freeze({
        kind: 'verified-server-session',
        issuer,
        subjectFingerprintSha256: verified.fingerprint,
        pgLogin: snapshot.pgLogin,
        sessionId: snapshot.sessionId,
        bindingId: snapshot.bindingId,
        sessionExpiresAtMs: expires,
      });
    } catch {
      // No token, DB identity, key material, subject or SQL diagnostics.
      // No retry on failed/unknown session lookup.
      return null;
    }
  };
}
