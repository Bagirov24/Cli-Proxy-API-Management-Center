import type { AuthorizedReadScope, ControlCollection } from '../contracts';

/**
 * Stage 2G.4d: an opt-in server-only authorization revision port.
 *
 * The source MUST be authoritative for this tenant and shared by all backend
 * instances. Every relevant tenant status, membership/role, Account, Pool and
 * Egress grant mutation MUST advance the same revision atomically with its
 * authorization write. An in-memory map is ONLY a synthetic test double.
 *
 * No revision may be supplied by the caller, JWT or HTTP headers. This guard
 * detects drift at check time; it CANNOT serialize a later HTTP response with
 * a concurrent revoke and is not a production revocation barrier.
 */
export interface ServerAuthorizationRevisionSource {
  readRevision(
    scope: Readonly<AuthorizedReadScope>,
    collection: ControlCollection,
    signal: AbortSignal
  ): Promise<unknown>;
}

declare const authorizationRevisionBrand: unique symbol;
export type ServerAuthorizationRevision = Readonly<{
  readonly value: string;
  /** Earliest future active grant expiry, conservatively floored to ms. */
  readonly notAfterMs: number | null;
  readonly [authorizationRevisionBrand]: true;
}>;

export class AuthorizationRevisionChanged extends Error {
  constructor() {
    super('Authorization revision changed');
    this.name = 'AuthorizationRevisionChanged';
  }
}

/** Current database signed gate denied; never treat it as a missing source. */
export class AuthorizationRevisionDenied extends Error {
  constructor() {
    super('Authorization revision denied');
    this.name = 'AuthorizationRevisionDenied';
  }
}

export class AuthorizationRevisionUnavailable extends Error {
  constructor() {
    super('Authorization revision unavailable');
    this.name = 'AuthorizationRevisionUnavailable';
  }
}

const REVISION_PATTERN = /^[1-9][0-9]{0,18}$/;
const MAX_INT64 = 9_223_372_036_854_775_807n;
const SAFE_ACTOR = /^[A-Za-z0-9_-]{1,128}$/;
const SAFE_TENANT = /^[A-Za-z0-9_-]{1,64}$/;

/** No SQL, revision or secrets are ever included in a public error. */
export async function captureServerAuthorizationRevision(
  source: ServerAuthorizationRevisionSource,
  scope: AuthorizedReadScope,
  collection: ControlCollection,
  signal: AbortSignal
): Promise<ServerAuthorizationRevision> {
  if (!source || typeof source.readRevision !== 'function' ||
      !scope || !SAFE_ACTOR.test(scope.actorId) ||
      !SAFE_TENANT.test(scope.tenantId) ||
      typeof scope.role !== 'string' ||
      !SAFE_ACTOR.test(scope.correlationId) ||
      (scope.tokenFingerprint !== undefined &&
        (typeof scope.tokenFingerprint !== 'string' ||
         !/^[0-9a-f]{64}$/.test(scope.tokenFingerprint))) ||
      typeof collection !== 'string' || !signal || signal.aborted) {
    throw new AuthorizationRevisionUnavailable();
  }
  try {
    // Freeze server-authenticated values across awaits: a mutable caller
    // request can never replace actor, role, collection or tenant scope.
    const trustedScope = Object.freeze({
      actorId: scope.actorId, tenantId: scope.tenantId,
      role: scope.role, correlationId: scope.correlationId,
      ...(scope.tokenFingerprint === undefined
        ? {} : { tokenFingerprint: scope.tokenFingerprint }),
    });
    const raw = await source.readRevision(trustedScope, collection, signal);
    // Legacy string sources are SYNTHETIC test doubles. The PostgreSQL
    // adapter returns BOTH epoch and next grant-expiry deadline.
    const candidate = typeof raw === 'string'
      ? { revision: raw, notAfterMs: null } : raw;
    if (signal.aborted || !candidate || typeof candidate !== 'object' ||
        Array.isArray(candidate)) throw new Error('Missing revision attestation');
    const entry = candidate as { revision?: unknown; notAfterMs?: unknown };
    const epoch = entry.revision;
    const until = entry.notAfterMs;
    // PostgreSQL BIGINT must remain canonical decimal TEXT, never Number.
    if (typeof epoch !== 'string' || !REVISION_PATTERN.test(epoch) ||
        BigInt(epoch) > MAX_INT64 ||
        (until !== null &&
          (typeof until !== 'string' || !/^[1-9][0-9]{0,15}$/.test(until) ||
           !Number.isSafeInteger(Number(until))))) {
      throw new Error('Malformed revision or expiry cutoff');
    }
    const attestation = Object.freeze({
      value: epoch, notAfterMs: until === null ? null : Number(until),
    }) as ServerAuthorizationRevision;
    if (isAuthorizationRevisionExpiredAt(attestation, Date.now())) {
      throw new AuthorizationRevisionChanged();
    }
    return attestation;
  } catch (error) {
    if (error instanceof AuthorizationRevisionDenied ||
        error instanceof AuthorizationRevisionChanged) throw error;
    // Invalid/missing/failed storage is unavailable, never an Allow.
    throw new AuthorizationRevisionUnavailable();
  }
}

export async function assertServerAuthorizationRevision(
  source: ServerAuthorizationRevisionSource,
  scope: AuthorizedReadScope,
  collection: ControlCollection,
  baseline: ServerAuthorizationRevision,
  signal: AbortSignal
): Promise<void> {
  const current = await captureServerAuthorizationRevision(
    source, scope, collection, signal
  );
  if (current.value !== baseline.value ||
      current.notAfterMs !== baseline.notAfterMs ||
      isAuthorizationRevisionExpiredAt(baseline, Date.now())) {
    throw new AuthorizationRevisionChanged();
  }
}

/** Explicit clock check after last await, without leaking expiry to caller. */
export function isAuthorizationRevisionExpiredAt(
  value: Readonly<Pick<ServerAuthorizationRevision, 'notAfterMs'>>,
  nowMs: number
): boolean {
  return value.notAfterMs !== null &&
    (!Number.isSafeInteger(nowMs) || nowMs >= value.notAfterMs);
}
