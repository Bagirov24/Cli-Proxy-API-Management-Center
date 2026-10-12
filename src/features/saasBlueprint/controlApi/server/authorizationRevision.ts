import type { AuthorizedReadScope } from '../contracts';

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
    scope: Readonly<Pick<AuthorizedReadScope, 'actorId' | 'tenantId'>>,
    signal: AbortSignal
  ): Promise<unknown>;
}

declare const authorizationRevisionBrand: unique symbol;
export type ServerAuthorizationRevision = string & {
  readonly [authorizationRevisionBrand]: true;
};

export class AuthorizationRevisionChanged extends Error {
  constructor() {
    super('Authorization revision changed');
    this.name = 'AuthorizationRevisionChanged';
  }
}

export class AuthorizationRevisionUnavailable extends Error {
  constructor() {
    super('Authorization revision unavailable');
    this.name = 'AuthorizationRevisionUnavailable';
  }
}

const REVISION_PATTERN = /^(0|[1-9][0-9]{0,18})$/;
const MAX_INT64 = 9_223_372_036_854_775_807n;
const SAFE_ACTOR = /^[A-Za-z0-9_-]{1,128}$/;
const SAFE_TENANT = /^[A-Za-z0-9_-]{1,64}$/;

/** No SQL, revision or secrets are ever included in a public error. */
export async function captureServerAuthorizationRevision(
  source: ServerAuthorizationRevisionSource,
  scope: AuthorizedReadScope,
  signal: AbortSignal
): Promise<ServerAuthorizationRevision> {
  if (!source || typeof source.readRevision !== 'function' ||
      !scope || !SAFE_ACTOR.test(scope.actorId) ||
      !SAFE_TENANT.test(scope.tenantId) || !signal || signal.aborted) {
    throw new AuthorizationRevisionUnavailable();
  }
  try {
    const revision = await source.readRevision({
      actorId: scope.actorId, tenantId: scope.tenantId,
    }, signal);
    // PostgreSQL BIGINT is represented as canonical decimal text; do not
    // round 64-bit revisions through JavaScript Number.
    if (signal.aborted || typeof revision !== 'string' ||
        !REVISION_PATTERN.test(revision) || BigInt(revision) > MAX_INT64) {
      throw new Error('Invalid revision attestation');
    }
    return revision as ServerAuthorizationRevision;
  } catch {
    // Invalid/missing/failed storage is unavailable, never an Allow.
    throw new AuthorizationRevisionUnavailable();
  }
}

export async function assertServerAuthorizationRevision(
  source: ServerAuthorizationRevisionSource,
  scope: AuthorizedReadScope,
  baseline: ServerAuthorizationRevision,
  signal: AbortSignal
): Promise<void> {
  const current = await captureServerAuthorizationRevision(source, scope, signal);
  if (current !== baseline) throw new AuthorizationRevisionChanged();
}
