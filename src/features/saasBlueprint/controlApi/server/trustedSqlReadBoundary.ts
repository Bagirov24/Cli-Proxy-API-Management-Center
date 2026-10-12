import { authorizeTenantRead } from '../authorization';
import type {
  AuthorizedReadScope, ControlActor, ControlCollection,
} from '../contracts';
import {
  CONTROL_READ_SELECT_SQL, readSignedScopedMetadata,
  type ScopedSqlPool, type SignedTransactionIssuer, type SqlRow,
} from './signedSqlBoundary';
import {
  createVerifiedSubjectSessionBridge,
  type AccessTokenVerifier, type VerifiedAccessIdentity,
} from './trustedAccessToken';

/**
 * Stage 2G.2: isolated, NON-HTTP trust-boundary acceptance port.
 *
 * No OIDC discovery, production sessions, Core adapter, public listener or
 * deployment. Only server-pinned access-token keys and server-held actor data
 * may construct an AuthorizedReadScope. SQL row projection is NOT a public
 * ControlResource DTO; the existing SQL boundary allowlists its fields.
 */
export interface TrustedSqlReadDependencies {
  readonly tokens: AccessTokenVerifier;
  readonly actorDirectory: {
    resolveActorId(identity: VerifiedAccessIdentity): Promise<string | null>;
  };
  readonly actors: {
    lookup(actorId: string, signal: AbortSignal): Promise<ControlActor | null>;
  };
  readonly pool: ScopedSqlPool;
  readonly signer: SignedTransactionIssuer;
  /** Trusted backend-generated only. Never use client correlation headers. */
  readonly newCorrelationId?: () => string;
}

export interface TrustedSqlReadRequest {
  readonly accessToken: string;
  readonly tenantId: string;
  readonly collection: ControlCollection;
  readonly signal: AbortSignal;
  readonly limit?: number;
}

export type TrustedSqlReadResult =
  | {
    readonly ok: true;
    readonly status: 200;
    readonly source: 'staging-signed-rls';
    readonly correlationId: string;
    readonly tenantId: string;
    readonly collection: ControlCollection;
    readonly rows: readonly SqlRow[];
  }
  | {
    readonly ok: false;
    readonly status: 401 | 403 | 404 | 503;
    readonly correlationId: string;
    readonly error: {
      readonly code: 'UNAUTHENTICATED' | 'FORBIDDEN' | 'NOT_FOUND' | 'SOURCE_UNAVAILABLE';
      readonly message: 'Authentication required' | 'Permission denied' |
        'Resource unavailable' | 'Service unavailable';
    };
  };

const UNAUTHENTICATED = {
  ok: false, status: 401,
  error: { code: 'UNAUTHENTICATED', message: 'Authentication required' },
} as const;
const FORBIDDEN = {
  ok: false, status: 403,
  error: { code: 'FORBIDDEN', message: 'Permission denied' },
} as const;
const NOT_FOUND = {
  ok: false, status: 404,
  error: { code: 'NOT_FOUND', message: 'Resource unavailable' },
} as const;
const UNAVAILABLE = {
  ok: false, status: 503,
  error: { code: 'SOURCE_UNAVAILABLE', message: 'Service unavailable' },
} as const;

const SAFE_ACTOR = /^[A-Za-z0-9_-]{1,128}$/;
const SAFE_TENANT = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * Stale reads are denied if ANY server-held membership changes while SQL is
 * in flight. The caller must additionally abort its signal on tenant switch.
 * JWT replay within its valid lifetime is NOT prevented by this module;
 * production requires a server-side session/revocation strategy.
 */
export function createTrustedSqlReadBoundary(deps: TrustedSqlReadDependencies) {
  const sessions = createVerifiedSubjectSessionBridge(deps.tokens, deps.actorDirectory);

  return async function read(request: TrustedSqlReadRequest): Promise<TrustedSqlReadResult> {
    const correlationId = deps.newCorrelationId?.() ?? crypto.randomUUID();
    const response = (failure: typeof UNAUTHENTICATED | typeof FORBIDDEN |
      typeof NOT_FOUND | typeof UNAVAILABLE): TrustedSqlReadResult =>
      ({ ...failure, correlationId });
    try {
      // Do not accept caller-supplied actor/role or forged SQL GUC in request.
      if (!SAFE_ACTOR.test(correlationId) || !request?.signal ||
          request.signal.aborted) return response(UNAVAILABLE);
      if (typeof request.accessToken !== 'string' ||
          request.accessToken.length > 8192) return response(UNAUTHENTICATED);
      if (!SAFE_TENANT.test(request.tenantId) ||
          !Object.prototype.hasOwnProperty.call(CONTROL_READ_SELECT_SQL, request.collection) ||
          (request.limit !== undefined && (!Number.isSafeInteger(request.limit) ||
            request.limit < 1 || request.limit > 100))) return response(NOT_FOUND);

      const initialSession = await sessions.verify(request.accessToken);
      if (request.signal.aborted) return response(UNAVAILABLE);
      if (!initialSession) return response(UNAUTHENTICATED);

      const actor = await deps.actors.lookup(initialSession.actorId, request.signal);
      if (request.signal.aborted) return response(UNAVAILABLE);
      if (!actor || actor.id !== initialSession.actorId ||
          !Array.isArray(actor.memberships)) return response(UNAUTHENTICATED);

      // Snapshot before SQL: actor stores may mutate memberships in place.
      const initialMemberships = JSON.stringify(actor.memberships);
      const allowed = authorizeTenantRead(actor, request.tenantId, request.collection);
      if (!allowed.allowed) {
        return response(allowed.reason === 'not-found' ? NOT_FOUND : FORBIDDEN);
      }
      const scope: AuthorizedReadScope = {
        actorId: actor.id,
        tenantId: request.tenantId,
        role: allowed.membership.role,
        correlationId,
      };
      const rows = await readSignedScopedMetadata(deps.pool, deps.signer, {
        scope, collection: request.collection, signal: request.signal, limit: request.limit,
      });
      if (request.signal.aborted) return response(UNAVAILABLE);

      // Verify the SAME access token + issuer/subject mapping after the async
      // SQL read. Neither client-provided JWT roles nor cached memberships
      // can turn a revoked/changed authorization into a successful response.
      const currentSession = await sessions.verify(request.accessToken);
      if (request.signal.aborted) return response(UNAVAILABLE);
      if (!currentSession || currentSession.actorId !== initialSession.actorId) {
        return response(UNAUTHENTICATED);
      }
      const current = await deps.actors.lookup(currentSession.actorId, request.signal);
      if (request.signal.aborted) return response(UNAVAILABLE);
      if (!current || current.id !== scope.actorId) return response(UNAUTHENTICATED);
      if (!Array.isArray(current.memberships) ||
          JSON.stringify(current.memberships) !== initialMemberships) {
        return response(NOT_FOUND);
      }
      const again = authorizeTenantRead(current, request.tenantId, request.collection);
      if (!again.allowed || again.membership.role !== scope.role) {
        return response(NOT_FOUND);
      }
      return {
        ok: true, status: 200, source: 'staging-signed-rls', correlationId,
        tenantId: scope.tenantId, collection: request.collection, rows,
      };
    } catch {
      // Never echo SQL, JWT, actor directory errors or secret-bearing rows.
      return response(UNAVAILABLE);
    }
  };
}
