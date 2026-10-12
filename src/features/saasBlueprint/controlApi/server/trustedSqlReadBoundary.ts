import { authorizeTenantRead } from '../authorization';
import {
  assertServerAuthorizationRevision, captureServerAuthorizationRevision,
  AuthorizationRevisionChanged, AuthorizationRevisionDenied,
  type ServerAuthorizationRevisionSource,
} from './authorizationRevision';
import type { SecurityAuditReason, SecurityAuditRecorder } from './securityAudit';
import type {
  AuthorizedReadScope, ControlActor, ControlCollection,
} from '../contracts';
import {
  CONTROL_READ_SELECT_SQL, readSignedScopedMetadata,
  ScopedSqlAuthorizationDenied,
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
  /**
   * Opt-in 2G.4d staging port. Omission preserves the historical 2G.4c
   * behavior; production MUST NOT treat omission as revision enforcement.
   */
  readonly revisions?: ServerAuthorizationRevisionSource;
  /** Mandatory test/staging audit port; a failed write denies the response. */
  readonly audit: SecurityAuditRecorder;
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
    let trustedActorId: string | null = null;
    let trustedTenantId: string | null = null;
    let collection: ControlCollection | null = null;

    const finish = (
      result: TrustedSqlReadResult, reason: SecurityAuditReason
    ): TrustedSqlReadResult => {
      // Synchronous only: no new await between final RBAC and returning
      // metadata. The sink never receives any JWT, SQL or raw request body.
      try {
        deps.audit.record({
          correlationId, actorId: trustedActorId,
          tenantId: result.ok ? trustedTenantId : null,
          collection, result: result.ok ? 'allow' :
            result.status === 503 ? 'error' : 'deny', reason,
        });
        return result;
      } catch {
        // A failed audit write must not become an unauthorized success.
        // Already read SQL rows are discarded and diagnostic text is hidden.
        return response(UNAVAILABLE);
      }
    };

    try {
      // Do not accept caller-supplied actor/role or forged SQL GUC in request.
      if (!SAFE_ACTOR.test(correlationId) || !request?.signal ||
          request.signal.aborted) {
        return finish(response(UNAVAILABLE), 'request-cancelled');
      }
      if (typeof request.accessToken !== 'string' ||
          request.accessToken.length > 8192) {
        return finish(response(UNAUTHENTICATED), 'unauthenticated');
      }
      if (!SAFE_TENANT.test(request.tenantId) ||
          !Object.prototype.hasOwnProperty.call(CONTROL_READ_SELECT_SQL, request.collection) ||
          (request.limit !== undefined && (!Number.isSafeInteger(request.limit) ||
            request.limit < 1 || request.limit > 100))) {
        return finish(response(NOT_FOUND), 'invalid-request');
      }
      // Freeze values at the trusted boundary. A request object with mutable
      // properties cannot switch collection/tenant/limit across awaits.
      const requestedCollection = request.collection;
      const requestedTenant = request.tenantId;
      const requestedLimit = request.limit;
      const signal = request.signal;
      const accessToken = request.accessToken;
      collection = requestedCollection;

      const initialSession = await sessions.verify(accessToken);
      if (signal.aborted) return finish(response(UNAVAILABLE), 'request-cancelled');
      if (!initialSession) return finish(response(UNAUTHENTICATED), 'unauthenticated');

      const actor = await deps.actors.lookup(initialSession.actorId, signal);
      if (signal.aborted) return finish(response(UNAVAILABLE), 'request-cancelled');
      if (!actor || actor.id !== initialSession.actorId ||
          !Array.isArray(actor.memberships)) {
        return finish(response(UNAUTHENTICATED), 'unauthenticated');
      }
      trustedActorId = actor.id;
      // Snapshot before SQL: actor stores may mutate memberships in place.
      const originalMemberships = JSON.stringify(actor.memberships);
      const allowed = authorizeTenantRead(actor, requestedTenant, requestedCollection);
      if (!allowed.allowed) {
        return finish(response(allowed.reason === 'not-found' ? NOT_FOUND : FORBIDDEN),
          allowed.reason === 'not-found' ? 'tenant-hidden' : 'role-forbidden');
      }
      trustedTenantId = requestedTenant;
      const scope: AuthorizedReadScope = {
        actorId: actor.id,
        tenantId: requestedTenant,
        role: allowed.membership.role,
        correlationId,
      };
      // Server-owned revision is captured only AFTER trusted identity/RBAC.
      // No user-provided revision participates in authorization.
      const revisionSource = deps.revisions;
      const initialRevision = revisionSource
        ? await captureServerAuthorizationRevision(
          revisionSource, scope, requestedCollection, signal
        )
        : null;
      if (signal.aborted) return finish(response(UNAVAILABLE), 'request-cancelled');

      const rows = await readSignedScopedMetadata(deps.pool, deps.signer, {
        scope, collection: requestedCollection, signal, limit: requestedLimit,
      });
      if (signal.aborted) return finish(response(UNAVAILABLE), 'request-cancelled');

      // Stage 2G.4c: a separate signed transaction checks CURRENT PG RLS,
      // membership/tenant state AND the same independently granted resources
      // after the first COMMIT. Drift => deny, never return the old rows.
      // This is deliberately NOT an atomic revocation guarantee after the
      // final verification; a revision/serialization protocol is still SPEC.
      const refreshedRows = await readSignedScopedMetadata(deps.pool, deps.signer, {
        scope, collection: requestedCollection, signal, limit: requestedLimit,
      });
      if (signal.aborted) return finish(response(UNAVAILABLE), 'request-cancelled');
      if (JSON.stringify(refreshedRows) !== JSON.stringify(rows)) {
        return finish(response(NOT_FOUND), 'authorization-changed');
      }

      // Verify the SAME access token + issuer/subject mapping after the async
      // SQL read; revoked/changed rights must not produce stale responses.
      const currentSession = await sessions.verify(accessToken);
      if (signal.aborted) return finish(response(UNAVAILABLE), 'request-cancelled');
      if (!currentSession || currentSession.actorId !== initialSession.actorId) {
        return finish(response(UNAUTHENTICATED), 'unauthenticated');
      }
      const current = await deps.actors.lookup(currentSession.actorId, signal);
      if (signal.aborted) return finish(response(UNAVAILABLE), 'request-cancelled');
      if (!current || current.id !== scope.actorId) {
        return finish(response(UNAUTHENTICATED), 'unauthenticated');
      }
      if (!Array.isArray(current.memberships) ||
          JSON.stringify(current.memberships) !== originalMemberships) {
        return finish(response(NOT_FOUND), 'authorization-changed');
      }
      const again = authorizeTenantRead(current, requestedTenant, requestedCollection);
      if (!again.allowed || again.membership.role !== scope.role) {
        return finish(response(NOT_FOUND), 'authorization-changed');
      }
      // Final server-only check after the second SQL COMMIT AND trusted
      // token/actor/RBAC revalidation. Drift denies even if LIMIT masks a
      // grant change from both row-set comparisons. No third metadata SELECT.
      // Another revoke can still commit after this check: NOT linearizable.
      if (revisionSource && initialRevision !== null) {
        await assertServerAuthorizationRevision(
          revisionSource, scope, requestedCollection, initialRevision, signal
        );
        if (signal.aborted) return finish(response(UNAVAILABLE), 'request-cancelled');
      }
      return finish({
        ok: true, status: 200, source: 'staging-signed-rls', correlationId,
        tenantId: scope.tenantId, collection: requestedCollection, rows,
      }, 'read-allowed');
    } catch (error) {
      if (request?.signal?.aborted) {
        return finish(response(UNAVAILABLE), 'request-cancelled');
      }
      // The signed PG gate may deny a tenant/membership that the in-memory
      // actor store still believes active. Hide its existence as generic 404.
      if (error instanceof AuthorizationRevisionChanged ||
          error instanceof AuthorizationRevisionDenied) {
        return finish(response(NOT_FOUND), 'authorization-changed');
      }
      if (error instanceof ScopedSqlAuthorizationDenied) {
        return finish(response(NOT_FOUND), 'authorization-changed');
      }
      // No SQL/driver, JWT, identity directory or sink details escape.
      return finish(response(UNAVAILABLE), 'source-unavailable');
    }
  };
}
