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
  withSignedScopedPublicationBarrier, ScopedSqlAuthorizationDenied,
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
  /** Only explicit staging PG16 opt-in: migration 009 signed audit outbox. */
  readonly recordStagingOutbox?: boolean;
  /** Strict opt-in to PG16 015; arbitrary operation UUID never authenticates. */
  readonly recordStagingProducerOperation?: boolean;
  /** 016 issuer/recovery mode is never enabled on ordinary reads/HTTP. */
  readonly recordStagingOperationMode?: 'issue' | 'reserved_commit' | 'status';
  /**
   * Stage 2G.4d.7a: STRICT opt-in for migration-010 fingerprint-enrolled
   * synthetic sessions. No implicit fallback to actor-only PG scope.
   * Requires the server-owned revision source for time-only expiry.
   */
  readonly requireTokenBoundSession?: boolean;
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
  /** Stable UUIDv4 identifier only consumed by the separate 015 staging mode. */
  readonly producerOperationId?: string;
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
    readonly operationState?: 'issued' | 'committed' | 'expired';
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

/** Only a server-injected local sink, not a request/HTTP route handler. */
export interface TrustedLocalPublicationPayload {
  readonly correlationId: string;
  readonly tenantId: string;
  readonly collection: ControlCollection;
  readonly rows: readonly SqlRow[];
}
export interface TrustedLocalPublicationSink {
  /** PRIVATE stage only; must not emit bytes until returned sync commit. */
  stage(
    payload: Readonly<TrustedLocalPublicationPayload>,
    signal: AbortSignal
  ): Promise<() => void>;
}

export type TrustedSqlPublishedResult =
  | Exclude<TrustedSqlReadResult, { readonly ok: true }>
  | {
    readonly ok: true;
    readonly status: 200;
    readonly correlationId: string;
    readonly source: 'staging-local-publication';
    readonly published: true;
    readonly operationState?: 'issued' | 'committed' | 'expired';
  };

const SAFE_ACTOR = /^[A-Za-z0-9_-]{1,128}$/;
const SAFE_TENANT = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * Stale reads are denied if ANY server-held membership changes while SQL is
 * in flight. The caller must additionally abort its signal on tenant switch.
 * JWT replay within its valid lifetime is NOT prevented by this module;
 * production requires a server-side session/revocation strategy.
 */
function createTrustedSqlReadBoundaryEngine(
  deps: TrustedSqlReadDependencies,
  publisher?: TrustedLocalPublicationSink
) {
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
      const requestedOperation = request.producerOperationId;
      if (publisher && (deps.recordStagingProducerOperation === true ||
          deps.recordStagingOperationMode !== undefined) &&
          (typeof requestedOperation !== 'string' ||
           !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
             requestedOperation))) {
        return finish(response(NOT_FOUND), 'invalid-request');
      }
      const signal = request.signal;
      const accessToken = request.accessToken;
      collection = requestedCollection;

      const initialSession = await sessions.verify(accessToken);
      if (signal.aborted) return finish(response(UNAVAILABLE), 'request-cancelled');
      if (!initialSession) return finish(response(UNAUTHENTICATED), 'unauthenticated');
      if (deps.requireTokenBoundSession === true && !deps.revisions) {
        return finish(response(UNAVAILABLE), 'source-unavailable');
      }
      // Exact verified bearer fingerprint, NOT the untrusted JWT "jti"
      // claim or a caller-provided session handle. It is only ever signed
      // into PostgreSQL's private transaction scope, never returned.
      const tokenFingerprint = deps.requireTokenBoundSession === true
        ? Array.from(
          new Uint8Array(await crypto.subtle.digest(
            'SHA-256', new TextEncoder().encode(accessToken)
          )), (byte) => byte.toString(16).padStart(2, '0')
        ).join('')
        : undefined;
      if (signal.aborted) return finish(response(UNAVAILABLE), 'request-cancelled');

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
        ...(tokenFingerprint === undefined ? {} : { tokenFingerprint }),
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
      if (publisher) {
        // This special entrypoint never returns SQL rows to its caller.
        // A committed PostgreSQL writer changes epoch; the original
        // pre-read baseline must still match UNDER a FOR SHARE lease.
        if (!revisionSource || initialRevision === null) {
          return finish(response(UNAVAILABLE), 'source-unavailable');
        }
        const payload: TrustedLocalPublicationPayload = Object.freeze({
          correlationId, tenantId: scope.tenantId, collection: requestedCollection,
          rows: Object.freeze(rows.map(row => Object.freeze({ ...row }))),
        });
        // Check the real identity+server actor AGAIN inside the signed lease,
        // once before and once after asynchronous transport staging. A future
        // production actor store must version its changes in the same DB.
        const assertTrustedActor = async (leaseSignal: AbortSignal) => {
          const verified = await sessions.verify(accessToken);
          if (leaseSignal.aborted || !verified ||
              verified.actorId !== scope.actorId) {
            throw new AuthorizationRevisionChanged();
          }
          const fresh = await deps.actors.lookup(verified.actorId, leaseSignal);
          if (leaseSignal.aborted || !fresh || fresh.id !== scope.actorId ||
              !Array.isArray(fresh.memberships) ||
              JSON.stringify(fresh.memberships) !== originalMemberships) {
            throw new AuthorizationRevisionChanged();
          }
          const permission = authorizeTenantRead(
            fresh, requestedTenant, requestedCollection
          );
          if (!permission.allowed || permission.membership.role !== scope.role) {
            throw new AuthorizationRevisionChanged();
          }
        };
        const operationState = await withSignedScopedPublicationBarrier(deps.pool, deps.signer, {
          scope, collection: requestedCollection, baseline: initialRevision, signal,
          limit: requestedLimit,
          recordStagingOutbox: deps.recordStagingOutbox === true,
          producerOperationId: (deps.recordStagingProducerOperation === true ||
              deps.recordStagingOperationMode !== undefined)
            ? requestedOperation : undefined,
          operationMode: deps.recordStagingOperationMode,
          handoff: {
            async prepare(leaseSignal) {
              await assertTrustedActor(leaseSignal);
              const commit = await publisher.stage(payload, leaseSignal);
              await assertTrustedActor(leaseSignal);
              return commit;
            },
            beforeCommit() {
              // Pure signed status lookup logs once AFTER COMMIT via finish().
              if (deps.recordStagingOperationMode === 'status') return;
              // Fail-closed audit is immediately BEFORE local handoff, with
              // no intervening await; an audit exception suppresses commit.
              // It records read authorization, NOT remote delivery.
              deps.audit.record({
                correlationId, actorId: scope.actorId, tenantId: scope.tenantId,
                collection: requestedCollection, result: 'allow',
                reason: 'read-allowed',
              });
            },
          },
        });
        if (deps.recordStagingOperationMode === 'status') {
          // Read-only outcome is truthful only after signed PostgreSQL COMMIT.
          // A failed audit still denies without exposing even the state enum.
          if (!operationState) return finish(response(UNAVAILABLE), 'source-unavailable');
          // 017: DENY only AFTER COMMIT so unknown-ID polling consumes its
          // private signed PG budget. Neither sentinel is a public enum.
          if (operationState === 'absent' || operationState === 'throttled') {
            return finish(response(NOT_FOUND), 'authorization-changed');
          }
          return finish({
            ok: true, status: 200, source: 'staging-signed-rls',
            correlationId, tenantId: scope.tenantId,
            collection: requestedCollection, rows: [], operationState,
          }, 'read-allowed');
        }
        // Audit already succeeded before handoff. Return no SQL bytes to
        // the published-mode caller and DO NOT record a duplicate Allow.
        return {
          ok: true, status: 200, source: 'staging-signed-rls',
          correlationId, tenantId: scope.tenantId, collection: requestedCollection,
          rows: [],
        };
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

/** Original read-only staging path: no publication, unchanged response. */
export function createTrustedSqlReadBoundary(deps: TrustedSqlReadDependencies) {
  return createTrustedSqlReadBoundaryEngine(deps);
}

/**
 * 2G.4d.5b: receipt-only synthetic publication entrypoint. Requires a
 * server-owned revision source and local-only staging sink. The request
 * supplies only access token, tenant, collection, signal and bounded limit.
 * Verified identity/RBAC, sanitized rows, initial epoch and audit remain
 * inside this module; neither raw rows nor a claimed actor/role/revision
 * is returned to the caller. NOT a production HTTP transport.
 */
export function createTrustedSqlPublishedBoundary(
  deps: TrustedSqlReadDependencies & {
    readonly revisions: ServerAuthorizationRevisionSource;
  },
  publisher: TrustedLocalPublicationSink
) {
  const mode = deps?.recordStagingOperationMode;
  if (!deps?.revisions || !publisher || typeof publisher.stage !== 'function' ||
      (deps.recordStagingProducerOperation === true &&
       deps.recordStagingOutbox !== true) ||
      (deps.recordStagingProducerOperation === true && mode !== undefined) ||
      (mode !== undefined && !['issue', 'reserved_commit', 'status'].includes(mode)) ||
      (mode !== undefined && (mode === 'reserved_commit') !==
       (deps.recordStagingOutbox === true))) {
    throw new Error('Invalid staging publication dependency');
  }
  const run = createTrustedSqlReadBoundaryEngine(deps, publisher);
  return async function publish(
    request: TrustedSqlReadRequest
  ): Promise<TrustedSqlPublishedResult> {
    const result = await run(request);
    if (!result.ok) return result;
    return Object.freeze({
      ok: true, status: 200, source: 'staging-local-publication',
      correlationId: result.correlationId, published: true,
      ...(result.operationState === undefined ? {} :
        { operationState: result.operationState }),
    });
  };
}
