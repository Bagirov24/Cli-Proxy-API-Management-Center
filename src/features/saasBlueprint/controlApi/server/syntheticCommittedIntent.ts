/**
 * Stage 2G.4d.7e/f — payload-free synthetic post-COMMIT producer idempotency.
 *
 * Existing local publication invokes an injected synchronous handoff before
 * PostgreSQL COMMIT. This NEW, isolated port injects NO application handoff:
 * the signed transaction only inserts migration-009 audit + migration-013
 * immutable intent. Independent 012/013/014 workers may observe a committed
 * intent later. It NEVER emits a response body, remote request or client ACK.
 *
 * Only usable in disposable GitHub PostgreSQL16 acceptance. The old
 * publication boundary is unchanged; this is not a production replacement.
 */
import {
  createTrustedSqlPublishedBoundary,
  type TrustedSqlReadDependencies,
  type TrustedSqlReadRequest,
  type TrustedSqlPublishedResult,
} from './trustedSqlReadBoundary';
import type { ServerAuthorizationRevisionSource } from './authorizationRevision';

// Scoped to this server-only module: the Vite TS build does not include
// Node global typings; the browser has no process and therefore fails closed.
declare const process: { readonly env: Readonly<Record<string, string | undefined>> };

export type SyntheticCommittedIntentResult =
  | Exclude<TrustedSqlPublishedResult, { readonly ok: true }>
  | {
      readonly ok: true;
      readonly status: 200;
      readonly source: 'staging-committed-intent-only';
      readonly correlationId: string;
      readonly intentCommitted: true;
      readonly externalReceipt: 'not_attested';
    };

/**
 * Every new staging-only entrypoint is disabled without an isolated GitHub
 * ephemeral PostgreSQL 16 and server-controlled authorization revisions.
 * This is defense in depth, NOT a production identity/transport mechanism.
 */
function assertDisposableStaging(
  deps: TrustedSqlReadDependencies & {
    readonly revisions: ServerAuthorizationRevisionSource;
  },
  requireOutbox: boolean
): void {
  if (typeof process === 'undefined' ||
      process.env.GITHUB_ACTIONS !== 'true' ||
      process.env.SAAS_EPHEMERAL_E2E_CI !== 'true' ||
      process.env.PGHOST !== '127.0.0.1' ||
      process.env.PGDATABASE !== 'saas_ephemeral_test' ||
      process.env.PGPORT !== '5432' ||
      process.env.NODE_ENV === 'production' ||
      process.env.RAILWAY_PROJECT_ID ||
      process.env.RAILWAY_ENVIRONMENT ||
      !deps?.revisions || (requireOutbox && deps.recordStagingOutbox !== true)) {
    throw new Error('Refusing post-COMMIT intent outside disposable PG16');
  }
}

/** Private NO-OP sender: never observe, persist or transmit SQL rows. */
const NO_EFFECT_SINK = {
  async stage(_privatePayload: unknown, signal: AbortSignal): Promise<() => void> {
    if (signal.aborted) throw new Error('Synthetic intent preparation aborted');
    return () => { /* strictly NO pre-COMMIT effect */ };
  },
};

/**
 * Fail closed unless the staging-only, guarded outbox path is explicitly
 * enabled. Caller supplies a stable UUIDv4 operation ID, NEVER an identity
 * grant, stage/commit callback, payload or worker.
 * The closure returned by stage is intentionally inert before SQL COMMIT.
 */
export function createTrustedSyntheticCommittedIntentBoundary(
  deps: TrustedSqlReadDependencies & {
    readonly revisions: ServerAuthorizationRevisionSource;
  }
): (request: TrustedSqlReadRequest & { readonly producerOperationId: string }) =>
  Promise<SyntheticCommittedIntentResult> {
  assertDisposableStaging(deps, true);

  const stageIntent = createTrustedSqlPublishedBoundary({
    ...deps,
    recordStagingProducerOperation: true,
  }, {
    // Never inspect/store/emit the sanitized rows passed by the old local
    // publication engine; only its signed 009 audit/013 intent is durable.
    async stage(_privatePayload, signal) {
      if (signal.aborted) throw new Error('Intent preparation aborted');
      return () => { /* no external side effect before PostgreSQL COMMIT */ };
    },
  });

  return async function recordIntent(request) {
    const result = await stageIntent(request);
    if (!result.ok) return result;
    // "committed" only after signed SQL COMMIT resolved successfully.
    // Other paths (including an uncertain COMMIT response) fail closed as
    // generic unavailable, never asserting that no intent exists.
    return Object.freeze({
      ok: true as const,
      status: 200 as const,
      source: 'staging-committed-intent-only' as const,
      correlationId: result.correlationId,
      intentCommitted: true as const,
      externalReceipt: 'not_attested' as const,
    });
  };
}

/** 016: DB-issued operation ID; the ID itself is NOT a credential. */
export type SyntheticOperationIssuedResult =
  | Exclude<TrustedSqlPublishedResult, { readonly ok: true }>
  | {
      readonly ok: true;
      readonly status: 200;
      readonly source: 'staging-operation-issued';
      readonly correlationId: string;
      readonly operationId: string;
      /** Database TTL starts at INSERT; this is a nominal upper bound. */
      readonly maxIssueWindowSeconds: 120;
    };

/** 016: authenticated, request-shape-bound committed-intent status only. */
export type SyntheticOperationRecoveryResult =
  | Exclude<TrustedSqlPublishedResult, { readonly ok: true }>
  | {
      readonly ok: true;
      readonly status: 200;
      readonly source: 'staging-operation-status';
      readonly correlationId: string;
      readonly operationState: 'issued' | 'committed' | 'expired';
      readonly externalReceipt: 'not_attested';
    };

/** Server mints fresh UUIDv4 only AFTER it has received a request. The
 * signed SQL issuer still rechecks tenant/actor/role/revision/RLS and stores
 * a guarded, immutable two-hour tombstone before this UUID is returned. */
export function createTrustedSyntheticOperationIssuer(
  deps: TrustedSqlReadDependencies & {
    readonly revisions: ServerAuthorizationRevisionSource;
  }
): (request: TrustedSqlReadRequest) => Promise<SyntheticOperationIssuedResult> {
  assertDisposableStaging(deps, false);
  const issue = createTrustedSqlPublishedBoundary({
    ...deps, recordStagingOutbox: false,
    recordStagingProducerOperation: false,
    recordStagingOperationMode: 'issue',
  }, NO_EFFECT_SINK);
  return async function issueOperation(request) {
    // The UUID is server-generated, not a caller-declared identity.
    const operationId = crypto.randomUUID();
    const result = await issue({ ...request, producerOperationId: operationId });
    if (!result.ok) return result;
    return Object.freeze({
      ok: true as const, status: 200 as const,
      source: 'staging-operation-issued' as const,
      correlationId: result.correlationId,
      operationId, maxIssueWindowSeconds: 120 as const,
    });
  };
}

/** Only a successfully reauthenticated owner with exact shape can recover
 * an issued/committed/expired label. Never return event_id or worker state. */
export function createTrustedSyntheticOperationStatusBoundary(
  deps: TrustedSqlReadDependencies & {
    readonly revisions: ServerAuthorizationRevisionSource;
  }
): (request: TrustedSqlReadRequest & { readonly producerOperationId: string }) =>
  Promise<SyntheticOperationRecoveryResult> {
  assertDisposableStaging(deps, false);
  const recover = createTrustedSqlPublishedBoundary({
    ...deps, recordStagingOutbox: false,
    recordStagingProducerOperation: false,
    recordStagingOperationMode: 'status',
  }, NO_EFFECT_SINK);
  return async function operationStatus(request) {
    const result = await recover(request);
    if (!result.ok) return result;
    if (!result.operationState) {
      // Invalid driver/scope result is never a successful recovery.
      throw new Error('Invalid synthetic operation status attestation');
    }
    return Object.freeze({
      ok: true as const, status: 200 as const,
      source: 'staging-operation-status' as const,
      correlationId: result.correlationId,
      operationState: result.operationState,
      externalReceipt: 'not_attested' as const,
    });
  };
}

/** 016 reserved-only event path. Migration 015's legacy synthetic entrypoint
 * remains unmodified for backwards-compatible tests. No remote callback. */
export function createTrustedReservedSyntheticIntentBoundary(
  deps: TrustedSqlReadDependencies & {
    readonly revisions: ServerAuthorizationRevisionSource;
  }
): (request: TrustedSqlReadRequest & { readonly producerOperationId: string }) =>
  Promise<SyntheticCommittedIntentResult> {
  assertDisposableStaging(deps, true);
  const record = createTrustedSqlPublishedBoundary({
    ...deps, recordStagingOutbox: true,
    recordStagingProducerOperation: false,
    recordStagingOperationMode: 'reserved_commit',
  }, NO_EFFECT_SINK);
  return async function commitReservedIntent(request) {
    const result = await record(request);
    if (!result.ok) return result;
    return Object.freeze({
      ok: true as const, status: 200 as const,
      source: 'staging-committed-intent-only' as const,
      correlationId: result.correlationId,
      intentCommitted: true as const,
      externalReceipt: 'not_attested' as const,
    });
  };
}
