/**
 * Stage 2G.4d.7e — a deliberately payload-free synthetic post-COMMIT port.
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
 * Fail closed unless the staging-only, guarded outbox path is explicitly
 * enabled. No caller supplies a stage, commit, callback, payload or worker.
 * The closure returned by stage is intentionally inert before SQL COMMIT.
 */
export function createTrustedSyntheticCommittedIntentBoundary(
  deps: TrustedSqlReadDependencies & {
    readonly revisions: ServerAuthorizationRevisionSource;
  }
): (request: TrustedSqlReadRequest) => Promise<SyntheticCommittedIntentResult> {
  if (typeof process === 'undefined' ||
      process.env.GITHUB_ACTIONS !== 'true' ||
      process.env.SAAS_EPHEMERAL_E2E_CI !== 'true' ||
      process.env.PGHOST !== '127.0.0.1' ||
      process.env.PGDATABASE !== 'saas_ephemeral_test' ||
      process.env.PGPORT !== '5432' ||
      process.env.RAILWAY_PROJECT_ID ||
      process.env.RAILWAY_ENVIRONMENT ||
      !deps?.revisions ||
      deps.recordStagingOutbox !== true) {
    throw new Error('Refusing post-COMMIT intent outside disposable PG16');
  }

  const stageIntent = createTrustedSqlPublishedBoundary(deps, {
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
