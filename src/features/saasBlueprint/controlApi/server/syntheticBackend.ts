import type { BlueprintSnapshot } from '../../domain';
import { authorizeTenantRead } from '../authorization';
import type {
  AuthorizedReadScope, ControlActor, ControlCollection, ControlReadResult,
} from '../contracts';
import { listAccessibleTenants, readSyntheticTenantCollection } from '../readOnlyProjection';
import type { ControlServerDependencies } from './httpHandler';

export interface SyntheticBackendOptions {
  /** All fixture actors live in server-held state, never a request payload. */
  readonly actors: ReadonlyMap<string, ControlActor>;
  readonly snapshot: () => BlueprintSnapshot;
  readonly nowMs: () => number;
}

/**
 * Explicitly synthetic backing adapter. Does not implement Core metadata
 * transport and cannot make network calls or read credentials.
 */
export function createSyntheticControlBackend(options: SyntheticBackendOptions):
  Pick<ControlServerDependencies, 'actors' | 'reader'> {
  return {
    actors: {
      async lookup(actorId: string, signal: AbortSignal): Promise<ControlActor | null> {
        if (signal.aborted) throw new Error('Cancelled');
        return options.actors.get(actorId) ?? null;
      },
    },
    reader: {
      source: 'synthetic-simulation',
      async listTenants(actor, { signal }) {
        if (signal.aborted) throw new Error('Cancelled');
        return listAccessibleTenants(options.snapshot(), actor);
      },
      async readCollection(
        scope: AuthorizedReadScope,
        collection: ControlCollection,
        { signal }: { readonly signal: AbortSignal }
      ): Promise<ControlReadResult> {
        if (signal.aborted) throw new Error('Cancelled');
        const actor = options.actors.get(scope.actorId);
        if (!actor) return { ok: false, status: 404,
          error: { code: 'NOT_FOUND', message: 'Resource unavailable' } };
        const auth = authorizeTenantRead(actor, scope.tenantId, collection);
        if (!auth.allowed || auth.membership.role !== scope.role) {
          return { ok: false, status: 404,
            error: { code: 'NOT_FOUND', message: 'Resource unavailable' } };
        }
        return readSyntheticTenantCollection(
          options.snapshot(), actor, scope.tenantId, collection, options.nowMs()
        );
      },
    },
  };
}
