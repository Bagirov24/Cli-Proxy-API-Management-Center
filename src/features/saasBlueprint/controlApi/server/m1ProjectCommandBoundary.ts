/**
 * M1a: explicitly UNMOUNTED server command port for tenant project metadata.
 * Unit tests plus disposable PostgreSQL16 SQL functions only. Never a public
 * HTTP route, OIDC deployment, real PG pool, Core/CPA/VPN/issuer or production
 * API. No bearer, role or signer key is passed to the write port.
 *
 * A future transaction adapter MUST sign the actor/tenant tx-scoped PG GUC
 * using a privileged server-only signer, recheck current membership and
 * tenant state INSIDE the DB transaction and map false/UNKNOWN safely.
 * This TypeScript boundary is NOT sufficient to authorize DB writes alone.
 */
import { authorizeTenantRead } from '../authorization';
import type { ControlActor, TenantRole } from '../contracts';
import {
  createVerifiedSubjectSessionBridge,
  type AccessTokenVerifier, type VerifiedAccessIdentity,
} from './trustedAccessToken';

export type M1ProjectCommand =
  | {
      readonly operation: 'create';
      readonly accessToken: string;
      readonly tenantId: string;
      readonly projectId: string;
      readonly name: string;
      readonly signal: AbortSignal;
    }
  | {
      readonly operation: 'rename';
      readonly accessToken: string;
      readonly tenantId: string;
      readonly projectId: string;
      readonly name: string;
      readonly expectedVersion: number;
      readonly signal: AbortSignal;
    }
  | {
      readonly operation: 'disable';
      readonly accessToken: string;
      readonly tenantId: string;
      readonly projectId: string;
      readonly expectedVersion: number;
      readonly signal: AbortSignal;
    };

export interface M1ProjectWriteScope {
  readonly actorId: string;
  readonly tenantId: string;
  readonly role: 'tenant-owner' | 'tenant-admin';
  readonly correlationId: string;
}

export interface M1ProjectMutation {
  readonly operation: M1ProjectCommand['operation'];
  readonly scope: Readonly<M1ProjectWriteScope>;
  readonly projectId: string;
  readonly name?: string;
  readonly expectedVersion?: number;
  readonly signal: AbortSignal;
}

export interface M1ProjectTransactionalWriter {
  /**
   * Must atomically enforce signed PG tx scope, active membership and
   * tenant, version CAS, project lifecycle and transactional audit. A mock
   * may be used only in CI. No HTTP or Core writer integration exists.
   * false = denied/not found/conflict; errors or abort = uncertain.
   */
  execute(input: Readonly<M1ProjectMutation>): Promise<boolean>;
}

export interface M1ProjectDependencies {
  readonly tokens: AccessTokenVerifier;
  readonly directory: {
    resolveActorId(identity: VerifiedAccessIdentity): Promise<string | null>;
  };
  readonly actors: {
    lookup(actorId: string, signal: AbortSignal): Promise<ControlActor | null>;
  };
  readonly writer: M1ProjectTransactionalWriter;
  readonly newCorrelationId?: () => string;
}

type FailureStatus = 401 | 404 | 503;
const failures = {
  401: { code: 'UNAUTHENTICATED', message: 'Authentication required' },
  404: { code: 'NOT_FOUND', message: 'Resource unavailable' },
  503: { code: 'SOURCE_UNAVAILABLE', message: 'Service unavailable' },
} as const;

export type M1ProjectCommandResult =
  | { readonly ok: true; readonly status: 200 | 201; readonly correlationId: string }
  | {
      readonly ok: false;
      readonly status: FailureStatus;
      readonly correlationId: string;
      readonly error: typeof failures[FailureStatus];
    };

const ID = /^[a-zA-Z0-9_-]{1,64}$/;
const ACTOR = /^[a-zA-Z0-9_-]{1,128}$/;
function validName(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 1 ||
      value.length > 120 || value.trim() !== value) return false;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 32 || code === 127) return false;
  }
  return true;
}
function canWrite(role: TenantRole): role is M1ProjectWriteScope['role'] {
  return role === 'tenant-owner' || role === 'tenant-admin';
}
function roleOf(actor: ControlActor | null, tenantId: string):
  M1ProjectWriteScope['role'] | null {
  if (!actor) return null;
  const auth = authorizeTenantRead(actor, tenantId, 'projects');
  return auth.allowed && canWrite(auth.membership.role) ? auth.membership.role : null;
}

export function createM1ProjectCommandBoundary(deps: M1ProjectDependencies) {
  if (!deps?.tokens || !deps.directory || !deps.actors || !deps.writer ||
      typeof deps.tokens.verifyAccessToken !== 'function' ||
      typeof deps.directory.resolveActorId !== 'function' ||
      typeof deps.actors.lookup !== 'function' ||
      typeof deps.writer.execute !== 'function') {
    throw new Error('M1a requires a trusted verifier, directory, actor store and private writer');
  }
  const sessions = createVerifiedSubjectSessionBridge(deps.tokens, deps.directory);

  return async function command(request: M1ProjectCommand): Promise<M1ProjectCommandResult> {
    const correlationId = deps.newCorrelationId?.() ?? crypto.randomUUID();
    const fail = (status: FailureStatus): M1ProjectCommandResult =>
      ({ ok: false, status, correlationId, error: failures[status] });
    try {
      // Freeze client fields before the first async identity resolution.
      const operation = request?.operation;
      const token = request?.accessToken;
      const tenantId = request?.tenantId;
      const projectId = request?.projectId;
      const name = 'name' in request ? request.name : undefined;
      const version = 'expectedVersion' in request ? request.expectedVersion : undefined;
      const signal = request?.signal;
      if (!ACTOR.test(correlationId) || !signal || signal.aborted) return fail(503);
      if (typeof token !== 'string' || token.length < 1 || token.length > 8192) {
        return fail(401);
      }
      if (typeof tenantId !== 'string' || typeof projectId !== 'string' ||
          !ID.test(tenantId) || !ID.test(projectId) ||
          (operation !== 'create' && operation !== 'rename' && operation !== 'disable') ||
          ((operation === 'create' || operation === 'rename') && !validName(name)) ||
          (operation === 'disable' && name !== undefined) ||
          (operation === 'create' && version !== undefined) ||
          (operation !== 'create' && (typeof version !== 'number' ||
            !Number.isSafeInteger(version) || version < 1 ||
            version >= Number.MAX_SAFE_INTEGER))) {
        return fail(404);
      }

      const verified = await sessions.verify(token);
      if (signal.aborted) return fail(503);
      if (!verified) return fail(401);
      const actor = await deps.actors.lookup(verified.actorId, signal);
      if (signal.aborted) return fail(503);
      const role = roleOf(actor, tenantId);
      if (!role || !actor) return fail(404);
      const initialMemberships = JSON.stringify(actor.memberships);

      // Recheck verification and server-held role immediately before write.
      // DB-side signed tx-scoped membership enforcement is STILL REQUIRED.
      const reverified = await sessions.verify(token);
      if (signal.aborted) return fail(503);
      if (!reverified || reverified.actorId !== verified.actorId) return fail(401);
      const freshActor = await deps.actors.lookup(verified.actorId, signal);
      if (signal.aborted) return fail(503);
      if (!freshActor || freshActor.id !== actor.id ||
          JSON.stringify(freshActor.memberships) !== initialMemberships ||
          roleOf(freshActor, tenantId) !== role) return fail(404);

      const scope: M1ProjectWriteScope = Object.freeze({
        actorId: verified.actorId, tenantId, role, correlationId,
      });
      const input: M1ProjectMutation = Object.freeze({
        operation, scope, projectId,
        ...(operation === 'create' || operation === 'rename' ? { name } : {}),
        ...(operation === 'rename' || operation === 'disable' ? { expectedVersion: version } : {}),
        signal,
      });
      const committed = await deps.writer.execute(input);
      // UNKNOWN-after-COMMIT is not safe to retry automatically. A cancelled
      // or uncertain request NEVER grants a public success via this port.
      if (signal.aborted) return fail(503);
      if (committed !== true) return fail(404);
      return { ok: true, status: operation === 'create' ? 201 : 200, correlationId };
    } catch {
      // Never emit token, membership, SQL errors, project name or secrets.
      return fail(503);
    }
  };
}
