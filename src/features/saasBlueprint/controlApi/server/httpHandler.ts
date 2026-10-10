import { authorizeTenantRead } from '../authorization';
import type {
  AuthorizedReadScope, ControlActor, ControlCollection, ControlReadResult,
  ControlResource, ControlSource,
} from '../contracts';
import { cleanReadResult, cleanTenantIndex } from './safeTransport';
import type { VerifiedSyntheticSession } from './syntheticSessions';

type TenantResource = Extract<ControlResource, { kind: 'tenant' }>;

export interface ControlServerDependencies {
  /** Synthetic registry now, trusted OIDC/session verification on staging. */
  readonly sessions: {
    verify(token: string): Promise<VerifiedSyntheticSession | null>;
  };
  /** Server-held memberships; never derived from client headers or body. */
  readonly actors: {
    lookup(actorId: string, signal: AbortSignal): Promise<ControlActor | null>;
  };
  readonly reader: {
    readonly source: ControlSource;
    listTenants(actor: ControlActor, options: { readonly signal: AbortSignal }):
      Promise<readonly TenantResource[]>;
    readCollection(
      scope: AuthorizedReadScope,
      collection: ControlCollection,
      options: { readonly signal: AbortSignal }
    ): Promise<ControlReadResult>;
  };
  /** Never accept this ID from X-Correlation-ID or any other client header. */
  readonly newCorrelationId?: () => string;
}

type Route =
  | { readonly kind: 'index' }
  | { readonly kind: 'read'; readonly tenantId: string; readonly collection: ControlCollection };

const COLLECTIONS = [
  'tenant', 'projects', 'applications', 'client-keys',
  'accounts', 'pools', 'egress', 'routing',
] as const;

function parseRoute(path: string): Route | null {
  if (path === '/control-api/v1/tenants') return { kind: 'index' };
  // No URL-decoding, embedded slashes, traversal, trailing slash or wildcard.
  const matched = /^\/control-api\/v1\/tenants\/([a-zA-Z0-9_-]{1,64})\/metadata\/([a-z-]+)$/.exec(path);
  if (!matched) return null;
  const collection = matched[2] as ControlCollection;
  if (!COLLECTIONS.includes(collection)) return null;
  return { kind: 'read', tenantId: matched[1], collection };
}

const NOT_FOUND = {
  ok: false, status: 404,
  error: { code: 'NOT_FOUND', message: 'Resource unavailable' },
} as const;
const UNAUTHENTICATED = {
  ok: false, status: 401,
  error: { code: 'UNAUTHENTICATED', message: 'Authentication required' },
} as const;
const FORBIDDEN = {
  ok: false, status: 403,
  error: { code: 'FORBIDDEN', message: 'Permission denied' },
} as const;
const UNAVAILABLE = {
  ok: false, status: 503,
  error: { code: 'SOURCE_UNAVAILABLE', message: 'Service unavailable' },
} as const;
const METHOD_NOT_ALLOWED = {
  ok: false, status: 405,
  error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' },
} as const;

function jsonResponse(body: unknown, status: number, correlationId: string): Response {
  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'private, no-store, max-age=0',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Referrer-Policy': 'no-referrer',
    'Vary': 'Authorization',
    'X-Correlation-Id': correlationId,
  });
  if (status === 405) headers.set('Allow', 'GET');
  // Deliberately NO Access-Control-Allow-Origin, cookies, cache or HTML.
  return new Response(JSON.stringify(body), { status, headers });
}

function sameMemberships(
  initialActorId: string, initialMemberships: string, after: ControlActor | null
): boolean {
  return !!after && after.id === initialActorId &&
    JSON.stringify(after.memberships) === initialMemberships;
}

/**
 * Isolated Fetch API handler, NOT mounted in the UI, Gateway or Core.
 * No listener exists unless a separate local-only bootstrap opts in.
 */
export function createControlHttpHandler(deps: ControlServerDependencies) {
  return async function handle(request: Request): Promise<Response> {
    const correlationId = deps.newCorrelationId?.() ?? crypto.randomUUID();
    const reply = (data: unknown, status: number) => jsonResponse(data, status, correlationId);

    try {
      const url = new URL(request.url);
      if (url.search || url.hash) return reply(NOT_FOUND, 404);
      const route = parseRoute(url.pathname);
      if (!route) return reply(NOT_FOUND, 404);
      if (request.method !== 'GET') return reply(METHOD_NOT_ALLOWED, 405);

      // Cross-origin requests do not get CORS and are explicitly rejected.
      const origin = request.headers.get('origin');
      if (origin !== null && origin !== url.origin) return reply(FORBIDDEN, 403);

      const header = request.headers.get('authorization') ?? '';
      const match = /^Bearer ([a-zA-Z0-9._~-]{1,2048})$/.exec(header);
      if (!match || request.signal.aborted) return reply(UNAUTHENTICATED, 401);

      const verified = await deps.sessions.verify(match[1]);
      if (!verified || request.signal.aborted) return reply(UNAUTHENTICATED, 401);

      const actor = await deps.actors.lookup(verified.actorId, request.signal);
      if (!actor || actor.id !== verified.actorId || request.signal.aborted) {
        return reply(UNAUTHENTICATED, 401);
      }
      // Copy membership state BEFORE any await: in-place store updates must not
      // silently turn an already-started read into a stale authorization.
      const originalMemberships = JSON.stringify(actor.memberships);
      const originalActorId = actor.id;

      if (route.kind === 'index') {
        const raw = await deps.reader.listTenants(actor, { signal: request.signal });
        if (request.signal.aborted) return reply(UNAVAILABLE, 503);
        const again = await deps.sessions.verify(match[1]);
        const current = again ? await deps.actors.lookup(again.actorId, request.signal) : null;
        if (!again || again.actorId !== actor.id || !sameMemberships(originalActorId, originalMemberships, current)) {
          return reply(UNAUTHENTICATED, 401);
        }
        if (request.signal.aborted) return reply(UNAVAILABLE, 503);
        const safe = cleanTenantIndex(raw, current!);
        if (!safe) return reply(UNAVAILABLE, 503);
        return reply({
          ok: true, status: 200, apiVersion: 1,
          source: deps.reader.source, data: safe,
        }, 200);
      }

      // The server checks RBAC BEFORE asking any metadata adapter.
      const initial = authorizeTenantRead(actor, route.tenantId, route.collection);
      if (!initial.allowed) return reply(initial.reason === 'not-found' ? NOT_FOUND : FORBIDDEN,
        initial.reason === 'not-found' ? 404 : 403);

      const scope: AuthorizedReadScope = {
        actorId: actor.id, tenantId: route.tenantId,
        role: initial.membership.role, correlationId,
      };
      const raw = await deps.reader.readCollection(scope, route.collection, {
        signal: request.signal,
      });
      if (request.signal.aborted) return reply(UNAVAILABLE, 503);

      // Prevent a stale response after session revocation or tenant switch.
      const again = await deps.sessions.verify(match[1]);
      const current = again ? await deps.actors.lookup(again.actorId, request.signal) : null;
      if (!again || again.actorId !== actor.id || !sameMemberships(originalActorId, originalMemberships, current)) {
        return reply(UNAUTHENTICATED, 401);
      }
      if (request.signal.aborted) return reply(UNAVAILABLE, 503);
      const lastCheck = authorizeTenantRead(current!, route.tenantId, route.collection);
      if (!lastCheck.allowed || lastCheck.membership.role !== scope.role) {
        return reply(NOT_FOUND, 404);
      }

      const safe = cleanReadResult(raw, deps.reader.source, route.tenantId,
        route.collection, scope.role);
      if (!safe) return reply(UNAVAILABLE, 503);
      return reply(safe, safe.status);
    } catch {
      // Do not forward upstream messages, response bodies or auth headers.
      return reply(UNAVAILABLE, 503);
    }
  };
}
