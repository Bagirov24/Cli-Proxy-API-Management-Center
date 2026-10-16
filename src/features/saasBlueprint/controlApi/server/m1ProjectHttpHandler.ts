/**
 * M1i: NOT MOUNTED project-write HTTP adapter.
 *
 * Only for explicit, disposable GitHub CI, never used by the app/router.
 * No Bun.serve(), public port, production PG adapter, real OIDC, API key
 * issuance, auto retry or idempotent replay. A real deployment requires
 * separately reviewed production identity, signed DB writer and fencing.
 */
import {
  createM1ProjectCommandBoundary,
  type M1ProjectCommand, type M1ProjectDependencies,
} from './m1ProjectCommandBoundary';

type Operation = M1ProjectCommand['operation'];
const PATH =
  /^\/control-api\/v1\/tenants\/([A-Za-z0-9_-]{1,64})\/metadata\/projects\/([A-Za-z0-9_-]{1,64})$/;
const BEARER = /^Bearer ([A-Za-z0-9._~-]{1,8192})$/;
const CONTENT_TYPE = /^application\/json(?:;\s*charset=utf-8)?$/i;
const MAX_BODY = 512;
const MIN_VERSION = 1;
const MAX_VERSION = Number.MAX_SAFE_INTEGER - 1;
const SAFE_CORRELATION = /^[A-Za-z0-9_-]{1,128}$/;
const FAILURE = {
  401: { code: 'UNAUTHENTICATED', message: 'Authentication required' },
  403: { code: 'FORBIDDEN', message: 'Permission denied' },
  404: { code: 'NOT_FOUND', message: 'Resource unavailable' },
  405: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' },
  503: { code: 'SOURCE_UNAVAILABLE', message: 'Service unavailable' },
} as const;
type FailureStatus = keyof typeof FAILURE;
const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'private, no-store, max-age=0',
  Pragma: 'no-cache',
  'X-Content-Type-Options': 'nosniff',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Referrer-Policy': 'no-referrer',
  Vary: 'Authorization',
} as const;

function ephemeralCiEnabled(): boolean {
  // The UI/browser bundle cannot satisfy this Node CI process guard.
  const env = (globalThis as unknown as {
    process?: { env?: Record<string, string | undefined> };
  }).process?.env;
  return env?.GITHUB_ACTIONS === 'true' &&
    env.SAAS_EPHEMERAL_M1_HTTP_CI === 'true' &&
    env.NODE_ENV !== 'production' &&
    !env.RAILWAY_PROJECT_ID &&
    !env.RAILWAY_ENVIRONMENT &&
    !env.RAILWAY_SERVICE_ID;
}

function respond(
  status: 200 | 201 | FailureStatus,
  correlationId: string
): Response {
  const headers = new Headers(JSON_HEADERS);
  headers.set('X-Correlation-Id', correlationId);
  if (status === 405) headers.set('Allow', 'POST, PATCH, DELETE');
  const body = status === 200 || status === 201
    ? { ok: true, status, apiVersion: 1, source: 'ci-only-unmounted' }
    : { ok: false, status, error: FAILURE[status] };
  return new Response(JSON.stringify(body), { status, headers });
}

async function boundedJson(request: Request): Promise<Record<string, unknown> | null> {
  const length = request.headers.get('content-length');
  if (length !== null &&
      (!/^(0|[1-9][0-9]{0,3})$/.test(length) || Number(length) > MAX_BODY)) {
    return null;
  }
  if (!request.body || !CONTENT_TYPE.test(request.headers.get('content-type') ?? '')) {
    return null;
  }
  const reader = request.body.getReader();
  const data = new Uint8Array(MAX_BODY);
  let total = 0;
  try {
    for (;;) {
      if (request.signal.aborted) return null;
      const next = await reader.read();
      if (next.done) break;
      if (total + next.value.byteLength > MAX_BODY) {
        await reader.cancel();
        return null;
      }
      data.set(next.value, total);
      total += next.value.byteLength;
    }
    if (total === 0 || (length !== null && total !== Number(length))) return null;
    const decoded = new TextDecoder('utf-8', { fatal: true })
      .decode(data.subarray(0, total));
    const value: unknown = JSON.parse(decoded);
    return value !== null && typeof value === 'object' && !Array.isArray(value)
      ? value as Record<string, unknown> : null;
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
}

function safeName(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 1 ||
      value.length > 120 || value.trim() !== value) return false;
  for (let i = 0; i < value.length; i++) {
    const point = value.charCodeAt(i);
    if (point < 32 || point === 127) return false;
  }
  return true;
}

function safePayload(
  op: Operation, input: Record<string, unknown>
): { readonly name?: string; readonly expectedVersion?: number } | null {
  const keys = Object.keys(input).sort().join(',');
  if (op === 'create' && keys === 'name' && safeName(input.name)) {
    return { name: input.name };
  }
  if (op === 'rename' && keys === 'expectedVersion,name' &&
      safeName(input.name) && typeof input.expectedVersion === 'number' &&
      Number.isSafeInteger(input.expectedVersion) &&
      input.expectedVersion >= MIN_VERSION && input.expectedVersion <= MAX_VERSION) {
    return { name: input.name, expectedVersion: input.expectedVersion };
  }
  if (op === 'disable' && keys === 'expectedVersion' &&
      typeof input.expectedVersion === 'number' &&
      Number.isSafeInteger(input.expectedVersion) &&
      input.expectedVersion >= MIN_VERSION && input.expectedVersion <= MAX_VERSION) {
    return { expectedVersion: input.expectedVersion };
  }
  return null;
}

export interface M1ProjectHttpCiOptions {
  readonly enabledForDisposableCi: true;
}

/**
 * Explicit CI-only adapter for Fetch Request/Response. It is never
 * mounted, and cannot be instantiated without GitHub + explicit CI flag.
 */
export function createM1ProjectHttpHandler(
  deps: M1ProjectDependencies, options: M1ProjectHttpCiOptions
) {
  if (options?.enabledForDisposableCi !== true || !ephemeralCiEnabled()) {
    throw new Error('M1i project writes are disabled outside disposable GitHub CI');
  }
  // Fail initialization before any Request is accepted, even in CI.
  createM1ProjectCommandBoundary(deps);

  return async function handle(request: Request): Promise<Response> {
    // Never read correlationId/role/tenant/attempt from headers or JSON.
    const supplied = deps.newCorrelationId?.();
    const correlationId = supplied && SAFE_CORRELATION.test(supplied)
      ? supplied : crypto.randomUUID();
    const reply = (status: 200 | 201 | FailureStatus) =>
      respond(status, correlationId);
    try {
      if (!ephemeralCiEnabled()) return reply(503);
      if (request.signal.aborted) return reply(503);
      const url = new URL(request.url);
      if (url.protocol !== 'http:' ||
          !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) ||
          url.username || url.password || url.search || url.hash) return reply(404);
      const route = PATH.exec(url.pathname);
      if (!route) return reply(404);
      const op: Operation | null = request.method === 'POST' ? 'create'
        : request.method === 'PATCH' ? 'rename'
          : request.method === 'DELETE' ? 'disable' : null;
      if (!op) return reply(405);

      // No cookies, unsafe browser cross-origin requests, CORS, or
      // implicit client-provided authority/idempotency/attempt tokens.
      if (request.headers.has('cookie') ||
          request.headers.has('idempotency-key') ||
          request.headers.has('x-attempt-id') ||
          request.headers.has('x-actor-id') ||
          request.headers.has('x-tenant-id') ||
          request.headers.has('x-role') ||
          request.headers.has('x-correlation-id')) return reply(404);
      const origin = request.headers.get('origin');
      if ((origin !== null && origin !== url.origin) ||
          request.headers.get('sec-fetch-site') === 'cross-site') return reply(403);
      const match = BEARER.exec(request.headers.get('authorization') ?? '');
      if (!match) return reply(401);
      const json = await boundedJson(request);
      if (request.signal.aborted) return reply(503);
      if (!json) return reply(404);
      const dto = safePayload(op, json);
      if (!dto) return reply(404);
      const [tenantId, projectId] = [route[1], route[2]];
      const base = {
        operation: op, accessToken: match[1], tenantId, projectId,
        signal: request.signal,
      };
      const command: M1ProjectCommand = op === 'create'
        ? { ...base, operation: 'create', name: dto.name! }
        : op === 'rename'
          ? { ...base, operation: 'rename',
            name: dto.name!, expectedVersion: dto.expectedVersion! }
          : { ...base, operation: 'disable', expectedVersion: dto.expectedVersion! };
      const run = createM1ProjectCommandBoundary({
        ...deps, newCorrelationId: () => correlationId,
      });
      const result = await run(command);
      if (request.signal.aborted) return reply(503);
      if (result.ok && result.status === (op === 'create' ? 201 : 200)) {
        return reply(result.status);
      }
      if (!result.ok && (result.status === 401 ||
          result.status === 404 || result.status === 503)) {
        return reply(result.status);
      }
      return reply(503);
    } catch {
      // No token, tenant, project, SQL diagnostic, raw body or stack leaks.
      return reply(503);
    }
  };
}
