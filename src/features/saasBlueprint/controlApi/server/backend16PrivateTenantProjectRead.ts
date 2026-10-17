/**
 * Backend16: UNMOUNTED, fail-closed, private HTTP read boundary.
 *
 * This is NOT an OIDC implementation or PostgreSQL adapter. The two trusted
 * ports must be supplied by a separately reviewed server-side composition.
 * Importing this module never starts an HTTP listener and never connects to DB.
 *
 * In particular, a JWT fingerprint or client tenant ID is NOT authorization.
 * The database port must select and authenticate a distinct physical PG LOGIN
 * for the verified subject; recheck current grant/session/subject binding in
 * one READ ONLY transaction while holding the required FOR SHARE locks and
 * respecting FORCE RLS. No SET ROLE or client-controlled GUC impersonation.
 */

export type VerifiedPrincipal = Readonly<{
  kind: 'verified-server-session';
  issuer: string;
  subjectFingerprintSha256: string;
  pgLogin: string;
  sessionId: string;
  bindingId: string;
  sessionExpiresAtMs: number;
}>;

/** Returned by the trusted PostgreSQL reader, not derived from HTTP claims. */
export type AuthorizedTenantProjects = Readonly<{
  kind: 'authorized';
  tenantId: string;
  projectIds: readonly string[];
}>;

export type ReaderDecision = AuthorizedTenantProjects | Readonly<{ kind: 'denied' }>;

export type Backend16PrivateReadPorts = Readonly<{
  /** Must be explicitly enabled by a private, server-controlled config gate. */
  enabled: () => boolean;
  /** Exact HTTPS origin pinned by the server operator, never from Host headers. */
  expectedOrigin: string;
  /** Must verify OIDC issuer, signature/JWKS, audience, exp/iat/nbf, etc. */
  authenticate: (bearerJwt: string, signal: AbortSignal) => Promise<VerifiedPrincipal | null>;
  /** Must atomically check PG LOGIN+tenant grant+session+binding+FORCE RLS. */
  readAuthorized: (
    principal: VerifiedPrincipal,
    tenantId: string,
    signal: AbortSignal,
  ) => Promise<ReaderDecision>;
  now?: () => number;
}>;

export type Backend16PrivateReadHandler = (request: Request) => Promise<Response>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const PG_LOGIN = /^[a-z][a-z0-9_]{2,62}$/;
const ROUTE = /^\/internal\/saas\/v1\/tenants\/([0-9a-f-]{36})(\/projects)?$/;
const JWT = /^[A-Za-z0-9_-]{1,2048}\.[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,2048}$/;
const FORBIDDEN_PG_LOGINS = new Set([
  'postgres', 'saas_schema_migrator', 'saas_runtime_reader', 'saas_runtime_writer',
]);
const MAX_JWT_LENGTH = 6144;
const MAX_PROJECTS = 50;
const MAX_SESSION_MS = 15 * 60_000;

const RESPONSE_HEADERS = {
  'Cache-Control': 'no-store, no-cache, must-revalidate',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Vary': 'Authorization',
  'Cross-Origin-Resource-Policy': 'same-origin',
} as const;

function response(status: number, payload: unknown, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { ...RESPONSE_HEADERS, 'Content-Type': 'application/json; charset=utf-8', ...extra },
  });
}
function denied(status: number, code: string, extra?: Record<string, string>): Response {
  return response(status, { error: { code } }, extra);
}

function validOrigin(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 256) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value &&
      !url.username && !url.password && !url.search && !url.hash;
  } catch { return false; }
}

function isCanonicalUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value);
}

function validPrincipal(value: unknown, nowMs: number): value is VerifiedPrincipal {
  if (!value || typeof value !== 'object' || !Number.isSafeInteger(nowMs)) return false;
  const p = value as Partial<VerifiedPrincipal>;
  if (p.kind !== 'verified-server-session' || typeof p.issuer !== 'string' ||
      typeof p.subjectFingerprintSha256 !== 'string' || !SHA256.test(p.subjectFingerprintSha256) ||
      typeof p.pgLogin !== 'string' || !PG_LOGIN.test(p.pgLogin) ||
      FORBIDDEN_PG_LOGINS.has(p.pgLogin) || !isCanonicalUuid(p.sessionId) ||
      !isCanonicalUuid(p.bindingId) || typeof p.sessionExpiresAtMs !== 'number' ||
      !Number.isSafeInteger(p.sessionExpiresAtMs) ||
      p.sessionExpiresAtMs <= nowMs || p.sessionExpiresAtMs > nowMs + MAX_SESSION_MS) return false;
  try {
    const u = new URL(p.issuer);
    return u.protocol === 'https:' && !!u.hostname && !u.username && !u.password &&
      !u.search && !u.hash && u.pathname.length <= 300 && p.issuer.length <= 512;
  } catch { return false; }
}

function validAuthorized(value: unknown, tenantId: string): value is AuthorizedTenantProjects {
  if (!value || typeof value !== 'object') return false;
  const v = value as Partial<AuthorizedTenantProjects>;
  if (v.kind !== 'authorized' || v.tenantId !== tenantId ||
      !Array.isArray(v.projectIds) || v.projectIds.length > MAX_PROJECTS) return false;
  const ids = v.projectIds as readonly unknown[];
  return ids.every(isCanonicalUuid) && new Set(ids).size === ids.length;
}

/**
 * Intentionally unmounted. Do not attach to a public listener until BOTH
 * trusted ports have independent real PostgreSQL16/OIDC security acceptance.
 */
export function createBackend16PrivateReadHandler(ports: Backend16PrivateReadPorts): Backend16PrivateReadHandler {
  if (!ports || !validOrigin(ports.expectedOrigin) ||
      typeof ports.enabled !== 'function' ||
      typeof ports.authenticate !== 'function' || typeof ports.readAuthorized !== 'function' ||
      (ports.now !== undefined && typeof ports.now !== 'function')) {
    throw new TypeError('trusted private read ports required');
  }
  const expectedOrigin = ports.expectedOrigin;

  return async (request: Request): Promise<Response> => {
    // No authentication, DNS or database calls are made when disabled.
    try { if (ports.enabled() !== true) return denied(404, 'NOT_FOUND'); }
    catch { return denied(503, 'UNAVAILABLE'); }

    if (request.method !== 'GET') return denied(405, 'METHOD_NOT_ALLOWED', { Allow: 'GET' });
    if (request.signal.aborted) return denied(503, 'UNAVAILABLE');
    if (request.body !== null) return denied(400, 'BAD_REQUEST');
    if (request.headers.has('Cookie') || request.headers.has('X-Tenant-ID') ||
        request.headers.has('Forwarded') || request.headers.has('X-Forwarded-Host') ||
        request.headers.has('X-Forwarded-Proto') || request.headers.has('X-Forwarded-User') ||
        request.headers.has('X-Original-URL') || request.headers.has('X-Rewrite-URL') ||
        request.headers.get('Sec-Fetch-Site') === 'cross-site' ||
        (request.headers.has('Origin') &&
         request.headers.get('Origin') !== expectedOrigin) ||
        request.headers.has('X-Role') || request.headers.has('X-PG-Login') ||
        request.headers.has('Transfer-Encoding')) return denied(400, 'BAD_REQUEST');
    const contentLength = request.headers.get('Content-Length');
    if (contentLength !== null && contentLength !== '0') return denied(400, 'BAD_REQUEST');

    let tenantId: string, listProjects: boolean;
    try {
      const url = new URL(request.url);
      if (url.origin !== expectedOrigin) return denied(404, 'NOT_FOUND');
      if (url.search || url.hash || url.username || url.password) return denied(400, 'BAD_REQUEST');
      const match = ROUTE.exec(url.pathname);
      if (!match || !isCanonicalUuid(match[1])) return denied(404, 'NOT_FOUND');
      tenantId = match[1];
      listProjects = match[2] === '/projects';
    } catch { return denied(400, 'BAD_REQUEST'); }

    const authorization = request.headers.get('Authorization');
    if (authorization === null || authorization.length > MAX_JWT_LENGTH + 7) {
      return denied(401, 'UNAUTHORIZED', { 'WWW-Authenticate': 'Bearer' });
    }
    const auth = /^Bearer (.+)$/i.exec(authorization);
    if (!auth || auth[1].length > MAX_JWT_LENGTH || !JWT.test(auth[1])) {
      return denied(401, 'UNAUTHORIZED', { 'WWW-Authenticate': 'Bearer' });
    }

    try {
      // A verified JWT is not enough: the SQL port must recheck tenant grant,
      // current session and subject binding in the same locked read transaction.
      const principal = await ports.authenticate(auth[1], request.signal);
      if (request.signal.aborted) return denied(503, 'UNAVAILABLE');
      const now = (ports.now ?? Date.now)();
      if (!validPrincipal(principal, now)) return denied(401, 'UNAUTHORIZED', { 'WWW-Authenticate': 'Bearer' });
      const read = await ports.readAuthorized(principal, tenantId, request.signal);
      if (request.signal.aborted) return denied(503, 'UNAVAILABLE');
      if (!validPrincipal(principal, (ports.now ?? Date.now)())) return denied(503, 'UNAVAILABLE');
      if (read?.kind === 'denied') return denied(404, 'NOT_FOUND');
      if (!validAuthorized(read, tenantId)) return denied(503, 'UNAVAILABLE');

      // Whitelist-only output. No actor fingerprint, PG login, grants, raw
      // SQL rows, session IDs, secrets, or OIDC/JWT material ever serialize.
      if (!listProjects) return response(200, { tenant: { id: tenantId } });
      return response(200, { tenantId, projectIds: [...read.projectIds] });
    } catch {
      // Never leak SQLSTATE, tenant existence, tokens, subjects or stack traces.
      return denied(503, 'UNAVAILABLE');
    }
  };
}
