/**
 * Backend 06: explicit, fetch-only SaaS server composition for isolated staging.
 *
 * No Bun.serve(), DNS/public endpoint, credentials, SQL migrations or Core
 * integration. The host MUST independently enforce private ingress and use
 * reviewed least-privilege PG drivers, signer, audit and durable journal.
 * Staging configuration flags are startup gates, NOT proof of network policy.
 */
import {
  createOperatorPinnedOidcAccessVerifier,
  pinnedOidcConfigFromServerEnvironment,
  type OperatorPinnedOidcEnvironment,
} from './operatorPinnedOidcAccessVerifier';
import {
  createPgDurableIdentitySessionAuthority,
  type PgIdentityPool,
} from './pgDurableIdentitySessionAuthority';
import {
  createTenantProjectsReadHttpHandler,
  type TenantProjectsHttpDependencies,
} from './tenantProjectsReadHttpHandler';
import {
  createTenantProjectsWriteHttpHandler,
  type TenantProjectsWriteHttpDependencies,
} from './tenantProjectsWriteHttpHandler';

export interface SaasStagingHttpEnvironment extends OperatorPinnedOidcEnvironment {
  readonly SAAS_HTTP_EXPLICIT_ENABLE?: string;
  readonly SAAS_RUNTIME_PROFILE?: string;
  readonly SAAS_NETWORK_POLICY?: string;
  readonly SAAS_EXTERNAL_ORIGIN?: string;
  readonly SAAS_EPHEMERAL_COMPOSITION_CI?: string;
  readonly GITHUB_ACTIONS?: string;
  readonly RAILWAY_ENVIRONMENT?: string;
}

export interface SaasStagingHttpDependencies {
  /** SQL026/027: a separate restricted login, not the write/read pool. */
  readonly identityPool: PgIdentityPool;
  readonly read: Pick<TenantProjectsHttpDependencies,
    'pool' | 'signer' | 'revisions' | 'audit' | 'newCorrelationId'>;
  readonly write: Pick<TenantProjectsWriteHttpDependencies,
    'journal' | 'writer' | 'newCorrelationId'>;
  /**
   * Independently implemented fail-closed operational probe. A true result
   * is not an identity, audit, physical discard or network-policy approval.
   * Called on EVERY SaaS API request, not just /readyz.
   */
  readonly readiness: {
    check(signal: AbortSignal): Promise<boolean>;
  };
}

const COLLECTION =
  /^\/control-api\/v1\/tenants\/[A-Za-z0-9_-]{1,64}\/projects$/;
const ITEM =
  /^\/control-api\/v1\/tenants\/[A-Za-z0-9_-]{1,64}\/projects\/[A-Za-z0-9_-]{1,64}$/;

function refuse(): never {
  throw new Error('Isolated SaaS staging composition configuration refused');
}

function externalOrigin(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 12 ||
      value.length > 256) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value &&
      !url.username && !url.password && !url.search && !url.hash;
  } catch { return false; }
}

function response(status: 200 | 404 | 405 | 503, allow?: string): Response {
  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'private, no-store, max-age=0',
    Pragma: 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'none'",
  });
  if (allow) headers.set('Allow', allow);
  const body = status === 200
    ? {ok: true, status: 200}
    : {ok: false, status,
      error: status === 503
        ? {code: 'SOURCE_UNAVAILABLE', message: 'Service unavailable'}
        : status === 405
          ? {code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed'}
          : {code: 'NOT_FOUND', message: 'Resource unavailable'}};
  return new Response(JSON.stringify(body), {status, headers});
}

/**
 * This factory composes real handler factories and verified public JWKS
 * with SQL026/027 identity authority. It does not create a listener.
 * Never override the verified token/directory/session ports from HTTP or
 * from unchecked caller spreads. There is no synthetic identity fallback.
 */
export async function createSaasStagingHttpComposition(
  env: SaasStagingHttpEnvironment,
  deps: SaasStagingHttpDependencies
): Promise<{readonly handle: (request: Request) => Promise<Response>}> {
  if (!env || env.SAAS_HTTP_EXPLICIT_ENABLE !== 'true' ||
      env.SAAS_RUNTIME_PROFILE !== 'isolated-staging' ||
      env.SAAS_NETWORK_POLICY !== 'private-only' ||
      env.RAILWAY_ENVIRONMENT !== 'staging' ||
      (env.GITHUB_ACTIONS === 'true' &&
       env.SAAS_EPHEMERAL_COMPOSITION_CI !== 'true') ||
      !externalOrigin(env.SAAS_EXTERNAL_ORIGIN) ||
      !deps || !deps.read || !deps.write ||
      typeof deps.readiness?.check !== 'function') refuse();

  // Verify operator-owned RSA public trust BEFORE touching any PG pool.
  // Invalid/missing IdP inputs abort startup; never fetch or generate keys.
  const tokens = await createOperatorPinnedOidcAccessVerifier(
    pinnedOidcConfigFromServerEnvironment(env)
  );
  const identity = createPgDurableIdentitySessionAuthority(deps.identityPool);
  const origin = env.SAAS_EXTERNAL_ORIGIN;
  const read = createTenantProjectsReadHttpHandler({
    expectedOrigin: origin,
    tokens,
    actorDirectory: identity.directory,
    actors: identity.actors,
    pool: deps.read.pool,
    signer: deps.read.signer,
    revisions: deps.read.revisions,
    audit: deps.read.audit,
    newCorrelationId: deps.read.newCorrelationId,
  });
  const write = createTenantProjectsWriteHttpHandler({
    expectedOrigin: origin,
    tokens,
    directory: identity.directory,
    actors: identity.actors,
    sessions: identity.sessions,
    journal: deps.write.journal,
    writer: deps.write.writer,
    newCorrelationId: deps.write.newCorrelationId,
  });

  async function ready(signal: AbortSignal): Promise<boolean> {
    if (signal.aborted) return false;
    try {
      const ok = await deps.readiness.check(signal);
      return !signal.aborted && ok === true;
    } catch {
      return false;
    }
  }

  async function handle(request: Request): Promise<Response> {
    try {
      if (!request || request.signal.aborted) return response(503);
      const url = new URL(request.url);
      if (url.origin !== origin || url.username || url.password ||
          url.hash) return response(404);
      const path = url.pathname;
      if (path === '/internal/healthz' || path === '/internal/readyz') {
        if (url.search) return response(404);
        if (request.method !== 'GET') return response(405, 'GET');
        if (path === '/internal/healthz') return response(200);
        return response(await ready(request.signal) ? 200 : 503);
      }
      const collection = COLLECTION.test(path);
      const item = ITEM.test(path);
      if (!collection && !item) return response(404);
      if (collection && request.method !== 'GET' &&
          request.method !== 'POST') return response(405, 'GET, POST');
      if (item && request.method !== 'PATCH') return response(405, 'PATCH');
      if (!(await ready(request.signal))) return response(503);
      // No retry, reissue or automatic replay after any downstream 503.
      return collection && request.method === 'GET'
        ? await read(request)
        : await write(request);
    } catch {
      // Never expose verifier, SQL, signer or connection diagnostics.
      return response(503);
    }
  }

  return Object.freeze({handle});
}
