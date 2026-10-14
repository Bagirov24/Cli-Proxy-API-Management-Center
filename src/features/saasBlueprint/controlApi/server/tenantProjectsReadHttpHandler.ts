/**
 * First deploy-shaped SaaS control-plane HTTP READ slice.
 *
 * GET /control-api/v1/tenants/:tenantId/projects?limit=1..50
 *
 * NOT mounted by Vite/Gateway/Core. No global listener, token issuance, DB
 * password, SQL from the caller or production deployment. Actual requests
 * are authorized by the existing verified-issuer/session bridge, current
 * tenant RBAC, server-authoritative revisions and token-fingerprint-bound
 * signed PostgreSQL transactions. The caller must supply an independently
 * reviewed identity verifier, trusted actor directory, durable audit sink
 * and driver with proven connection quarantine BEFORE any real deployment.
 */
import {createTrustedSqlReadBoundary, type TrustedSqlReadDependencies}
  from './trustedSqlReadBoundary';
import type {SecurityAuditDecision, SecurityAuditReason} from './securityAudit';
import type {ServerAuthorizationRevisionSource} from './authorizationRevision';
import type {SqlRow} from './signedSqlBoundary';

export interface TenantProjectsHttpDependencies extends
  Omit<TrustedSqlReadDependencies,
    'revisions' | 'requireTokenBoundSession' | 'recordStagingOutbox' |
    'recordStagingProducerOperation' | 'recordStagingOperationMode'> {
  /** Bound by the deployer, never from Host/X-Forwarded-* or an HTTP header. */
  readonly expectedOrigin: string;
  /** Mandatory tenant-wide DB-authoritative revision/expiry source. */
  readonly revisions: ServerAuthorizationRevisionSource;
}

type FailureStatus = 401 | 403 | 404 | 405 | 503;
const FAILURES = {
  401: {code:'UNAUTHENTICATED',message:'Authentication required'},
  403: {code:'FORBIDDEN',message:'Permission denied'},
  404: {code:'NOT_FOUND',message:'Resource unavailable'},
  405: {code:'METHOD_NOT_ALLOWED',message:'Method not allowed'},
  503: {code:'SOURCE_UNAVAILABLE',message:'Service unavailable'},
} as const;
const TENANT = /^[A-Za-z0-9_-]{1,64}$/;
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const BEARER = /^Bearer ([A-Za-z0-9._~-]{1,8192})$/;
const PATH = /^\/control-api\/v1\/tenants\/([A-Za-z0-9_-]{1,64})\/projects$/;
const PROJECT_ID = /^[A-Za-z0-9_-]{1,128}$/;
const VALID_STATUS = new Set(['active','disabled']);
const INJECTED_HEADERS = [
  'cookie','x-actor-id','x-tenant-id','x-role','x-session-id',
  'x-correlation-id','x-project-id','x-token-fingerprint',
  'x-forwarded-user','x-forwarded-role','x-forwarded-tenant',
] as const;

function ephemeralLoopbackEnabled(): boolean {
  // This is ONLY for real HTTP against disposable PG16 in GitHub Actions.
  const env = (globalThis as unknown as {
    process?: {env?: Record<string,string|undefined>}
  }).process?.env;
  return env?.GITHUB_ACTIONS === 'true' &&
    env.SAAS_PROJECT_READ_HTTP_CI === 'true' &&
    env.NODE_ENV !== 'production' &&
    !env.RAILWAY_PROJECT_ID && !env.RAILWAY_ENVIRONMENT &&
    !env.RAILWAY_SERVICE_ID;
}
function validOrigin(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 256) return false;
  try {
    const parsed = new URL(value);
    if (parsed.origin !== value || parsed.username || parsed.password ||
        parsed.hostname.length < 1 || parsed.hash || parsed.search) return false;
    if (parsed.protocol === 'https:') return true;
    return parsed.protocol === 'http:' &&
      parsed.hostname === '127.0.0.1' && ephemeralLoopbackEnabled();
  } catch { return false; }
}
function response(status: 200 | FailureStatus,
  correlationId: string, data?: readonly ProjectSummary[]): Response {
  const headers = new Headers({
    'Content-Type':'application/json; charset=utf-8',
    'Cache-Control':'private, no-store, max-age=0',
    'Pragma':'no-cache',
    'X-Content-Type-Options':'nosniff',
    'Cross-Origin-Resource-Policy':'same-origin',
    'Referrer-Policy':'no-referrer',
    'Content-Security-Policy':"default-src 'none'",
    'Vary':'Authorization',
    'X-Correlation-Id':correlationId,
  });
  if (status === 405) headers.set('Allow','GET');
  const body = status === 200
    ? {ok:true,status:200,apiVersion:1,source:'signed-postgresql',data}
    : {ok:false,status,error:FAILURES[status]};
  // No tenant, actor, token, SQL, schema, DB details or raw upstream errors.
  return new Response(JSON.stringify(body),{status,headers});
}
export interface ProjectSummary {
  readonly id: string;
  readonly name: string;
  readonly status: 'active' | 'disabled';
}
function projectRows(
  rows: readonly SqlRow[], tenant: string, limit: number
): readonly ProjectSummary[] | null {
  if (!Array.isArray(rows) || rows.length > limit) return null;
  const ids = new Set<string>();
  const projects: ProjectSummary[] = [];
  for (const row of rows) {
    if (!row || typeof row !== 'object' || Array.isArray(row) ||
        Object.keys(row).sort().join(',') !== 'id,name,status,tenant_id' ||
        typeof row.id !== 'string' || !PROJECT_ID.test(row.id) ||
        row.tenant_id !== tenant || ids.has(row.id) ||
        typeof row.name !== 'string' || !row.name ||
        row.name.length > 120 || row.name.trim() !== row.name ||
        [...row.name].some(c => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127) ||
        typeof row.status !== 'string' || !VALID_STATUS.has(row.status)) {
      return null;
    }
    ids.add(row.id);
    projects.push(Object.freeze({
      id:row.id,name:row.name,status:row.status as ProjectSummary['status'],
    }));
  }
  return Object.freeze(projects);
}

/**
 * This module is a handler factory, not a deployment. It cannot accept an
 * omitted authorization-revision source or actor-only signed SQL fallback.
 * Only the signed PG read boundary decides which rows the client may see.
 */
export function createTenantProjectsReadHttpHandler(
  deps: TenantProjectsHttpDependencies
) {
  if (!deps || !validOrigin(deps.expectedOrigin) ||
      typeof deps.tokens?.verifyAccessToken !== 'function' ||
      typeof deps.actorDirectory?.resolveActorId !== 'function' ||
      typeof deps.actors?.lookup !== 'function' ||
      typeof deps.revisions?.readRevision !== 'function' ||
      typeof deps.signer?.sign !== 'function' ||
      typeof deps.pool?.connect !== 'function' ||
      typeof deps.pool?.quarantine !== 'function' ||
      typeof deps.audit?.record !== 'function' ||
      (deps.newCorrelationId !== undefined &&
       typeof deps.newCorrelationId !== 'function')) {
    throw new Error('Invalid tenant project read server dependencies');
  }
  // Pick dependencies explicitly: JS callers cannot turn off token-bound
  // PG sessions or sneak in staging write/outbox options via object spread.
  const pinned = Object.freeze({
    tokens:deps.tokens, actorDirectory:deps.actorDirectory,
    actors:deps.actors, pool:deps.pool, signer:deps.signer,
    revisions:deps.revisions, requireTokenBoundSession:true,
  } as const);
  const expectedOrigin = deps.expectedOrigin;
  return async function handle(request: Request): Promise<Response> {
    const supplied = deps.newCorrelationId?.();
    const correlationId = typeof supplied === 'string' && ID.test(supplied)
      ? supplied : crypto.randomUUID();
    function deny(status: FailureStatus, reason: SecurityAuditReason,
      collection: 'projects' | null = null): Response {
      try {
        deps.audit.record({
          correlationId,actorId:null,tenantId:null,collection,
          result:status === 503 ? 'error' : 'deny',reason,
        });
      } catch { return response(503,correlationId); }
      return response(status,correlationId);
    }
    try {
      if (!request || request.signal.aborted) return deny(503,'request-cancelled');
      // Fail closed even after factory setup if the ephemeral HTTP exemption
      // is turned off before a request reaches a loopback test listener.
      if (!validOrigin(expectedOrigin)) return deny(503,'source-unavailable');
      const url = new URL(request.url);
      if (url.origin !== expectedOrigin || url.username || url.password ||
          url.hash) return deny(404,'invalid-request');
      const match = PATH.exec(url.pathname);
      if (!match || !TENANT.test(match[1])) return deny(404,'invalid-request');
      if (request.method !== 'GET') return deny(405,'invalid-request','projects');
      if (INJECTED_HEADERS.some(name=>request.headers.has(name)) ||
          request.headers.get('sec-fetch-site') === 'cross-site' ||
          (request.headers.has('origin') &&
           request.headers.get('origin') !== expectedOrigin)) {
        return deny(403,'role-forbidden','projects');
      }
      let limit = 20;
      if (url.search) {
        const keys = [...url.searchParams.keys()];
        const values = url.searchParams.getAll('limit');
        if (keys.length !== 1 || keys[0] !== 'limit' ||
            values.length !== 1 || !/^(?:[1-9]|[1-4][0-9]|50)$/.test(values[0])) {
          return deny(404,'invalid-request','projects');
        }
        limit = Number(values[0]);
      }
      const auth = BEARER.exec(request.headers.get('authorization') ?? '');
      if (!auth) return deny(401,'unauthenticated','projects');

      // Delay the actual audit decision until AFTER the final public DTO
      // whitelist, abort check and all signed SQL/session checks. Nothing
      // is published until the durable caller-supplied synchronous audit
      // recorder succeeds. Its failure returns only a 503.
      const staged: {current: SecurityAuditDecision | null} = {current:null};
      const read = createTrustedSqlReadBoundary({
        ...pinned, newCorrelationId:()=>correlationId,
        audit:{record(decision){
          if (staged.current) throw new Error('Multiple read audit events');
          staged.current=decision;
        }},
      });
      const result = await read({
        accessToken:auth[1],tenantId:match[1],collection:'projects',
        limit,signal:request.signal,
      });
      if (request.signal.aborted) return deny(503,'request-cancelled','projects');
      const decision = staged.current;
      if (!decision || decision.correlationId !== correlationId) {
        return deny(503,'source-unavailable','projects');
      }
      if (!result.ok) {
        // Never copy driver/SQL/identity failures through to the client.
        try { deps.audit.record(decision); } catch {
          return response(503,correlationId);
        }
        if (![401,403,404,503].includes(result.status)) {
          return response(503,correlationId);
        }
        return response(result.status,correlationId);
      }
      const projects = projectRows(result.rows,match[1],limit);
      if (!projects || decision.result !== 'allow') {
        return deny(503,'source-unavailable','projects');
      }
      try { deps.audit.record(decision); } catch {
        return response(503,correlationId);
      }
      return response(200,correlationId,projects);
    } catch {
      // Do not emit raw exceptions or serialize untrusted tenant/project IDs.
      return deny(503,'source-unavailable');
    }
  };
}
