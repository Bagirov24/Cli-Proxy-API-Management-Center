/**
 * Backend slice 02: unmounted tenant-project POST/PATCH HTTP handler.
 *
 * Uses the established M1 project command authority and a private signed PG
 * writer. No network listener, production runtime wiring, SQL, issuer secrets
 * or keys are introduced by this module.
 *
 * 1. Verify bearer issuer/subject and current server-owned actor + tenant RBAC.
 * 2. Mint one server-only UUIDv4 attempt for each authorized write.
 * 3. Resolve server-held per-bearer session UUID+epoch (PG25 required).
 * 4. Obtain durable fsynced pre-COMMIT intent receipt BEFORE invoking PG.
 * 5. Delegate signed transaction scope, DB membership, project CAS, mandatory
 *    audit and attempt binding to the injected restricted PG writer.
 * 6. Bind the same server-derived bearer SHA-256 into the private PG26
 *    writer so the signed SQL transaction cannot borrow another session.
 * 7. Never retry after an uncertain COMMIT. A 503 is NOT proof of rollback.
 *
 * Neither TypeScript interfaces nor the existing synthetic M1 PG driver
 * attest production durability/off-host WORM or physical connection discard.
 */
import {
  createM1ProjectCommandBoundary,
  type M1ProjectDependencies, type M1ProjectMutation,
} from './m1ProjectCommandBoundary';

export interface TenantProjectWriteAttempt {
  readonly attemptId: string;
  readonly actorId: string;
  readonly tenantId: string;
  readonly projectId: string;
  readonly operation: 'create' | 'rename';
  readonly expectedVersion: number | null;
}

export interface TenantProjectPrecommitJournal {
  /** Must only resolve after durable, verifiable fsync; no auto repair. */
  prepare(input: Readonly<TenantProjectWriteAttempt>): Promise<{
    readonly attemptId: string;
    readonly sequence: number;
  }>;
}
export interface TenantProjectSignedWriter {
  /**
   * Executes only fixed SQL as least-privilege role, using a signed PG scope,
   * DB-side membership+CAS gates and atomic project/audit/attempt insert.
   * A throw/abort/UNKNOWN COMMIT must poison the physical connection/pool.
   * Do NOT retry or reissue attempts inside this method.
   */
  execute(input: Readonly<M1ProjectMutation & {
    readonly attemptId: string;
    /** PG25 requires this EXACT locked session in the same signed tx. */
    readonly sessionId: string;
    readonly sessionRevision: number;
    /**
     * SHA-256 of the twice-verified full bearer, computed server-side. The
     * PG26 writer MUST sign this exact value as scope.tokenFingerprint, set
     * saas.scope_token_fingerprint via SET LOCAL, and use the same current
     * PG25 session UUID/revision. Never take a fingerprint or jti from HTTP.
     */
    readonly tokenFingerprint: string;
  }>): Promise<boolean>;
}

/** Private per-bearer registry: never receives a raw JWT or untrusted ID. */
export interface TenantProjectWriteSessionAuthority {
  resolve(input: Readonly<{
    readonly actorId: string;
    readonly tenantId: string;
    /** SHA-256 of the verified access JWT, not caller-supplied jti. */
    readonly tokenFingerprint: string;
  }>, signal: AbortSignal): Promise<{
    readonly sessionId: string;
    readonly sessionRevision: number;
  } | null>;
}
export interface TenantProjectsWriteHttpDependencies
  extends Omit<M1ProjectDependencies, 'writer'> {
  /** Server configured, never selected from Host/X-Forwarded-* request. */
  readonly expectedOrigin: string;
  readonly journal: TenantProjectPrecommitJournal;
  /** Mandatory after SQL025: signed PG session proof must exist per mutation. */
  readonly sessions: TenantProjectWriteSessionAuthority;
  readonly writer: TenantProjectSignedWriter;
}

const SAFE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const UUIDV4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SAFE_CORRELATION = /^[A-Za-z0-9_-]{1,128}$/;
const POST = /^\/control-api\/v1\/tenants\/([A-Za-z0-9_-]{1,64})\/projects$/;
const PATCH = /^\/control-api\/v1\/tenants\/([A-Za-z0-9_-]{1,64})\/projects\/([A-Za-z0-9_-]{1,64})$/;
const BEARER = /^Bearer ([A-Za-z0-9._~-]{1,8192})$/;
const JSON_TYPE = /^application\/json(?:;\s*charset=utf-8)?$/i;
const MAX_BODY = 512;

const FAILURE = {
  401: {code:'UNAUTHENTICATED', message:'Authentication required'},
  403: {code:'FORBIDDEN', message:'Permission denied'},
  404: {code:'NOT_FOUND', message:'Resource unavailable'},
  405: {code:'METHOD_NOT_ALLOWED', message:'Method not allowed'},
  503: {code:'SOURCE_UNAVAILABLE', message:'Service unavailable'},
} as const;
type FailureStatus = keyof typeof FAILURE;
const BLOCKED_HEADERS = [
  'cookie','idempotency-key','x-attempt-id','x-request-id','x-session-id',
  'x-correlation-id','x-actor-id','x-role','x-tenant-id','x-project-id',
  'x-token-fingerprint','if-match','x-forwarded-user',
  'x-forwarded-role','x-forwarded-tenant',
] as const;

function ephemeralHttpCi(): boolean {
  const env = (globalThis as unknown as {
    process?: {env?: Record<string,string|undefined>};
  }).process?.env;
  return env?.GITHUB_ACTIONS === 'true' &&
    env.SAAS_PROJECT_WRITE_HTTP_CI === 'true' &&
    env.SAAS_EPHEMERAL_M1_PG_CI === 'true' &&
    env.PGHOST === '127.0.0.1' &&
    env.PGDATABASE === 'saas_ephemeral_test' &&
    env.NODE_ENV !== 'production' &&
    !env.RAILWAY_PROJECT_ID && !env.RAILWAY_ENVIRONMENT &&
    !env.RAILWAY_SERVICE_ID;
}
function pinnedOrigin(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 256) return false;
  try {
    const u = new URL(value);
    if (u.origin !== value || u.username || u.password ||
        u.search || u.hash) return false;
    return u.protocol === 'https:' ||
      (u.protocol === 'http:' && u.hostname === '127.0.0.1' &&
       ephemeralHttpCi());
  } catch { return false; }
}
function reply(status: 200|201|FailureStatus, correlationId: string,
  projectId?: string): Response {
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
  if (status === 405) headers.set('Allow','POST, PATCH');
  const body = status === 200 || status === 201
    ? {ok:true,status,apiVersion:1,source:'signed-postgresql',
      ...(status === 201 && projectId !== undefined ? {projectId} : {})}
    : {ok:false,status,error:FAILURE[status]};
  return new Response(JSON.stringify(body),{status,headers});
}
function safeName(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 1 ||
      value.length > 120 || value.trim() !== value) return false;
  for (let i=0; i<value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 32 || c === 127) return false;
  }
  return true;
}
async function boundedJson(request: Request):
  Promise<Record<string,unknown>|null> {
  const length = request.headers.get('content-length');
  if (length !== null &&
      (!/^(0|[1-9][0-9]{0,2})$/.test(length) ||
       Number(length) > MAX_BODY)) return null;
  if (!JSON_TYPE.test(request.headers.get('content-type')??'') ||
      !request.body) return null;
  const reader = request.body.getReader();
  const bytes = new Uint8Array(MAX_BODY);
  let count=0;
  try {
    for (;;) {
      if (request.signal.aborted) return null;
      const next = await reader.read();
      if (next.done) break;
      if (count + next.value.byteLength > MAX_BODY) {
        await reader.cancel();
        return null;
      }
      bytes.set(next.value,count);
      count += next.value.byteLength;
    }
    if (count === 0 ||
        (length !== null && count !== Number(length))) return null;
    const decoded = new TextDecoder('utf-8',{fatal:true})
      .decode(bytes.subarray(0,count));
    const parsed: unknown = JSON.parse(decoded);
    return parsed !== null && typeof parsed === 'object' &&
      !Array.isArray(parsed) ? parsed as Record<string,unknown> : null;
  } catch { return null; }
  finally { reader.releaseLock(); }
}

/** Non-mounting factory. External wiring must provide a governed signer/PG. */
export function createTenantProjectsWriteHttpHandler(
  deps: TenantProjectsWriteHttpDependencies
) {
  if (!deps || !pinnedOrigin(deps.expectedOrigin) ||
      typeof deps.tokens?.verifyAccessToken !== 'function' ||
      typeof deps.directory?.resolveActorId !== 'function' ||
      typeof deps.actors?.lookup !== 'function' ||
      typeof deps.journal?.prepare !== 'function' ||
      typeof deps.sessions?.resolve !== 'function' ||
      typeof deps.writer?.execute !== 'function' ||
      (deps.newCorrelationId !== undefined &&
       typeof deps.newCorrelationId !== 'function')) {
    throw new Error('Invalid tenant project write configuration');
  }
  const origin=deps.expectedOrigin;
  // Bound writer: the request and JWT can NEVER choose a UUID/attempt counter,
  // persist a precommit receipt, or bypass the existing M1 server actor gate.
  // Only an already-authorized M1 command can invoke this private writer.
  return async function handle(request: Request): Promise<Response> {
    const supplied = deps.newCorrelationId?.();
    const correlationId = typeof supplied === 'string' &&
      SAFE_CORRELATION.test(supplied) ? supplied : crypto.randomUUID();
    const respond=(status:200|201|FailureStatus,projectId?:string)=>
      reply(status,correlationId,projectId);
    try {
      if (!request || request.signal.aborted || !pinnedOrigin(origin))
        return respond(503);
      const url = new URL(request.url);
      if (url.origin !== origin || url.username || url.password ||
          url.search || url.hash) return respond(404);
      const createMatch=POST.exec(url.pathname);
      const renameMatch=PATCH.exec(url.pathname);
      if (!createMatch && !renameMatch) return respond(404);
      if ((request.method !== 'POST' || !createMatch) &&
          (request.method !== 'PATCH' || !renameMatch)) return respond(405);
      if (BLOCKED_HEADERS.some(name=>request.headers.has(name)) ||
          request.headers.get('sec-fetch-site') === 'cross-site' ||
          (request.headers.has('origin') &&
           request.headers.get('origin') !== origin)) return respond(403);
      const bearer = BEARER.exec(request.headers.get('authorization')??'');
      if (!bearer) return respond(401);
      const dto = await boundedJson(request);
      if (request.signal.aborted) return respond(503);
      if (!dto) return respond(404);
      const operation = createMatch ? 'create' : 'rename';
      if (!safeName(dto.name) ||
          (operation === 'create' &&
           Object.keys(dto).sort().join(',') !== 'name') ||
          (operation === 'rename' &&
           (Object.keys(dto).sort().join(',') !== 'expectedVersion,name' ||
            typeof dto.expectedVersion !== 'number' ||
            !Number.isSafeInteger(dto.expectedVersion) ||
            dto.expectedVersion < 1 ||
            dto.expectedVersion >= Number.MAX_SAFE_INTEGER))) return respond(404);
      const tenantId = (createMatch??renameMatch)![1];
      const projectId = createMatch ? crypto.randomUUID() : renameMatch![2];
      if (!SAFE_ID.test(projectId)) return respond(503);
      const signed = createM1ProjectCommandBoundary({
        tokens:deps.tokens,directory:deps.directory,actors:deps.actors,
        newCorrelationId:()=>correlationId,
        writer:{
          async execute(input) {
            if (request.signal.aborted) throw new Error('Request cancelled');
            if (input.operation !== 'create' && input.operation !== 'rename')
              throw new Error('Unsupported backend operation');
            // The bearer was independently verified twice by the M1 actor
            // boundary BEFORE this private writer can run. The token's own
            // fingerprint, NOT its jti nor any request header, indexes the
            // server-owned session registry. SQL025 rechecks status/epoch
            // under FOR SHARE in the SAME signed PG16 write transaction.
            const bytes = new Uint8Array(await crypto.subtle.digest(
              'SHA-256', new TextEncoder().encode(bearer[1])
            ));
            const tokenFingerprint = Array.from(bytes,b=>
              b.toString(16).padStart(2,'0')).join('');
            if (request.signal.aborted) throw new Error('Request cancelled');
            const session = await deps.sessions.resolve(Object.freeze({
              actorId:input.scope.actorId,tenantId:input.scope.tenantId,
              tokenFingerprint,
            }),request.signal);
            if (request.signal.aborted || !session ||
                !UUIDV4.test(session.sessionId) ||
                !Number.isSafeInteger(session.sessionRevision) ||
                session.sessionRevision < 1 ||
                session.sessionRevision >= Number.MAX_SAFE_INTEGER) {
              throw new Error('Trusted project session missing or stale');
            }
            const attemptId = crypto.randomUUID();
            if (!UUIDV4.test(attemptId)) throw new Error('Invalid server attempt');
            const entry=Object.freeze({
              attemptId,actorId:input.scope.actorId,
              tenantId:input.scope.tenantId,
              projectId:input.projectId,operation:input.operation,
              expectedVersion:input.expectedVersion??null,
            });
            // No attempt may touch PostgreSQL until an external signer has
            // durably sealed its *server-issued* attempt identity.
            const receipt=await deps.journal.prepare(entry);
            if (request.signal.aborted || !receipt ||
                receipt.attemptId !== attemptId ||
                !Number.isSafeInteger(receipt.sequence) ||
                receipt.sequence < 1) {
              throw new Error('Missing durable attempt acknowledgement');
            }
            // Exact issued UUID passed to PG M1g audit binding; failures,
            // including UNKNOWN after COMMIT, MUST NOT be retried here.
            return deps.writer.execute(Object.freeze({
              ...input,attemptId,tokenFingerprint,
              sessionId:session.sessionId,sessionRevision:session.sessionRevision,
            }));
          },
        },
      });
      const result=await signed(operation==='create'
        ? {operation:'create',accessToken:bearer[1],tenantId,projectId,
          name:dto.name as string,signal:request.signal}
        : {operation:'rename',accessToken:bearer[1],tenantId,projectId,
          name:dto.name as string,expectedVersion:dto.expectedVersion as number,
          signal:request.signal});
      if (request.signal.aborted) return respond(503);
      if (!result.ok) return respond(result.status);
      if (result.status !== (operation==='create'?201:200))
        return respond(503);
      return respond(result.status,operation==='create'?projectId:undefined);
    } catch {
      // Raw SQL, signer, attempt, issuer and COMMIT exception text is secret.
      return respond(503);
    }
  };
}
