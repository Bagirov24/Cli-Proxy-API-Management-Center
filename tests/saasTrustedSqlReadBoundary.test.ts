import { beforeAll, describe, expect, test } from 'bun:test';
import {
  createSecurityAuditRecorder, createSyntheticAuditBuffer,
  type SecurityAuditSink,
} from '../src/features/saasBlueprint/controlApi/server/securityAudit';
import type {
  ControlActor, TenantMembership,
} from '../src/features/saasBlueprint/controlApi/contracts';
import {
  createPinnedAccessTokenVerifier,
} from '../src/features/saasBlueprint/controlApi/server/trustedAccessToken';
import {
  createPinnedHmacScopeIssuer, CONTROL_READ_SELECT_SQL, SCOPED_READ_GATE_SQL,
  type ScopedSqlPool, type SignedTransactionIssuer, type SqlValue,
} from '../src/features/saasBlueprint/controlApi/server/signedSqlBoundary';
import {
  createTrustedSqlReadBoundary, type TrustedSqlReadRequest,
} from '../src/features/saasBlueprint/controlApi/server/trustedSqlReadBoundary';
import type {
  ServerAuthorizationRevisionSource,
} from '../src/features/saasBlueprint/controlApi/server/authorizationRevision';

const issuer = 'https://synthetic-issuer.example.test/oauth';
const audience = 'saas-control-api';
const now = 1_800_000_000;
const correlationId = 'server-trace-2g2';
let rsa: CryptoKeyPair;
let signer: SignedTransactionIssuer;

const membership = (
  tenantId: string, role: TenantMembership['role'] = 'tenant-viewer',
  status: TenantMembership['status'] = 'active'
): TenantMembership => ({ tenantId, role, status });

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function accessToken(
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {}
): Promise<string> {
  const h = base64url(new TextEncoder().encode(JSON.stringify({
    typ: 'at+jwt', alg: 'RS256', kid: 'synthetic-key', ...header,
  })));
  const payload = base64url(new TextEncoder().encode(JSON.stringify({
    iss: issuer, sub: 'sub-north', aud: audience,
    iat: now - 50, exp: now + 100, ...claims,
  })));
  const signature = new Uint8Array(await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', rsa.privateKey,
    new TextEncoder().encode(h + '.' + payload)
  ));
  return h + '.' + payload + '.' + base64url(signature);
}

interface TestHarnessOptions {
  readonly onSelect?: () => Promise<void> | void;
  readonly failSelect?: boolean;
  readonly rows?: readonly Record<string, unknown>[];
  readonly rowsBySelect?: readonly (readonly Record<string, unknown>[])[];
  readonly gateAnswers?: readonly boolean[];
  readonly auditSink?: SecurityAuditSink;
  readonly revisions?: ServerAuthorizationRevisionSource;
  readonly onCommit?: (count: number) => Promise<void> | void;
  readonly onActorLookup?: (count: number) => void;
}

function harness(options: TestHarnessOptions = {}) {
  const actors = new Map<string, ControlActor>([
    ['actor-north', { id: 'actor-north', memberships: [membership('demo-north')] }],
    ['actor-orbit', { id: 'actor-orbit', memberships: [membership('demo-orbit')] }],
    ['actor-auditor', {
      id: 'actor-auditor', memberships: [membership('demo-north', 'tenant-auditor')],
    }],
  ]);
  const directory = new Map<string, string>([
    [issuer + ':sub-north', 'actor-north'],
    [issuer + ':sub-orbit', 'actor-orbit'],
    [issuer + ':sub-auditor', 'actor-auditor'],
  ]);
  const queries: { readonly sql: string; readonly params: readonly SqlValue[] }[] = [];
  const released: boolean[] = [];
  const quarantines: string[] = [];
  const auditBuffer = createSyntheticAuditBuffer();
  const audit = createSecurityAuditRecorder(options.auditSink ?? auditBuffer, {
    classification: 'synthetic', nowMs: () => 1_800_000_000_000,
  });
  let acquired = 0;
  let gateIndex = 0;
  let selectIndex = 0;
  let commitCount = 0;
  let actorLookupCount = 0;
  let poisoned = false;
  const pool: ScopedSqlPool = {
    quarantine(reason) { quarantines.push(reason); poisoned = true; },
    async connect() {
      if (poisoned) throw new Error('Closed pool');
      acquired += 1;
      return {
        async query(sql, params) {
          queries.push({ sql, params });
          if (sql === 'COMMIT') {
            await options.onCommit?.(++commitCount);
          }
          if (sql === 'SELECT txid_current()::text AS transaction_id') {
            return { rows: [{ transaction_id: '424242' }] };
          }
          if (sql === SCOPED_READ_GATE_SQL) {
            return { rows: [{ allowed: options.gateAnswers?.[gateIndex++] ?? true }] };
          }
          if (sql.startsWith('SELECT id, ')) {
            await options.onSelect?.();
            if (options.failSelect) throw new Error('DB_PASSWORD_NEVER_LOG');
            const tenant = String(params[0]);
            return { rows: options.rowsBySelect?.[selectIndex++] ?? options.rows ?? [{
              id: tenant === 'demo-north' ? 'north-project' : 'orbit-project',
              tenant_id: tenant, name: 'Synthetic project',
              status: 'active', token_secret: 'MUST_NOT_RETURN',
            }] };
          }
          return { rows: [] };
        },
        release(discard) { released.push(discard); },
      };
    },
  };
  const verifier = createPinnedAccessTokenVerifier({
    issuer, audience, publicKeys: new Map([['synthetic-key', rsa.publicKey]]),
    nowSeconds: () => now,
  });
  const read = createTrustedSqlReadBoundary({
    tokens: verifier,
    actorDirectory: {
      async resolveActorId(identity) {
        return directory.get(identity.issuer + ':' + identity.subject) ?? null;
      },
    },
    actors: {
      async lookup(actorId, signal) {
        options.onActorLookup?.(++actorLookupCount);
        if (signal.aborted) throw new Error('Aborted actor lookup');
        return actors.get(actorId) ?? null;
      },
    },
    pool, signer, audit, revisions: options.revisions,
    newCorrelationId: () => correlationId,
  });
  const request = (
    accessTokenValue: string, overrides: Partial<TrustedSqlReadRequest> = {}
  ): TrustedSqlReadRequest => ({
    accessToken: accessTokenValue, tenantId: 'demo-north',
    collection: 'projects', signal: new AbortController().signal,
    ...overrides,
  });
  return {
    read, request, actors, directory, queries, released, quarantines,
    auditEvents: () => auditBuffer.snapshot(),
    get acquired() { return acquired; },
  };
}

beforeAll(async () => {
  rsa = await crypto.subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
  }, true, ['sign', 'verify']) as CryptoKeyPair;
  const key = await crypto.subtle.importKey(
    'raw', crypto.getRandomValues(new Uint8Array(32)),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  signer = createPinnedHmacScopeIssuer(key);
});

describe('Stage 2G.2 — trusted JWT -> actor -> AuthZ -> signed SQL (synthetic only)', () => {
  test('accepts North metadata only after server-held identity/RBAC, signs scope and strips secrets', async () => {
    const h = harness();
    const result = await h.read(h.request(await accessToken(), { limit: 7 }));
    expect(result).toEqual({
      ok: true, status: 200, source: 'staging-signed-rls',
      correlationId, tenantId: 'demo-north', collection: 'projects',
      rows: [{ id: 'north-project', tenant_id: 'demo-north',
        name: 'Synthetic project', status: 'active' }],
    });
    expect(JSON.stringify(result)).not.toContain('MUST_NOT_RETURN');
    expect(h.acquired).toBe(2);
    expect(h.released).toEqual([false, false]);
    expect(h.quarantines).toEqual([]);
    expect(h.auditEvents()).toEqual([{
      version: 1, occurredAt: '2027-01-15T08:00:00.000Z',
      source: 'trusted-sql-read-boundary', classification: 'synthetic',
      operation: 'saas.metadata.read', correlationId,
      actorId: 'actor-north', tenantId: 'demo-north', collection: 'projects',
      result: 'allow', reason: 'read-allowed',
    }]);
    const sql = h.queries.map(x => x.sql).join(' ');
    expect(sql).not.toContain('actor-north');
    expect(sql).not.toContain('demo-north');
    expect(h.queries.at(0)?.sql).toBe('BEGIN');
    expect(h.queries.at(-1)?.sql).toBe('COMMIT');
    expect(h.queries.filter(q => q.sql.startsWith('SELECT set_config')).length).toBe(10);
    expect(h.queries.filter(q => q.sql === CONTROL_READ_SELECT_SQL.projects)).toHaveLength(2);
    expect(h.queries.find(q => q.sql === CONTROL_READ_SELECT_SQL.projects)?.params)
      .toEqual(['demo-north', 7]);
    const claims = new Map(h.queries.filter(q => q.sql.startsWith('SELECT set_config'))
      .map(q => [String(q.params[0]), String(q.params[1])]));
    expect(claims.get('saas.scope_actor')).toBe('actor-north');
    expect(claims.get('saas.scope_tenant')).toBe('demo-north');
    const signedExpiry = Number(claims.get('saas.scope_expiry'));
    expect(Number.isSafeInteger(signedExpiry)).toBe(true);
    expect(signedExpiry).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(claims.get('saas.scope_mac')).toBe(await signer.sign({
      actorId: 'actor-north', tenantId: 'demo-north', role: 'tenant-viewer',
      correlationId,
    }, '424242', signedExpiry));
  });

  test('Orbit uses its own mapping, scope and parameterized tenant, not the caller role', async () => {
    const h = harness();
    const result = await h.read(h.request(await accessToken({
      sub: 'sub-orbit', role: 'tenant-owner', actorId: 'actor-north',
      tenantId: 'demo-north',
    }), { tenantId: 'demo-orbit' }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.rows.map(row => row.id)).toEqual(['orbit-project']);
      expect(result.tenantId).toBe('demo-orbit');
    }
    expect(h.queries.find(q => q.sql === CONTROL_READ_SELECT_SQL.projects)?.params)
      .toEqual(['demo-orbit', 50]);
    expect(h.queries.find(q => q.params[0] === 'saas.scope_actor')?.params[1])
      .toBe('actor-orbit');
  });

  test('North -> Orbit and Orbit -> North deny without SQL or foreign resource IDs', async () => {
    for (const [subject, tenantId] of [
      ['sub-north', 'demo-orbit'], ['sub-orbit', 'demo-north'],
    ]) {
      const h = harness();
      const result = await h.read(h.request(await accessToken({ sub: subject }), { tenantId }));
      expect(result).toEqual({
        ok: false, status: 404, correlationId,
        error: { code: 'NOT_FOUND', message: 'Resource unavailable' },
      });
      expect(h.acquired).toBe(0);
      expect(JSON.stringify(result)).not.toContain(tenantId);
    }
  });

  test('auditor cannot read accounts; missing, revoked and duplicate memberships deny', async () => {
    const h = harness();
    const auditor = await accessToken({ sub: 'sub-auditor' });
    const blocked = await h.read(h.request(auditor, { collection: 'accounts' }));
    expect(blocked).toMatchObject({ ok: false, status: 403 });
    expect(h.acquired).toBe(0);
    const allowed = await h.read(h.request(auditor));
    expect(allowed.ok).toBe(true);
    for (const memberships of [
      [], [membership('demo-north', 'tenant-viewer', 'revoked')],
      [membership('demo-north'), membership('demo-north', 'tenant-owner')],
    ]) {
      h.actors.set('actor-north', { id: 'actor-north', memberships });
      const denied = await h.read(h.request(await accessToken()));
      expect(denied).toMatchObject({ ok: false, status: 404 });
    }
    expect(h.acquired).toBe(2);
  });

  test('forged JWT actor/role/tenant and extra request headers cannot elevate rights', async () => {
    const h = harness();
    const forged = await accessToken({
      actorId: 'actor-orbit', role: 'tenant-owner', tenantId: 'demo-orbit',
      memberships: [{ tenantId: 'demo-orbit', role: 'tenant-owner' }],
    });
    const request = { ...h.request(forged, { tenantId: 'demo-orbit' }),
      actorId: 'actor-orbit', role: 'tenant-owner', headers: {
        'X-Actor-ID': 'actor-orbit', 'X-Tenant-ID': 'demo-orbit',
        'X-Role': 'tenant-owner',
      } };
    expect(await h.read(request)).toMatchObject({ ok: false, status: 404 });
    expect(h.acquired).toBe(0);
  });

  test('foreign audience, unknown kid/issuer, ID-token and unknown subject are rejected', async () => {
    const h = harness();
    const bad = [
      await accessToken({ aud: 'other-api' }),
      await accessToken({ iss: 'https://unknown.example.test' }),
      await accessToken({}, { kid: 'unknown-key' }),
      await accessToken({}, { typ: 'JWT' }),
      await accessToken({ sub: 'unregistered' }),
      await accessToken({}, { alg: 'none' }),
      'raw_bad_token',
    ];
    for (const token of bad) {
      expect(await h.read(h.request(token))).toMatchObject({
        ok: false, status: 401, error: { code: 'UNAUTHENTICATED' },
      });
    }
    expect(h.acquired).toBe(0);
  });

  test('actor removed from trusted directory revokes a previously valid JWT', async () => {
    const h = harness();
    const token = await accessToken();
    expect((await h.read(h.request(token))).ok).toBe(true);
    h.directory.delete(issuer + ':sub-north');
    expect(await h.read(h.request(token))).toMatchObject({
      ok: false, status: 401,
    });
    expect(h.acquired).toBe(2);
  });

  test('membership revoked or downgraded during SQL cannot return a stale result', async () => {
    for (const changed of [
      [membership('demo-north', 'tenant-viewer', 'revoked')],
      [membership('demo-north', 'tenant-owner')],
      [membership('demo-orbit', 'tenant-viewer')],
    ]) {
      const h: ReturnType<typeof harness> = harness({ onSelect() {
        h.actors.set('actor-north', { id: 'actor-north', memberships: changed });
      } });
      const result = await h.read(h.request(await accessToken()));
      expect(result).toMatchObject({ ok: false, status: 404 });
      expect(JSON.stringify(result)).not.toContain('north-project');
      expect(h.acquired).toBe(2);
    }
  });

  test('issuer/subject actor mapping revoked during SQL invalidates the response', async () => {
    const h: ReturnType<typeof harness> = harness({ onSelect() { h.directory.delete(issuer + ':sub-north'); } });
    const result = await h.read(h.request(await accessToken()));
    expect(result).toMatchObject({ ok: false, status: 401 });
    expect(JSON.stringify(result)).not.toContain('north-project');
  });

  test('tenant switch aborts in-flight SQL and never returns stale rows', async () => {
    const controller = new AbortController();
    const h = harness({ onSelect() { controller.abort(); } });
    const result = await h.read(h.request(await accessToken(), {
      signal: controller.signal,
    }));
    expect(result).toMatchObject({ ok: false, status: 503 });
    expect(JSON.stringify(result)).not.toContain('north-project');
    expect(h.released).toEqual([true]);
    expect(h.quarantines).toContain('read-failed');
  });

  test('DB suspension/revocation overrides a stale active server actor snapshot', async () => {
    const h = harness({ gateAnswers: [false] });
    const result = await h.read(h.request(await accessToken()));
    expect(result).toMatchObject({
      ok: false, status: 404, error: { code: 'NOT_FOUND' },
    });
    expect(JSON.stringify(result)).not.toContain('north-project');
    expect(JSON.stringify(result)).not.toContain('demo-north');
    expect(h.queries.filter(q => q.sql === SCOPED_READ_GATE_SQL)).toHaveLength(1);
    expect(h.queries.some(q => q.sql.startsWith('SELECT id, '))).toBe(false);
    expect(h.queries.at(-1)?.sql).toBe('ROLLBACK');
    expect(h.released).toEqual([false]);
    expect(h.quarantines).toEqual([]);
    expect(h.auditEvents()).toMatchObject([{
      result: 'deny', reason: 'authorization-changed',
      actorId: 'actor-north', tenantId: null,
    }]);
  });

  test('database authorization change after SELECT revokes output, not DB connection', async () => {
    const h = harness({ gateAnswers: [true, false] });
    const result = await h.read(h.request(await accessToken()));
    expect(result).toMatchObject({ ok: false, status: 404 });
    expect(JSON.stringify(result)).not.toContain('north-project');
    expect(h.queries.filter(q => q.sql === SCOPED_READ_GATE_SQL)).toHaveLength(2);
    expect(h.queries.some(q => q.sql === 'COMMIT')).toBe(false);
    expect(h.queries.at(-1)?.sql).toBe('ROLLBACK');
    expect(h.released).toEqual([false]);
    expect(h.auditEvents()).toMatchObject([{
      result: 'deny', reason: 'authorization-changed', tenantId: null,
    }]);
  });

  test('post-COMMIT PostgreSQL suspension/revocation denies a stale successful first read', async () => {
    // 2 gate checks for the first committed SELECT; in the fresh signed
    // transaction the database changes its answer to false.
    const h = harness({ gateAnswers: [true, true, false] });
    const result = await h.read(h.request(await accessToken()));
    expect(result).toMatchObject({
      ok: false, status: 404, error: { code: 'NOT_FOUND' },
    });
    expect(JSON.stringify(result)).not.toContain('north-project');
    expect(JSON.stringify(result)).not.toContain('demo-north');
    expect(h.queries.filter(q => q.sql === CONTROL_READ_SELECT_SQL.projects)).toHaveLength(1);
    expect(h.queries.filter(q => q.sql === SCOPED_READ_GATE_SQL)).toHaveLength(3);
    expect(h.released).toEqual([false, false]);
    expect(h.quarantines).toEqual([]);
    expect(h.auditEvents()).toMatchObject([{
      result: 'deny', reason: 'authorization-changed',
      actorId: 'actor-north', tenantId: null,
    }]);
  });

  test('post-COMMIT grant revocation changes the row set and invalidates old metadata', async () => {
    const shared = {
      id: 'shared-account', kind: 'account', owner_kind: 'platform',
      owner_tenant_id: null, status: 'active',
    };
    const owned = {
      id: 'north-account', kind: 'account', owner_kind: 'tenant',
      owner_tenant_id: 'demo-north', status: 'active',
    };
    const h = harness({ rowsBySelect: [[owned, shared], [owned]] });
    const response = await h.read(h.request(await accessToken(), { collection: 'accounts' }));
    expect(response).toMatchObject({ ok: false, status: 404 });
    expect(JSON.stringify(response)).not.toContain('shared-account');
    expect(h.queries.filter(q => q.sql === CONTROL_READ_SELECT_SQL.accounts)).toHaveLength(2);
    expect(h.released).toEqual([false, false]);
    expect(h.quarantines).toEqual([]);
    expect(h.auditEvents()).toMatchObject([{
      result: 'deny', reason: 'authorization-changed', tenantId: null,
    }]);
    expect(JSON.stringify(h.auditEvents())).not.toContain('shared-account');
  });

  test('cancellation during the second signed transaction discards stale output and pool', async () => {
    const controller = new AbortController();
    let selects = 0;
    const h = harness({ onSelect() {
      selects++;
      if (selects === 2) controller.abort();
    } });
    const result = await h.read(h.request(await accessToken(), {
      signal: controller.signal,
    }));
    expect(result).toMatchObject({ ok: false, status: 503 });
    expect(JSON.stringify(result)).not.toContain('north-project');
    expect(h.released).toEqual([false, true]);
    expect(h.quarantines).toContain('read-failed');
    expect(h.auditEvents()).toMatchObject([{
      result: 'error', reason: 'request-cancelled', tenantId: null,
    }]);
  });

  test('snapshot of request tenant, collection and limit survives caller mutation during SELECT', async () => {
    const h = harness({ onSelect() {
      const mutable = request as unknown as {
        tenantId: string; collection: string; limit: number;
      };
      mutable.tenantId = 'demo-orbit';
      mutable.collection = 'accounts';
      mutable.limit = 100;
    } });
    const request = h.request(await accessToken(), { limit: 3 });
    const result = await h.read(request);
    expect(result).toMatchObject({
      ok: true, status: 200, collection: 'projects', tenantId: 'demo-north',
    });
    const statements = h.queries.filter(q => q.sql === CONTROL_READ_SELECT_SQL.projects);
    expect(statements).toHaveLength(2);
    expect(statements.map(q => q.params)).toEqual([
      ['demo-north', 3], ['demo-north', 3],
    ]);
    expect(h.queries.some(q => q.sql === CONTROL_READ_SELECT_SQL.accounts)).toBe(false);
    expect(h.auditEvents()).toMatchObject([{
      result: 'allow', tenantId: 'demo-north', collection: 'projects',
    }]);
  });

  test('a compromised SQL adapter cannot smuggle another tenant row into output', async () => {
    const h = harness({ rows: [{
      id: 'orbit-private-project', tenant_id: 'demo-orbit',
      name: 'Forbidden project', status: 'active',
    }] });
    const result = await h.read(h.request(await accessToken()));
    expect(result).toMatchObject({ ok: false, status: 503 });
    expect(JSON.stringify(result)).not.toContain('orbit-private-project');
    expect(h.quarantines).toContain('read-failed');
    expect(h.released).toEqual([true]);
  });

  test('poisoned SQL source fails closed without leaking driver errors or credentials', async () => {
    const h = harness({ failSelect: true });
    const result = await h.read(h.request(await accessToken()));
    expect(result).toEqual({
      ok: false, status: 503, correlationId,
      error: { code: 'SOURCE_UNAVAILABLE', message: 'Service unavailable' },
    });
    expect(JSON.stringify(result)).not.toContain('DB_PASSWORD_NEVER_LOG');
    expect(h.quarantines).toContain('read-failed');
    expect(h.released).toEqual([true]);
  });

  test('audit hides foreign tenant and all untrusted claims on a denied cross-tenant read', async () => {
    const h = harness();
    const bad = await accessToken({
      actorId: 'actor-orbit', role: 'tenant-owner', tenantId: 'demo-orbit',
    });
    const result = await h.read(h.request(bad, { tenantId: 'demo-orbit' }));
    expect(result).toMatchObject({ ok: false, status: 404 });
    expect(h.auditEvents()).toMatchObject([{
      actorId: 'actor-north', tenantId: null, collection: 'projects',
      classification: 'synthetic', result: 'deny', reason: 'tenant-hidden',
    }]);
    const serialized = JSON.stringify(h.auditEvents());
    expect(serialized).not.toContain('demo-orbit');
    expect(serialized).not.toContain('tenant-owner');
    expect(serialized).not.toContain(bad);
    expect(h.acquired).toBe(0);
  });

  test('invalid identity generates a tenantless audit denial without secrets', async () => {
    const h = harness();
    const invalid = await accessToken({ aud: 'wrong-audience', tenantId: 'secret-tenant' });
    const response = await h.read(h.request(invalid));
    expect(response).toMatchObject({ ok: false, status: 401 });
    expect(h.auditEvents()).toMatchObject([{
      actorId: null, tenantId: null, result: 'deny', reason: 'unauthenticated',
    }]);
    const serialized = JSON.stringify(h.auditEvents());
    expect(serialized).not.toContain(invalid);
    expect(serialized).not.toContain('secret-tenant');
  });

  test('audit marks mid-SQL revocation with safe reason and no tenant ID', async () => {
    const h: ReturnType<typeof harness> = harness({ onSelect() {
      h.actors.set('actor-north', {
        id: 'actor-north',
        memberships: [membership('demo-north', 'tenant-viewer', 'revoked')],
      });
    } });
    const result = await h.read(h.request(await accessToken()));
    expect(result).toMatchObject({ ok: false, status: 404 });
    expect(h.auditEvents()).toMatchObject([{
      actorId: 'actor-north', tenantId: null,
      result: 'deny', reason: 'authorization-changed',
    }]);
    expect(JSON.stringify(h.auditEvents())).not.toContain('north-project');
  });

  test('audit records cancellation without leaked tenant, SQL or token data', async () => {
    const controller = new AbortController();
    const h = harness({ onSelect() { controller.abort(); } });
    const token = await accessToken();
    const result = await h.read(h.request(token, { signal: controller.signal }));
    expect(result).toMatchObject({ ok: false, status: 503 });
    expect(h.auditEvents()).toMatchObject([{
      actorId: 'actor-north', tenantId: null,
      result: 'error', reason: 'request-cancelled',
    }]);
    expect(JSON.stringify(h.auditEvents())).not.toContain(token);
    expect(JSON.stringify(h.auditEvents())).not.toContain('SELECT');
  });

  test('failed audit sink causes generic 503 even after a successful SQL read', async () => {
    const h = harness({
      auditSink: { write() { throw new Error('SYNTHETIC_REFRESH_TOKEN_DO_NOT_LOG'); } },
    });
    const result = await h.read(h.request(await accessToken()));
    expect(result).toEqual({
      ok: false, status: 503, correlationId,
      error: { code: 'SOURCE_UNAVAILABLE', message: 'Service unavailable' },
    });
    expect(JSON.stringify(result)).not.toContain('SYNTHETIC_REFRESH_TOKEN');
    expect(JSON.stringify(result)).not.toContain('north-project');
    expect(h.acquired).toBe(2);
    expect(h.released).toEqual([false, false]);
  });

  test('SQL-like input, malformed limits and aborted calls never acquire a connection', async () => {
    const h = harness();
    const token = await accessToken();
    for (const fields of [
      { tenantId: "demo-north'; DROP TABLE grants;--" },
      { collection: '__proto__' as TrustedSqlReadRequest['collection'] },
      { limit: -1 },
      { limit: 1_000 },
    ]) {
      expect(await h.read(h.request(token, fields))).toMatchObject({
        ok: false, status: 404,
      });
    }
    const controller = new AbortController();
    controller.abort();
    expect(await h.read(h.request(token, { signal: controller.signal })))
      .toMatchObject({ ok: false, status: 503 });
    expect(h.acquired).toBe(0);
  });
});

function syntheticRevision(initial: unknown = '7') {
  let current: unknown = initial;
  const checked: { actorId: string; tenantId: string }[] = [];
  const source: ServerAuthorizationRevisionSource = {
    async readRevision(scope, signal) {
      if (signal.aborted) throw new Error('Synthetic abort');
      checked.push({ ...scope });
      return current;
    },
  };
  return { source, checked, set(next: unknown) { current = next; } };
}

describe('Stage 2G.4d — opt-in server-owned revision guard (SYNTHETIC)', () => {
  test('stable server revision allows, stays out of response/audit and uses trusted scope', async () => {
    const rev = syntheticRevision();
    const h = harness({ revisions: rev.source });
    const result = await h.read(h.request(await accessToken()));
    expect(result).toMatchObject({ ok: true, status: 200, tenantId: 'demo-north' });
    expect(rev.checked).toEqual([
      { actorId: 'actor-north', tenantId: 'demo-north' },
      { actorId: 'actor-north', tenantId: 'demo-north' },
    ]);
    expect(JSON.stringify(result)).not.toContain('authorizationRevision');
    expect(JSON.stringify(h.auditEvents())).not.toContain('"7"');
    expect(h.acquired).toBe(2);
    expect(h.quarantines).toEqual([]);
  });

  test('grant revision bump during SELECT denies old rows without poisoning safe SQL', async () => {
    const rev = syntheticRevision();
    const h = harness({ revisions: rev.source, onSelect() { rev.set('8'); } });
    const denied = await h.read(h.request(await accessToken()));
    expect(denied).toMatchObject({ ok: false, status: 404 });
    expect(JSON.stringify(denied)).not.toContain('north-project');
    expect(h.released).toEqual([false, false]);
    expect(h.quarantines).toEqual([]);
    expect(h.auditEvents()).toMatchObject([{
      result: 'deny', reason: 'authorization-changed', tenantId: null,
    }]);
    // A new request takes a fresh baseline; previously safe reservations
    // remain reusable after a business authorization denial.
    const fresh = await h.read(h.request(await accessToken()));
    expect(fresh).toMatchObject({ ok: true, status: 200 });
    expect(h.released).toEqual([false, false, false, false]);
  });

  test('revision bump AFTER first COMMIT is denied even when rows are unchanged', async () => {
    const rev = syntheticRevision();
    const h = harness({
      revisions: rev.source, onCommit(count) { if (count === 1) rev.set('8'); },
    });
    const result = await h.read(h.request(await accessToken()));
    expect(result).toMatchObject({ ok: false, status: 404 });
    expect(h.queries.filter(q => q.sql === 'COMMIT')).toHaveLength(2);
    expect(h.queries.filter(q => q.sql === CONTROL_READ_SELECT_SQL.projects)).toHaveLength(2);
    expect(h.auditEvents()).toMatchObject([{
      reason: 'authorization-changed', tenantId: null,
    }]);
  });

  test('last actor recheck may change revision; final guard rejects before Allow', async () => {
    const rev = syntheticRevision();
    const h = harness({
      revisions: rev.source,
      onActorLookup(count) { if (count === 2) rev.set('8'); },
    });
    const result = await h.read(h.request(await accessToken()));
    expect(result).toMatchObject({ ok: false, status: 404 });
    expect(rev.checked).toHaveLength(2);
    expect(JSON.stringify(result)).not.toContain('north-project');
  });

  test('untrusted JWT/request revision cannot override the server-owned revision', async () => {
    const rev = syntheticRevision();
    const h = harness({ revisions: rev.source });
    const token = await accessToken({ authorizationRevision: '999999',
      tenantId: 'demo-orbit', role: 'tenant-owner' });
    const request = { ...h.request(token), authorizationRevision: '999999',
      revision: '999999' };
    const result = await h.read(request);
    expect(result).toMatchObject({ ok: true, status: 200, tenantId: 'demo-north' });
    expect(rev.checked).toHaveLength(2);
    expect(rev.checked.every(scope => scope.tenantId === 'demo-north')).toBe(true);
    expect(JSON.stringify(result)).not.toContain('999999');
    expect(JSON.stringify(h.auditEvents())).not.toContain('999999');
  });

  test('cross-tenant IDOR is rejected BEFORE the revision source is consulted', async () => {
    const rev = syntheticRevision();
    const h = harness({ revisions: rev.source });
    const response = await h.read(h.request(await accessToken(), {
      tenantId: 'demo-orbit',
    }));
    expect(response).toMatchObject({ ok: false, status: 404 });
    expect(rev.checked).toHaveLength(0);
    expect(h.acquired).toBe(0);
    expect(JSON.stringify(response)).not.toContain('demo-orbit');
  });

  test('absent, noncanonical, overflow and failed revision storage deny as 503', async () => {
    for (const invalid of [null, '07', '-1', '9223372036854775808', 7, '']) {
      const rev = syntheticRevision(invalid);
      const h = harness({ revisions: rev.source });
      const result = await h.read(h.request(await accessToken()));
      expect(result).toMatchObject({ ok: false, status: 503 });
      expect(h.acquired).toBe(0);
      expect(h.auditEvents()).toMatchObject([{ tenantId: null, result: 'error' }]);
    }
    const h = harness({ revisions: { async readRevision() {
      throw new Error('PRIVATE_DATABASE_PASSWORD_NEVER_RETURN');
    } } });
    const response = await h.read(h.request(await accessToken()));
    expect(response).toMatchObject({ ok: false, status: 503 });
    expect(JSON.stringify(response)).not.toContain('PRIVATE_DATABASE_PASSWORD');
    expect(JSON.stringify(h.auditEvents())).not.toContain('PRIVATE_DATABASE_PASSWORD');
    expect(h.acquired).toBe(0);
  });

  test('revision storage lost only AFTER SQL still denies all previously read rows', async () => {
    let calls = 0;
    const h = harness({ revisions: { async readRevision() {
      return ++calls === 1 ? '7' : null;
    } } });
    const result = await h.read(h.request(await accessToken()));
    expect(result).toMatchObject({ ok: false, status: 503 });
    expect(h.acquired).toBe(2);
    expect(h.released).toEqual([false, false]);
    expect(JSON.stringify(result)).not.toContain('north-project');
    expect(h.auditEvents()).toMatchObject([{
      result: 'error', reason: 'source-unavailable', tenantId: null,
    }]);
  });

  test('request cancellation during the revision read denies before SQL', async () => {
    const controller = new AbortController();
    const h = harness({ revisions: { async readRevision() {
      controller.abort();
      return '7';
    } } });
    const result = await h.read(h.request(await accessToken(), {
      signal: controller.signal,
    }));
    expect(result).toMatchObject({ ok: false, status: 503 });
    expect(h.acquired).toBe(0);
    expect(h.auditEvents()).toMatchObject([{
      reason: 'request-cancelled', tenantId: null,
    }]);
  });

  test('old server revision cannot be replayed into the final check', async () => {
    let calls = 0;
    const h = harness({ revisions: { async readRevision() {
      calls++;
      return calls === 1 ? '22' : '21';
    } } });
    const result = await h.read(h.request(await accessToken()));
    expect(result).toMatchObject({ ok: false, status: 404 });
    expect(JSON.stringify(result)).not.toContain('north-project');
    expect(h.auditEvents()).toMatchObject([{
      reason: 'authorization-changed', tenantId: null,
    }]);
  });
});
