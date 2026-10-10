import { describe, expect, test } from 'bun:test';
import type { BlueprintSnapshot } from '../src/features/saasBlueprint/domain';
import type { ControlActor, ControlReadResult } from '../src/features/saasBlueprint/controlApi/contracts';
import {
  createControlHttpHandler, type ControlServerDependencies,
} from '../src/features/saasBlueprint/controlApi/server/httpHandler';
import { SyntheticSessionRegistry } from '../src/features/saasBlueprint/controlApi/server/syntheticSessions';
import { createSyntheticControlBackend } from '../src/features/saasBlueprint/controlApi/server/syntheticBackend';
import { DEMO_CLOCK, DEMO_SNAPSHOT } from '../src/features/saasBlueprint/demo/demoData';

const ORIGIN = 'http://127.0.0.1:18551';
const PREFIX = '/control-api/v1/tenants';
const ACCOUNTS = PREFIX + '/demo-north/metadata/accounts';
const NORTH: ControlActor = {
  id: 'actor-north', memberships: [
    { tenantId: 'demo-north', role: 'tenant-admin', status: 'active' },
  ],
};
const ORBIT: ControlActor = {
  id: 'actor-orbit', memberships: [
    { tenantId: 'demo-orbit', role: 'tenant-viewer', status: 'active' },
  ],
};
const AUDITOR: ControlActor = {
  id: 'actor-auditor', memberships: [
    { tenantId: 'demo-north', role: 'tenant-auditor', status: 'active' },
  ],
};

function fixture() {
  let clock = DEMO_CLOCK;
  let snapshot: BlueprintSnapshot = DEMO_SNAPSHOT;
  // Fresh membership objects per test: revocation cannot poison other fixtures.
  const actors = new Map<string, ControlActor>([NORTH, ORBIT, AUDITOR].map((actor) => [
    actor.id, { id: actor.id, memberships: actor.memberships.map((membership) => ({ ...membership })) },
  ]));
  const sessions = new SyntheticSessionRegistry(() => clock);
  const backend = createSyntheticControlBackend({
    actors, snapshot: () => snapshot, nowMs: () => clock,
  });
  const deps: ControlServerDependencies = {
    sessions, ...backend, newCorrelationId: () => 'server-correlation-only',
  };
  return {
    sessions, actors, backend, deps,
    handler: createControlHttpHandler(deps),
    advance: (ms: number) => { clock += ms; },
    setSnapshot: (next: BlueprintSnapshot) => { snapshot = next; },
    clock: () => clock,
  };
}

type Handler = ReturnType<typeof createControlHttpHandler>;

async function send(
  handler: Handler, path: string, options: {
    token?: string;
    method?: string;
    headers?: HeadersInit;
    signal?: AbortSignal;
  } = {}
): Promise<Response> {
  const headers = new Headers(options.headers);
  if (options.token !== undefined) headers.set('Authorization', 'Bearer ' + options.token);
  const request = new Request(ORIGIN + path, {
    method: options.method ?? 'GET', headers, signal: options.signal,
  });
  return handler(request);
}

async function body(response: Response): Promise<unknown> {
  return response.json();
}

describe('SaaS Control synthetic HTTP boundary (not production)', () => {
  test('issues opaque random sessions, and verifies actor only from server-held state', async () => {
    const f = fixture();
    const a = await f.sessions.issue('actor-north');
    const b = await f.sessions.issue('actor-north');
    expect(a).toMatch(/^sbv1_[A-Za-z0-9_-]{43}$/);
    expect(a).not.toBe(b);
    expect(a).not.toContain('actor-north');
    expect(await f.sessions.verify(a)).toEqual({ actorId: 'actor-north' });
    expect(await f.sessions.verify(a.slice(0, -1) + (a.endsWith('A') ? 'B' : 'A'))).toBeNull();
    expect(await f.sessions.verify('actor-north')).toBeNull();
    await f.sessions.revoke(a);
    expect(await f.sessions.verify(a)).toBeNull();
    expect(await f.sessions.verify(b)).toEqual({ actorId: 'actor-north' });
  });

  test('synthetic sessions fail closed on expiration and invalid issuance', async () => {
    const f = fixture();
    const token = await f.sessions.issue('actor-north', 100);
    f.advance(99);
    expect(await f.sessions.verify(token)).not.toBeNull();
    f.advance(1);
    expect(await f.sessions.verify(token)).toBeNull();
    await expect(f.sessions.issue('actor-north', 0)).rejects.toThrow();
    await expect(f.sessions.issue('actor-north', 15 * 60_000 + 1)).rejects.toThrow();
    await expect(f.sessions.issue('not a valid actor')).rejects.toThrow();
  });

  test('GET tenant index returns ONLY the authenticated actor memberships', async () => {
    const f = fixture();
    const northToken = await f.sessions.issue(NORTH.id);
    const northResponse = await send(f.handler, PREFIX, { token: northToken });
    expect(northResponse.status).toBe(200);
    expect(await body(northResponse)).toEqual({
      ok: true, status: 200, apiVersion: 1, source: 'synthetic-simulation',
      data: [{ kind: 'tenant', id: 'demo-north', name: 'North Studio',
        status: 'active', role: 'tenant-admin' }],
    });
    const orbitToken = await f.sessions.issue(ORBIT.id);
    const orbitBody = JSON.stringify(await body(await send(f.handler, PREFIX, { token: orbitToken })));
    expect(orbitBody).toContain('Orbit Lab');
    expect(orbitBody).not.toContain('North Studio');
  });

  test('authorized tenant account read is safe, separately granted and marked synthetic', async () => {
    const f = fixture();
    const token = await f.sessions.issue(NORTH.id);
    const response = await send(f.handler, ACCOUNTS, { token });
    expect(response.status).toBe(200);
    const result = await body(response);
    const text = JSON.stringify(result);
    expect(text).toContain('"source":"synthetic-simulation"');
    expect(text).toContain('account-north');
    expect(text).toContain('account-platform');
    expect(text).toContain('proxy-platform');
    for (const forbidden of ['account-orbit', 'proxy-orbit', 'vpn-orbit', 'access_token', 'apiKey']) {
      expect(text).not.toContain(forbidden);
    }
  });

  test('headers cannot impersonate actor/tenant or access a foreign collection', async () => {
    const f = fixture();
    const northToken = await f.sessions.issue(NORTH.id);
    const headers = {
      'X-Tenant-ID': 'demo-orbit',
      'X-Actor-ID': 'actor-orbit',
      'X-Role': 'tenant-owner',
      'X-Correlation-ID': 'client-chosen',
    };
    const denied = await send(f.handler, PREFIX + '/demo-orbit/metadata/accounts', {
      token: northToken, headers,
    });
    expect(denied.status).toBe(404);
    expect(await body(denied)).toEqual({
      ok: false, status: 404, error: { code: 'NOT_FOUND', message: 'Resource unavailable' },
    });
    expect(denied.headers.get('X-Correlation-ID')).toBe('server-correlation-only');
    const own = await send(f.handler, ACCOUNTS, { token: northToken, headers });
    expect(own.status).toBe(200);
    expect(JSON.stringify(await body(own))).not.toContain('account-orbit');
  });

  test('rejects absent, altered, revoked, duplicate and expired authentication', async () => {
    const f = fixture();
    expect((await send(f.handler, ACCOUNTS)).status).toBe(401);
    const token = await f.sessions.issue(NORTH.id, 100);
    for (const header of ['Basic ' + token, 'Bearer ' + token + ', Bearer ' + token,
      'Bearer actor-north', 'Bearer ' + token + ' extra']) {
      expect((await send(f.handler, ACCOUNTS, {
        headers: { Authorization: header },
      })).status).toBe(401);
    }
    expect((await send(f.handler, ACCOUNTS, { token })).status).toBe(200);
    f.advance(100);
    const expired = await send(f.handler, ACCOUNTS, { token });
    expect(expired.status).toBe(401);
    expect(JSON.stringify(await body(expired))).not.toContain('actor-north');
    const revoke = await f.sessions.issue(NORTH.id);
    await f.sessions.revoke(revoke);
    expect((await send(f.handler, ACCOUNTS, { token: revoke })).status).toBe(401);
    // A verified opaque token with no trusted actor record has no permissions.
    const unknown = await f.sessions.issue('actor-unregistered');
    expect((await send(f.handler, ACCOUNTS, { token: unknown })).status).toBe(401);
  });

  test('auditor role cannot enumerate accounts/keys/egress and never calls backend', async () => {
    const f = fixture();
    let reads = 0;
    const handler = createControlHttpHandler({
      ...f.deps,
      reader: { ...f.backend.reader,
        readCollection: (...args) => {
          reads += 1;
          return f.backend.reader.readCollection(...args);
        } },
    });
    const token = await f.sessions.issue(AUDITOR.id);
    for (const item of ['accounts', 'client-keys', 'egress', 'routing', 'pools']) {
      const response = await send(handler, PREFIX + '/demo-north/metadata/' + item, { token });
      expect(response.status).toBe(403);
      expect(JSON.stringify(await body(response))).not.toContain('account-');
    }
    expect(reads).toBe(0);
    expect((await send(handler, PREFIX + '/demo-north/metadata/projects', { token })).status)
      .toBe(200);
    expect(reads).toBe(1);
  });

  test('deny revoked or duplicated actor membership without tenant discovery', async () => {
    const f = fixture();
    const token = await f.sessions.issue(NORTH.id);
    f.actors.set(NORTH.id, { ...NORTH, memberships: [
      ...NORTH.memberships, ...NORTH.memberships,
    ] });
    expect((await send(f.handler, ACCOUNTS, { token })).status).toBe(404);
    f.actors.set(NORTH.id, {
      ...NORTH, memberships: [{ ...NORTH.memberships[0], status: 'revoked' }],
    });
    expect((await send(f.handler, ACCOUNTS, { token })).status).toBe(404);
  });

  test('does not expose stale foreign refs after grant revocation', async () => {
    const f = fixture();
    const token = await f.sessions.issue(NORTH.id);
    expect(JSON.stringify(await body(await send(f.handler, ACCOUNTS, { token }))))
      .toContain('account-platform');
    f.setSnapshot({
      ...DEMO_SNAPSHOT,
      accessGrants: DEMO_SNAPSHOT.accessGrants.filter((grant) =>
        grant.resourceKind !== 'account'),
    });
    const response = await send(f.handler, ACCOUNTS, { token });
    expect(response.status).toBe(200);
    expect(JSON.stringify(await body(response))).not.toContain('account-platform');
  });

  test('blocks malformed route, arbitrary collections and query parameters', async () => {
    const f = fixture();
    const token = await f.sessions.issue(NORTH.id);
    for (const path of [
      PREFIX + '/', PREFIX + '/demo-north/metadata/accounts/',
      PREFIX + '/demo-north/metadata/account',
      PREFIX + '/demo-north/metadata/unknown',
      PREFIX + '/demo-north/metadata/accounts?tenantId=demo-orbit',
      PREFIX + '/demo-north%2fanything/metadata/accounts',
      '/api/management/accounts', '/', PREFIX + '/demo-north/metadata/accounts/extra',
    ]) {
      expect((await send(f.handler, path, { token })).status).toBe(404);
    }
  });

  test('allows only GET; no CORS, cookies, caching, client correlation IDs or HTML', async () => {
    const f = fixture();
    const token = await f.sessions.issue(NORTH.id);
    for (const method of ['POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT']) {
      const response = await send(f.handler, ACCOUNTS, { token, method });
      expect(response.status).toBe(405);
      expect(response.headers.get('Allow')).toBe('GET');
    }
    const crossOrigin = await send(f.handler, ACCOUNTS, {
      token, headers: { Origin: 'https://malicious.example' },
    });
    expect(crossOrigin.status).toBe(403);
    const response = await send(f.handler, ACCOUNTS, {
      token, headers: { 'X-Correlation-ID': 'attacker-correlation' },
    });
    expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull();
    expect(response.headers.get('Set-Cookie')).toBeNull();
    expect(response.headers.get('Cache-Control')).toContain('no-store');
    expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(response.headers.get('X-Correlation-ID')).not.toBe('attacker-correlation');
    expect(response.headers.get('Content-Type')).toContain('application/json');
  });

  test('malicious extra DTO fields never appear in HTTP response', async () => {
    const f = fixture();
    const handler = createControlHttpHandler({
      ...f.deps,
      reader: { ...f.backend.reader,
        async readCollection(...args): Promise<ControlReadResult> {
          const raw = await f.backend.reader.readCollection(...args);
          if (!raw.ok) return raw;
          const infected = raw.data.map((item) => ({
            ...item, oauthToken: 'NEVER_SHOW_TOKEN', proxyPassword: 'NEVER_SHOW_PASSWORD',
            owner: 'owner' in item ? { ...item.owner, secret: 'NEVER_SHOW_OWNER' } : undefined,
          }));
          return { ...raw, data: infected as unknown as typeof raw.data };
        },
      },
    });
    const token = await f.sessions.issue(NORTH.id);
    const result = await send(handler, ACCOUNTS, { token });
    expect(result.status).toBe(200);
    const serialized = JSON.stringify(await body(result));
    for (const secret of ['NEVER_SHOW_TOKEN', 'NEVER_SHOW_PASSWORD', 'NEVER_SHOW_OWNER']) {
      expect(serialized).not.toContain(secret);
    }
  });

  test('mismatched source, tenant, invalid schema or secret-bearing endpoint all fail closed', async () => {
    const f = fixture();
    const token = await f.sessions.issue(NORTH.id);
    const base = await f.backend.reader.readCollection({
      actorId: NORTH.id, tenantId: 'demo-north', role: 'tenant-admin',
      correlationId: 'fixed-server',
    }, 'accounts', { signal: new AbortController().signal });
    if (!base.ok) throw new Error('fixture expected allow');
    const samples: unknown[] = [
      { ...base, source: 'core-metadata-readonly' },
      { ...base, tenantId: 'demo-orbit' },
      { ...base, collection: 'egress' },
      { ...base, data: [{ ...base.data[0], allowedModelIds: 'not-an-array' }] },
      { ...base, data: Array.from({ length: 201 }, () => base.data[0]) },
      { ...base, ok: false, status: 400, error: { code: 'SOURCE_UNAVAILABLE',
        message: 'PRIVATE_UPSTREAM_ERROR' } },
    ];
    for (const raw of samples) {
      const handler = createControlHttpHandler({
        ...f.deps, reader: { ...f.backend.reader,
          async readCollection() { return raw as ControlReadResult; },
        },
      });
      const response = await send(handler, ACCOUNTS, { token });
      expect(response.status).toBe(503);
      expect(JSON.stringify(await body(response))).not.toContain('PRIVATE_UPSTREAM_ERROR');
    }
  });

  test('unexpected upstream exceptions map to generic 503 and never expose secrets', async () => {
    const f = fixture();
    const handler = createControlHttpHandler({
      ...f.deps, reader: { ...f.backend.reader,
        async readCollection() { throw new Error('SECRET_INTERNAL_CORE_CONFIG'); },
      },
    });
    const token = await f.sessions.issue(NORTH.id);
    const response = await send(handler, ACCOUNTS, { token });
    expect(response.status).toBe(503);
    expect(JSON.stringify(await body(response))).not.toContain('SECRET_INTERNAL_CORE_CONFIG');
  });

  test('in-flight member revocation invalidates the response, including in-place updates', async () => {
    const f = fixture();
    const token = await f.sessions.issue(NORTH.id);
    let started!: () => void;
    let release!: () => void;
    const entered = new Promise<void>((resolve) => { started = resolve; });
    const pending = new Promise<void>((resolve) => { release = resolve; });
    const handler = createControlHttpHandler({
      ...f.deps, reader: { ...f.backend.reader,
        async readCollection(...args) {
          started();
          await pending;
          return f.backend.reader.readCollection(...args);
        },
      },
    });
    const promise = send(handler, ACCOUNTS, { token });
    await entered;
    // Mutate the original membership array in place, then resolve the source.
    const original = f.actors.get(NORTH.id)!;
    (original.memberships[0] as { status: string }).status = 'revoked';
    release();
    const response = await promise;
    expect(response.status).toBe(401);
    expect(JSON.stringify(await body(response))).not.toContain('account-north');
  });

  test('session revoked during a slow source request cannot produce a cached response', async () => {
    const f = fixture();
    const token = await f.sessions.issue(NORTH.id);
    let entered!: () => void;
    let release!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    const wait = new Promise<void>((resolve) => { release = resolve; });
    const handler = createControlHttpHandler({
      ...f.deps, reader: { ...f.backend.reader,
        async readCollection(...args) {
          entered();
          await wait;
          return f.backend.reader.readCollection(...args);
        },
      },
    });
    const promise = send(handler, ACCOUNTS, { token });
    await started;
    await f.sessions.revoke(token);
    release();
    expect((await promise).status).toBe(401);
  });

  test('cancelled requests do not read the adapter or emit prior tenant metadata', async () => {
    const f = fixture();
    let calls = 0;
    const handler = createControlHttpHandler({
      ...f.deps, reader: { ...f.backend.reader,
        async readCollection(...args) { calls += 1;
          return f.backend.reader.readCollection(...args); },
      },
    });
    const token = await f.sessions.issue(NORTH.id);
    const controller = new AbortController();
    controller.abort();
    const response = await send(handler, ACCOUNTS, {
      token, signal: controller.signal,
    });
    expect(response.status).toBe(401);
    expect(calls).toBe(0);
    expect(JSON.stringify(await body(response))).not.toContain('account-north');
  });

  test('suspended tenant and invalid source return generic errors, never model data', async () => {
    const f = fixture();
    const token = await f.sessions.issue(NORTH.id);
    f.setSnapshot({
      ...DEMO_SNAPSHOT, tenants: DEMO_SNAPSHOT.tenants.map((item) =>
        item.id === 'demo-north' ? { ...item, status: 'suspended' } : item),
    });
    const r = await send(f.handler, ACCOUNTS, { token });
    expect(r.status).toBe(403);
    expect(JSON.stringify(await body(r))).not.toContain('account-north');
  });

  test('live loopback HTTP can serve ONLY the synthetic backend without Core access', async () => {
    const f = fixture();
    const token = await f.sessions.issue(NORTH.id);
    // Real TCP only on localhost with synthetic fixture; zero outbound traffic.
    const server = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch: f.handler });
    try {
      const address = 'http://127.0.0.1:' + server.port + ACCOUNTS;
      const r = await fetch(address, { headers: { Authorization: 'Bearer ' + token } });
      expect(r.status).toBe(200);
      expect(JSON.stringify(await r.json())).toContain('account-north');
      const r2 = await fetch(address);
      expect(r2.status).toBe(401);
    } finally {
      server.stop(true);
    }
  });
});
