import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createBackend16PrivateReadHandler,
  type Backend16PrivateReadPorts,
  type VerifiedPrincipal,
} from '../src/features/saasBlueprint/controlApi/server/backend16PrivateTenantProjectRead.ts';

const TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const OTHER = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PROJECT = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const SESSION = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const BINDING = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const NOW = 1_750_000_000_000;
const TOKEN = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl';
const URL_BASE = 'https://private.test/internal/saas/v1/tenants/';
const VALID_PRINCIPAL: VerifiedPrincipal = {
  kind: 'verified-server-session',
  issuer: 'https://issuer.example.test/',
  subjectFingerprintSha256: 'a'.repeat(64),
  pgLogin: 'saas_principal_subject_01',
  sessionId: SESSION,
  bindingId: BINDING,
  sessionExpiresAtMs: NOW + 60_000,
};

type Counters = { authenticate: number; read: number };
function createFixture(overrides: Partial<Backend16PrivateReadPorts> = {}) {
  const counters: Counters = { authenticate: 0, read: 0 };
  const ports: Backend16PrivateReadPorts = {
    enabled: () => false, // deliberately opt-in even in fixtures
    expectedOrigin: 'https://private.test',
    authenticate: async () => { counters.authenticate++; return VALID_PRINCIPAL; },
    readAuthorized: async (_p, tenantId) => {
      counters.read++;
      return { kind: 'authorized', tenantId, projectIds: [PROJECT] };
    },
    now: () => NOW,
    ...overrides,
  };
  return { handler: createBackend16PrivateReadHandler(ports), counters };
}
function req(tenantId = TENANT, tail = '/projects', headers: Record<string, string> = {}) {
  return new Request(`${URL_BASE}${tenantId}${tail}`, {
    headers: { Authorization: `Bearer ${TOKEN}`, ...headers },
  });
}
async function body(response: Response): Promise<any> {
  return response.json();
}

test('explicitly disabled by default: no authority or data call', async () => {
  const { handler, counters } = createFixture();
  const response = await handler(req());
  assert.equal(response.status, 404);
  assert.deepEqual(counters, { authenticate: 0, read: 0 });
  assert.equal(response.headers.get('Access-Control-Allow-Origin'), null);
  assert.match(response.headers.get('Cache-Control')!, /no-store/);
});

test('GET whitelisted minimal project DTO, no principal or secrets', async () => {
  const { handler, counters } = createFixture({ enabled: () => true });
  const r = await handler(req());
  assert.equal(r.status, 200);
  assert.deepEqual(await body(r), { tenantId: TENANT, projectIds: [PROJECT] });
  assert.deepEqual(counters, { authenticate: 1, read: 1 });
  assert.equal(r.headers.get('X-Content-Type-Options'), 'nosniff');
  assert.equal(r.headers.get('Content-Security-Policy'), "default-src 'none'; frame-ancestors 'none'");
});

test('GET tenant returns only requested tenant ID after trusted data authorization', async () => {
  const { handler, counters } = createFixture({ enabled: () => true });
  const r = await handler(req(TENANT, ''));
  assert.equal(r.status, 200);
  assert.deepEqual(await body(r), { tenant: { id: TENANT } });
  assert.equal(counters.read, 1);
});

test('unverified request bearer never reaches trusted data reader', async () => {
  for (const authorization of [undefined, 'Basic aGk=', 'Bearer opaque', 'Bearer aaa.bbb.ccc, Bearer other',
    'Bearer abc.def.?', `Bearer ${'a'.repeat(6200)}.b.c`]) {
    const { handler, counters } = createFixture({ enabled: () => true });
    const headers = authorization ? { Authorization: authorization } : { Authorization: '' };
    const r = await handler(req(TENANT, '/projects', headers));
    assert.equal(r.status, 401, String(authorization).slice(0,20));
    assert.equal(counters.read, 0);
    assert.equal(r.headers.get('WWW-Authenticate'), 'Bearer');
  }
});

test('deny missing session, never read from database', async () => {
  const { handler, counters } = createFixture({ enabled: () => true, authenticate: async () => null });
  const r = await handler(req());
  assert.equal(r.status, 401);
  assert.equal(counters.read, 0);
});

test('expired, excessive TTL, unsafe PG LOGIN or bad issuer are refused before database access', async () => {
  const bads: Partial<VerifiedPrincipal>[] = [
    { sessionExpiresAtMs: NOW },
    { sessionExpiresAtMs: NOW - 100 },
    { sessionExpiresAtMs: NOW + 16 * 60_000 },
    { pgLogin: 'postgres' },
    { pgLogin: 'saas_schema_migrator' },
    { pgLogin: 'saas_runtime_reader' },
    { pgLogin: 'saas_runtime_writer' },
    { pgLogin: 'name-with-hyphen' },
    { issuer: 'http://issuer.example.test/' },
    { issuer: 'https://attacker@example.test/' },
    { issuer: 'https://issuer.example.test/?malicious=1' },
    { subjectFingerprintSha256: 'a'.repeat(63) },
    { sessionId: 'not-a-uuid' },
    { bindingId: 'not-a-uuid' },
    { kind: 'wrong' as VerifiedPrincipal['kind'] },
  ];
  for (const override of bads) {
    const { handler, counters } = createFixture({
      enabled: () => true,
      authenticate: async () => ({ ...VALID_PRINCIPAL, ...override }),
    });
    const r = await handler(req());
    assert.equal(r.status, 401, JSON.stringify(override));
    assert.equal(counters.read, 0);
  }
});

test('denied tenant and nonexistent tenant produce indistinguishable public 404', async () => {
  const { handler, counters } = createFixture({
    enabled: () => true,
    readAuthorized: async () => { counters.read++; return { kind: 'denied' }; },
  });
  const one = await handler(req(TENANT));
  const two = await handler(req(OTHER));
  assert.equal(one.status, 404);
  assert.equal(two.status, 404);
  assert.deepEqual(await body(one), await body(two));
});

test('client tenant/role/PG login headers and cookies are refused, not honored', async () => {
  for (const headers of [
    { 'X-Tenant-ID': OTHER }, { 'X-Role': 'admin' },
    { 'X-PG-Login': 'postgres' }, { Cookie: 'session=abc' },
    { 'Transfer-Encoding': 'chunked' },
  ]) {
    const { handler, counters } = createFixture({ enabled: () => true });
    const r = await handler(req(TENANT, '/projects', headers));
    assert.equal(r.status, 400);
    assert.equal(counters.authenticate, 0);
    assert.equal(counters.read, 0);
  }
});

test('query/header token overrides and encoded path variants are not accepted', async () => {
  for (const suffix of [
    `?tenantId=${OTHER}`, '?role=admin', '?jwt=abc', '#other',
  ]) {
    const { handler, counters } = createFixture({ enabled: () => true });
    const r = await handler(new Request(`${URL_BASE}${TENANT}/projects${suffix}`,
      { headers: { Authorization: `Bearer ${TOKEN}` } }));
    // Fragment is stripped by fetch clients, but our server-side Request carries it.
    assert.equal(r.status, 400);
    assert.equal(counters.read, 0);
  }
  const { handler } = createFixture({ enabled: () => true });
  assert.equal((await handler(req(TENANT.toUpperCase()))).status, 404);
  assert.equal((await handler(new Request(`${URL_BASE}${TENANT}%2Fprojects`,
    { headers: { Authorization: `Bearer ${TOKEN}` } }))).status, 404);
});

test('non-GET methods are refused without invoking verifier', async () => {
  for (const method of ['POST', 'PATCH', 'DELETE', 'OPTIONS']) {
    const { handler, counters } = createFixture({ enabled: () => true });
    const request = new Request(`${URL_BASE}${TENANT}`, { method });
    const r = await handler(request);
    assert.equal(r.status, 405);
    assert.equal(r.headers.get('Allow'), 'GET');
    assert.equal(counters.authenticate, 0);
    assert.equal(counters.read, 0);
  }
});

test('mismatched tenant response, duplicate projects, invalid or excessive project ids fail closed', async () => {
  const invalid = [
    { kind: 'authorized' as const, tenantId: OTHER, projectIds: [PROJECT] },
    { kind: 'authorized' as const, tenantId: TENANT, projectIds: [PROJECT, PROJECT] },
    { kind: 'authorized' as const, tenantId: TENANT, projectIds: ['not-a-uuid'] },
    { kind: 'authorized' as const, tenantId: TENANT, projectIds: Array.from({ length: 51 }, (_, i) =>
      `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`) },
  ];
  for (const row of invalid) {
    const { handler } = createFixture({ enabled: () => true, readAuthorized: async () => row });
    const r = await handler(req());
    assert.equal(r.status, 503);
    assert.deepEqual(await body(r), { error: { code: 'UNAVAILABLE' } });
  }
});

test('database result extra private fields never get serialized', async () => {
  const { handler } = createFixture({
    enabled: () => true,
    readAuthorized: async () => ({
      kind: 'authorized', tenantId: TENANT, projectIds: [PROJECT],
      apiKey: 'SENSITIVE_SECRET', bearer: TOKEN, grantRevision: 999, subjectFingerprint: 'ffff',
    }),
  });
  const r = await handler(req());
  const bodyString = await r.text();
  assert.equal(r.status, 200);
  assert.equal(bodyString.includes('SENSITIVE_SECRET'), false);
  assert.equal(bodyString.includes('grantRevision'), false);
  assert.equal(bodyString.includes(TOKEN), false);
  assert.deepEqual(JSON.parse(bodyString), { tenantId: TENANT, projectIds: [PROJECT] });
});

test('SQL/auth failures never leak SQLSTATE, token, issuer or tenant existence', async () => {
  for (const failureOn of ['auth', 'sql']) {
    const { handler } = createFixture({
      enabled: () => true,
      authenticate: async () => {
        if (failureOn === 'auth') throw new Error(`JWT ${TOKEN}: secret`);
        return VALID_PRINCIPAL;
      },
      readAuthorized: async () => { throw new Error(`42P01 SELECT private WHERE token='${TOKEN}'`); },
    });
    const r = await handler(req());
    const serialized = await r.text();
    assert.equal(r.status, 503);
    assert.deepEqual(JSON.parse(serialized), { error: { code: 'UNAVAILABLE' } });
    assert.equal(serialized.includes(TOKEN), false);
    assert.equal(serialized.includes('42P01'), false);
    assert.equal(serialized.includes('secret'), false);
  }
});

test('aborted request never dispatches authorization or data access', async () => {
  const controller = new AbortController();
  controller.abort();
  const { handler, counters } = createFixture({ enabled: () => true });
  const r = await handler(new Request(`${URL_BASE}${TENANT}`, {
    headers: { Authorization: `Bearer ${TOKEN}` }, signal: controller.signal,
  }));
  assert.equal(r.status, 503);
  assert.deepEqual(counters, { authenticate: 0, read: 0 });
});

test('abort during OIDC verification never reaches database reader', async () => {
  const controller = new AbortController();
  const { handler, counters } = createFixture({
    enabled: () => true,
    authenticate: async () => { controller.abort(); return VALID_PRINCIPAL; },
  });
  const r = await handler(new Request(`${URL_BASE}${TENANT}`, {
    headers: { Authorization: `Bearer ${TOKEN}` }, signal: controller.signal,
  }));
  assert.equal(r.status, 503);
  assert.equal(counters.read, 0);
});

test('abort during a SQL read never publishes rows after cancellation', async () => {
  const controller = new AbortController();
  const { handler } = createFixture({
    enabled: () => true,
    readAuthorized: async () => { controller.abort(); return { kind: 'authorized', tenantId: TENANT, projectIds: [PROJECT] }; },
  });
  const r = await handler(new Request(`${URL_BASE}${TENANT}`, {
    headers: { Authorization: `Bearer ${TOKEN}` }, signal: controller.signal,
  }));
  assert.equal(r.status, 503);
});

test('misconfigured or throwing enabled gate fails safely', async () => {
  assert.throws(() => createBackend16PrivateReadHandler({} as Backend16PrivateReadPorts), /trusted private read ports/);
  const { handler } = createFixture({ enabled: () => { throw Error('secret feature state'); } });
  const r = await handler(req());
  assert.deepEqual(await body(r), { error: { code: 'UNAVAILABLE' } });
});

test('session expiring while a lock-held DB read runs is never published', async () => {
  let ticks = 0;
  const { handler } = createFixture({
    enabled: () => true,
    now: () => ++ticks === 1 ? NOW : NOW + 120_000,
  });
  const r = await handler(req());
  assert.equal(r.status, 503);
  assert.deepEqual(await body(r), { error: { code: 'UNAVAILABLE' } });
});

test('origin is pinned at construction and cannot come from Host or forwarded headers', async () => {
  for (const origin of ['', 'http://private.test', 'https://private.test/path',
    'https://private.test/', 'https://user@private.test', 'https://private.test?x=1']) {
    assert.throws(() => createBackend16PrivateReadHandler({
      enabled: () => false, expectedOrigin: origin,
      authenticate: async () => VALID_PRINCIPAL,
      readAuthorized: async () => ({kind: 'denied'}),
    }), /trusted private read ports/);
  }
  const { handler, counters } = createFixture({ enabled: () => true });
  const foreign = await handler(new Request(`https://attacker.test/internal/saas/v1/tenants/${TENANT}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  }));
  assert.equal(foreign.status, 404);
  assert.deepEqual(counters, { authenticate: 0, read: 0 });
});

test('proxy and browser origin spoofing cannot reach authentication or data', async () => {
  for (const headers of [
    { Forwarded: 'host=attacker.test' }, { 'X-Forwarded-Host': 'attacker.test' },
    { 'X-Forwarded-Proto': 'http' }, { 'X-Forwarded-User': 'victim' },
    { 'X-Original-URL': '/admin' }, { 'X-Rewrite-URL': '/admin' },
    { 'Sec-Fetch-Site': 'cross-site' }, { Origin: 'https://attacker.test' },
  ]) {
    const { handler, counters } = createFixture({ enabled: () => true });
    const r = await handler(req(TENANT, '/projects', headers));
    assert.equal(r.status, 400, JSON.stringify(headers));
    assert.deepEqual(counters, { authenticate: 0, read: 0 });
  }
  const { handler } = createFixture({ enabled: () => true });
  const same = await handler(req(TENANT, '/projects', {Origin: 'https://private.test'}));
  assert.equal(same.status, 200);
  assert.equal(same.headers.get('Cross-Origin-Resource-Policy'), 'same-origin');
});

test('feature gating isolates even malformed credentials', async () => {
  const { handler, counters } = createFixture();
  const r = await handler(new Request(`${URL_BASE}${TENANT}?role=superuser`, {
    headers: { Authorization: 'completely-untrusted' },
  }));
  assert.equal(r.status, 404);
  assert.deepEqual(counters, { authenticate: 0, read: 0 });
});

test('authorization reader returning null is treated as outage, not proof of an absent tenant', async () => {
  const { handler } = createFixture({
    enabled: () => true,
    readAuthorized: async () => null as any,
  });
  const r = await handler(req());
  assert.equal(r.status, 503);
  assert.deepEqual(await body(r), { error: { code: 'UNAVAILABLE' } });
});
