import {beforeAll, describe, expect, test} from 'bun:test';
import {
  createSaasStagingHttpComposition,
  type SaasStagingHttpEnvironment,
} from '../src/features/saasBlueprint/controlApi/server/saasStagingHttpComposition';

const ORIGIN = 'https://saas.staging.valid-provider.org';
let jwks = '';

beforeAll(async () => {
  // Ephemeral, generated in memory: no pinned test key can enter production.
  const pair = await crypto.subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  }, true, ['sign', 'verify']);
  const publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey);
  jwks = JSON.stringify({keys: [{
    kty: 'RSA', alg: 'RS256', use: 'sig', kid: 'backend06-ci',
    e: 'AQAB', n: publicKey.n,
  }]});
});

function environment(overrides: Partial<SaasStagingHttpEnvironment> = {}):
  SaasStagingHttpEnvironment {
  return {
    SAAS_HTTP_EXPLICIT_ENABLE: 'true',
    SAAS_RUNTIME_PROFILE: 'isolated-staging',
    SAAS_NETWORK_POLICY: 'private-only',
    RAILWAY_ENVIRONMENT: 'staging',
    GITHUB_ACTIONS: 'true',
    SAAS_EPHEMERAL_COMPOSITION_CI: 'true',
    SAAS_EXTERNAL_ORIGIN: ORIGIN,
    SAAS_OIDC_ISSUER: 'https://idp.staging.valid-provider.org/',
    SAAS_OIDC_AUDIENCE: 'saas-control-api',
    SAAS_OIDC_PINNED_PUBLIC_JWKS_JSON: jwks,
    ...overrides,
  };
}

function ports() {
  let pgCalls = 0;
  let writeCalls = 0;
  let readinessCalls = 0;
  let ready = true;
  const deps = {
    identityPool: {
      async connect() {pgCalls++; throw new Error('identity PG must not run');},
      quarantine() {},
    },
    read: {
      pool: {
        async connect() {pgCalls++; throw new Error('read PG must not run');},
        quarantine() {},
      },
      signer: {async sign() {throw new Error('signer must not run');}},
      revisions: {async readRevision() {throw new Error('revision must not run');}},
      audit: {record() {}},
    },
    write: {
      journal: {async prepare() {throw new Error('journal must not run');}},
      writer: {async execute() {writeCalls++; return false;}},
    },
    readiness: {
      async check() {readinessCalls++; return ready;},
    },
  };
  return {
    deps,
    counters: () => ({pgCalls, writeCalls, readinessCalls}),
    setReady(value: boolean) {ready = value;},
  };
}

describe('SaaS Backend 06 isolated fetch-only server composition', () => {
  test('refuses disabled, non-isolated, production and CI-without-opt-in startup', async () => {
    const p = ports();
    for (const overrides of [
      {SAAS_HTTP_EXPLICIT_ENABLE: 'false'},
      {SAAS_RUNTIME_PROFILE: 'production'},
      {SAAS_NETWORK_POLICY: 'public'},
      {RAILWAY_ENVIRONMENT: 'production'},
      {RAILWAY_ENVIRONMENT: undefined},
      {SAAS_EXTERNAL_ORIGIN: 'http://127.0.0.1:8080'},
      {SAAS_EXTERNAL_ORIGIN: 'https://saas.staging.valid-provider.org/with-path'},
      {SAAS_EPHEMERAL_COMPOSITION_CI: undefined},
    ]) {
      await expect(createSaasStagingHttpComposition(
        environment(overrides), p.deps
      )).rejects.toThrow('configuration refused');
    }
    expect(p.counters().pgCalls).toBe(0);
  });

  test('rejects missing/malformed operator JWKS before identity is contacted', async () => {
    const p = ports();
    await expect(createSaasStagingHttpComposition(
      environment({SAAS_OIDC_PINNED_PUBLIC_JWKS_JSON: ''}), p.deps
    )).rejects.toThrow('trust configuration refused');
    await expect(createSaasStagingHttpComposition(
      environment({SAAS_OIDC_ISSUER: 'http://localhost/'}), p.deps
    )).rejects.toThrow('trust configuration refused');
    expect(p.counters().pgCalls).toBe(0);
  });

  test('health, readiness and strict route dispatch without any SQL or write', async () => {
    const p = ports();
    const app = await createSaasStagingHttpComposition(
      environment(), p.deps
    );
    const get = (path: string, method = 'GET') =>
      app.handle(new Request(ORIGIN + path, {method}));

    const health = await get('/internal/healthz');
    expect(health.status).toBe(200);
    expect(health.headers.get('cache-control')).toContain('no-store');
    expect((await get('/internal/readyz')).status).toBe(200);
    expect((await get('/internal/healthz?trace=1')).status).toBe(404);
    expect((await get('/internal/healthz', 'HEAD')).status).toBe(405);
    expect((await get('/other')).status).toBe(404);

    const collection = '/control-api/v1/tenants/t1/projects';
    const detail = collection + '/p1';
    expect((await get(collection)).status).toBe(401);
    expect((await get(collection, 'POST')).status).toBe(401);
    expect((await get(detail, 'PATCH')).status).toBe(401);
    const wrongMethod = await get(collection, 'PUT');
    expect(wrongMethod.status).toBe(405);
    expect(wrongMethod.headers.get('allow')).toBe('GET, POST');
    const wrongDetailMethod = await get(detail, 'GET');
    expect(wrongDetailMethod.status).toBe(405);
    expect(wrongDetailMethod.headers.get('allow')).toBe('PATCH');
    expect((await get(collection + '/p1/extra')).status).toBe(404);

    const badToken = await app.handle(new Request(ORIGIN + collection, {
      headers: {Authorization: 'Bearer invalid.jwt.signature'},
    }));
    expect(badToken.status).toBe(401);
    expect(p.counters().pgCalls).toBe(0);
    expect(p.counters().writeCalls).toBe(0);
  });

  test('fail closed on unhealthy probes, origin mismatch and abort', async () => {
    const p = ports();
    const app = await createSaasStagingHttpComposition(environment(), p.deps);
    p.setReady(false);
    expect((await app.handle(new Request(ORIGIN + '/internal/healthz'))).status)
      .toBe(200);
    expect((await app.handle(new Request(ORIGIN + '/internal/readyz'))).status)
      .toBe(503);
    const source = ORIGIN + '/control-api/v1/tenants/t1/projects';
    const denied = await app.handle(new Request(source));
    expect(denied.status).toBe(503);
    expect(await denied.text()).not.toContain('identity PG');
    expect((await app.handle(new Request('https://attacker.example.org/internal/healthz')))
      .status).toBe(404);
    const controller = new AbortController();
    controller.abort();
    expect((await app.handle(new Request(source, {signal: controller.signal})))
      .status).toBe(503);
    expect(p.counters().pgCalls).toBe(0);
    expect(p.counters().writeCalls).toBe(0);
  });

  test('readiness exceptions never expose details or permit a request', async () => {
    const p = ports();
    const app = await createSaasStagingHttpComposition(
      environment(), {
        ...p.deps,
        readiness: {async check() {throw new Error('PG password secret');}},
      }
    );
    const res = await app.handle(new Request(
      ORIGIN + '/control-api/v1/tenants/t1/projects'
    ));
    expect(res.status).toBe(503);
    expect(await res.text()).not.toContain('password');
    expect(p.counters().pgCalls).toBe(0);
  });
});
