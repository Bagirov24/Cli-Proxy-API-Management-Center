import { beforeAll, describe, expect, test } from 'bun:test';
import type { ControlActor } from '../src/features/saasBlueprint/controlApi/contracts';
import {
  createM1ProjectHttpHandler,
} from '../src/features/saasBlueprint/controlApi/server/m1ProjectHttpHandler';
import {
  createPinnedAccessTokenVerifier,
} from '../src/features/saasBlueprint/controlApi/server/trustedAccessToken';
import type {
  M1ProjectDependencies, M1ProjectMutation,
} from '../src/features/saasBlueprint/controlApi/server/m1ProjectCommandBoundary';

const ORIGIN = 'http://127.0.0.1:18621';
const PATH = '/control-api/v1/tenants/demo-north/metadata/projects/project-m1i';
const ISSUER = 'https://m1i-ci-issuer.example.test/';
const AUDIENCE = 'm1i-ci-projects';
const NOW = 1_800_000_000;
const enabled = process.env.GITHUB_ACTIONS === 'true' &&
  process.env.SAAS_EPHEMERAL_M1_HTTP_CI === 'true';
const ciTest = enabled ? test : test.skip;
const STATUS = {
  north: 'actor-north', orbit: 'actor-orbit', auditor: 'actor-auditor',
} as const;
let keys: CryptoKeyPair;
const bytes = (s: string) => new TextEncoder().encode(s);
function base64url(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
async function token(subject = 'sub-north', overrides: Record<string, unknown> = {}) {
  const head = base64url(bytes(JSON.stringify({
    alg: 'RS256', typ: 'at+jwt', kid: 'm1i-ephemeral',
  })));
  const claims = base64url(bytes(JSON.stringify({
    iss: ISSUER, aud: AUDIENCE, sub: subject,
    iat: NOW - 20, exp: NOW + 200,
    ...overrides,
  })));
  const sig = new Uint8Array(await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', keys.privateKey, bytes(head + '.' + claims),
  ));
  return head + '.' + claims + '.' + base64url(sig);
}
type Mode = 'success' | 'deny' | 'throw' | 'abort';
function fixture() {
  const actors = new Map<string, ControlActor>([
    [STATUS.north, { id: STATUS.north, memberships: [
      { tenantId: 'demo-north', role: 'tenant-admin', status: 'active' },
    ] }],
    [STATUS.orbit, { id: STATUS.orbit, memberships: [
      { tenantId: 'demo-orbit', role: 'tenant-viewer', status: 'active' },
    ] }],
    [STATUS.auditor, { id: STATUS.auditor, memberships: [
      { tenantId: 'demo-north', role: 'tenant-auditor', status: 'active' },
    ] }],
  ]);
  const writes: M1ProjectMutation[] = [];
  let outcome: Mode = 'success';
  let stop: (() => void) | null = null;
  const deps: M1ProjectDependencies = {
    tokens: createPinnedAccessTokenVerifier({
      issuer: ISSUER, audience: AUDIENCE,
      publicKeys: new Map([['m1i-ephemeral', keys.publicKey]]),
      nowSeconds: () => NOW,
    }),
    directory: {
      async resolveActorId(ident) {
        if (ident.issuer !== ISSUER) return null;
        const map: Record<string,string> = {
          'sub-north': STATUS.north, 'sub-orbit': STATUS.orbit,
          'sub-auditor': STATUS.auditor,
        };
        return map[ident.subject] ?? null;
      },
    },
    actors: { async lookup(id) { return actors.get(id) ?? null; } },
    writer: {
      async execute(input) {
        writes.push(input);
        if (outcome === 'throw') {
          throw new Error('PG_SECRET_INTERNAL_TRANSACTION_DO_NOT_EXPOSE');
        }
        if (outcome === 'abort') {
          stop?.();
          return true;
        }
        return outcome === 'success';
      },
    },
    newCorrelationId: () => 'server-m1i-correlation',
  };
  return {
    actors, writes, deps,
    create: () => createM1ProjectHttpHandler(deps, {
      enabledForDisposableCi: true,
    }),
    setMode(mode: Mode) { outcome = mode; },
    setAbort(fn: () => void) { stop = fn; },
  };
}
function request(
  path: string, method: string, jwt: string,
  payload: unknown = { name: 'HTTP project' },
  overrides: {
    headers?: HeadersInit; signal?: AbortSignal; raw?: string;
  } = {},
): Request {
  const headers = new Headers(overrides.headers);
  if (jwt) headers.set('Authorization', 'Bearer ' + jwt);
  if (!headers.has('content-type')) headers.set('Content-Type', 'application/json');
  return new Request(ORIGIN + path, {
    method, headers, signal: overrides.signal,
    body: overrides.raw ?? JSON.stringify(payload),
  });
}
async function body(response: Response): Promise<Record<string, unknown>> {
  return await response.json() as Record<string, unknown>;
}
beforeAll(async () => {
  keys = await crypto.subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
  }, true, ['sign','verify']) as CryptoKeyPair;
});

describe('M1i unmounted project write HTTP adapter', () => {
  test('factory is default-off even when a caller passes dependencies', () => {
    expect(() => createM1ProjectHttpHandler(fixture().deps,
      {} as { enabledForDisposableCi: true })).toThrow(
      'M1i project writes are disabled outside disposable GitHub CI');
    if (!enabled) expect(fixture().create).toThrow(
      'M1i project writes are disabled outside disposable GitHub CI');
  });

  ciTest('valid pinned synthetic RS256 POST/PATCH/DELETE preserves trusted writer scope', async () => {
    const f = fixture();
    const handler = f.create();
    const signed = await token('sub-north', {
      role: 'tenant-owner', actorId: STATUS.orbit, tenantId: 'demo-orbit',
      attemptId: 'FORGED_CLIENT_ATTEMPT',
    });
    const calls = [
      request(PATH, 'POST', signed, { name: 'Create' }),
      request(PATH, 'PATCH', signed, { name: 'Rename', expectedVersion: 1 }),
      request(PATH, 'DELETE', signed, { expectedVersion: 2 }),
    ];
    for (const [index, cmd] of calls.entries()) {
      const result = await handler(cmd);
      expect(result.status).toBe(index === 0 ? 201 : 200);
      expect(await body(result)).toEqual({
        ok: true, status: index === 0 ? 201 : 200,
        apiVersion: 1, source: 'ci-only-unmounted',
      });
      expect(result.headers.get('X-Correlation-Id')).toBe('server-m1i-correlation');
      expect(result.headers.get('Cache-Control')).toContain('no-store');
      expect(result.headers.get('Set-Cookie')).toBeNull();
      expect(result.headers.get('Access-Control-Allow-Origin')).toBeNull();
      expect(result.headers.get('X-Content-Type-Options')).toBe('nosniff');
    }
    expect(f.writes).toHaveLength(3);
    expect(f.writes.map(x => x.operation)).toEqual(['create', 'rename', 'disable']);
    expect(f.writes.map(x => x.expectedVersion)).toEqual([undefined, 1, 2]);
    for (const item of f.writes) {
      expect(item.scope).toEqual({
        actorId: STATUS.north, tenantId: 'demo-north',
        role: 'tenant-admin', correlationId: 'server-m1i-correlation',
      });
      expect(JSON.stringify(item)).not.toContain(signed);
      expect(JSON.stringify(item)).not.toContain('FORGED_CLIENT_ATTEMPT');
      expect(JSON.stringify(item)).not.toContain('actor-orbit');
    }
  });

  ciTest('unverified, expired, wrong issuer, viewer and revoked memberships cannot write', async () => {
    const f = fixture();
    const handler = f.create();
    const valid = await token();
    for (const invalid of [
      '', 'bad', valid.slice(0, -3) + 'ABC',
      await token('sub-north',{exp:NOW-1}),
      await token('sub-north',{iss:'https://attacker.invalid/'}),
    ]) {
      const response = await handler(request(PATH, 'POST', invalid));
      expect(response.status).toBe(401);
    }
    const viewer = await handler(request(
      '/control-api/v1/tenants/demo-orbit/metadata/projects/project-m1i',
      'POST', await token('sub-orbit')));
    expect(viewer.status).toBe(404);
    const wrong = await handler(request(PATH, 'POST', await token('sub-orbit')));
    expect(wrong.status).toBe(404);
    const auditor = await handler(request(PATH, 'POST', await token('sub-auditor')));
    expect(auditor.status).toBe(404);
    f.actors.set(STATUS.north, {
      id: STATUS.north, memberships: [
        { tenantId: 'demo-north', role: 'tenant-admin', status: 'revoked' },
      ],
    });
    expect((await handler(request(PATH,'POST',valid))).status).toBe(404);
    expect(f.writes).toHaveLength(0);
  });

  ciTest('rejects malformed routes, methods, browser origins and client authority headers', async () => {
    const f = fixture();
    const h = f.create();
    const signed = await token();
    for (const path of [
      '/control-api/v1/tenants/demo-north/metadata/projects/',
      PATH + '/', PATH + '/extra', PATH + '?tenantId=demo-orbit',
      PATH + '?idempotent=true',
      PATH.replace('demo-north', 'demo-north%2fother'),
      '/control-api/v1/tenants/demo-north/metadata/accounts',
    ]) {
      expect((await h(request(path,'POST',signed))).status).toBe(404);
    }
    for (const method of ['PUT','OPTIONS','GET']) {
      const res = method === 'GET'
        ? await h(new Request(ORIGIN+PATH,{
          headers: { Authorization: 'Bearer '+signed },
        }))
        : await h(request(PATH,method,signed));
      expect(res.status).toBe(405);
      expect(res.headers.get('Allow')).toBe('POST, PATCH, DELETE');
    }
    expect((await h(request(PATH,'POST',signed,{name:'X'},{
      headers:{Origin:'https://attacker.example.test'},
    }))).status).toBe(403);
    expect((await h(request(PATH,'POST',signed,{name:'X'},{
      headers:{'Sec-Fetch-Site':'cross-site'},
    }))).status).toBe(403);
    for (const name of [
      'Idempotency-Key','X-Attempt-ID','X-Actor-ID','X-Tenant-ID',
      'X-Role','X-Correlation-ID','Cookie',
    ]) {
      const res = await h(request(PATH,'POST',signed,{name:'X'},{
        headers:{[name]:'attacker-controlled'},
      }));
      expect(res.status).toBe(404);
    }
    expect(f.writes).toHaveLength(0);
  });

  ciTest('exact bounded JSON shape, CAS version, unsafe values and size caps fail closed', async () => {
    const f = fixture();
    const h = f.create();
    const jwt = await token();
    const bad: Array<[string,unknown]> = [
      ['POST',{}],['POST',{name:''}],['POST',{name:'bad\nname'}],
      ['POST',{name:' X '}],['POST',{name:'x'.repeat(121)}],
      ['POST',{name:'X', role:'tenant-owner'}],
      ['POST',{name:'X', expectedVersion:1}],
      ['POST',null],['POST',[{name:'X'}]],
      ['PATCH',{name:'x'}],
      ['PATCH',{name:'x',expectedVersion:0}],
      ['PATCH',{name:'x',expectedVersion:2.5}],
      ['PATCH',{name:'x',expectedVersion:9_007_199_254_740_991}],
      ['PATCH',{name:'x',expectedVersion:1,attemptId:'fake'}],
      ['DELETE',{expectedVersion:-1}],
      ['DELETE',{expectedVersion:1,name:'forbidden'}],
      ['DELETE',{name:'X'}],
    ];
    for(const [method,dto] of bad) {
      const r=await h(request(PATH,method,jwt,dto));
      expect(r.status).toBe(404);
    }
    for(const raw of ['{', '{ "name":"x",', JSON.stringify({name:'x'.repeat(600)})]) {
      expect((await h(request(PATH,'POST',jwt,undefined,{raw}))).status).toBe(404);
    }
    expect((await h(request(PATH,'POST',jwt,{name:'X'},{
      headers:{'Content-Type':'text/plain'},
    }))).status).toBe(404);
    expect((await h(request(PATH,'POST',jwt,{name:'X'},{
      headers:{'Content-Length':'9999'},
    }))).status).toBe(404);
    expect(f.writes).toHaveLength(0);
  });

  ciTest('writer conflict, unknown COMMIT and cancellation sanitize responses; no retry', async () => {
    const f = fixture();
    const h = f.create();
    const jwt = await token();
    f.setMode('deny');
    expect((await h(request(PATH,'POST',jwt))).status).toBe(404);
    f.setMode('throw');
    const unknown = await h(request(PATH,'POST',jwt));
    expect(unknown.status).toBe(503);
    expect(JSON.stringify(await body(unknown))).not.toContain('PG_SECRET');
    f.setMode('success');
    const ctrl = new AbortController();
    ctrl.abort();
    const cancelled = await h(request(PATH,'POST',jwt,{name:'X'},{
      signal:ctrl.signal,
    }));
    expect(cancelled.status).toBe(503);
    expect(f.writes).toHaveLength(2);
    const race = new AbortController();
    f.setAbort(() => race.abort());
    f.setMode('abort');
    const pending = await h(request(PATH,'POST',jwt,{name:'X'},{
      signal:race.signal,
    }));
    expect(pending.status).toBe(503);
    expect(f.writes).toHaveLength(3);
    // Never transparently retry even though the mock reported true.
  });

  ciTest('real loopback TCP serves ONLY the opt-in CI handler with no CORS or cookies', async () => {
    const f = fixture();
    const h = f.create();
    const server = Bun.serve({
      hostname:'127.0.0.1', port:0, fetch:h,
    });
    try {
      const jwt = await token();
      const response = await fetch(
        'http://127.0.0.1:'+server.port+PATH,
        { method:'POST', headers: {
          Authorization:'Bearer '+jwt, 'Content-Type':'application/json',
        }, body:JSON.stringify({name:'Real CI loopback'}) },
      );
      expect(response.status).toBe(201);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull();
      expect(response.headers.get('Set-Cookie')).toBeNull();
      expect(JSON.stringify(await body(response))).not.toContain(jwt);
      expect(f.writes).toHaveLength(1);
    } finally {
      server.stop(true);
    }
  });
});
