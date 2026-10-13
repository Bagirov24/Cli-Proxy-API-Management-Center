import { describe, expect, test } from 'bun:test';
import type { ControlActor } from '../src/features/saasBlueprint/controlApi/contracts';
import {
  createM1ProjectCommandBoundary,
  type M1ProjectCommand, type M1ProjectMutation,
} from '../src/features/saasBlueprint/controlApi/server/m1ProjectCommandBoundary';

const north: ControlActor = {
  id: 'actor-north', memberships: [
    { tenantId: 'demo-north', role: 'tenant-admin', status: 'active' },
  ],
};
const viewer: ControlActor = {
  id: 'actor-orbit', memberships: [
    { tenantId: 'demo-orbit', role: 'tenant-viewer', status: 'active' },
  ],
};
const auditor: ControlActor = {
  id: 'actor-auditor', memberships: [
    { tenantId: 'demo-north', role: 'tenant-auditor', status: 'active' },
  ],
};

const tokens: Readonly<Record<string, string>> = {
  'signed-north': 'sub-north',
  'signed-orbit': 'sub-orbit',
  'signed-auditor': 'sub-auditor',
};
const directory: Readonly<Record<string, string>> = {
  'sub-north': north.id, 'sub-orbit': viewer.id, 'sub-auditor': auditor.id,
};

function fixture() {
  const actors = new Map<string, ControlActor>(
    [north, viewer, auditor].map(actor => [
      actor.id, { ...actor, memberships: actor.memberships.map(x => ({ ...x })) },
    ])
  );
  const writes: M1ProjectMutation[] = [];
  let lookups = 0;
  let beforeSecondLookup: (() => void) | undefined;
  let directoryChanged = false;
  let writerOutcome: 'true' | 'false' | 'throw' | 'abort' = 'true';
  const controller = new AbortController();
  const handler = createM1ProjectCommandBoundary({
    tokens: {
      async verifyAccessToken(token) {
        const subject = tokens[token];
        return subject ? {
          issuer: 'https://synthetic-issuer.example.test/', subject,
          expiresAtSeconds: 2_000_000_000,
        } : null;
      },
    },
    directory: {
      async resolveActorId(identity) {
        return directoryChanged ? 'actor-orbit' : directory[identity.subject] ?? null;
      },
    },
    actors: {
      async lookup(id) {
        lookups += 1;
        if (lookups === 2) beforeSecondLookup?.();
        return actors.get(id) ?? null;
      },
    },
    writer: {
      async execute(input) {
        writes.push(input);
        if (writerOutcome === 'throw') throw new Error('PG PRIVATE SECRET: never return');
        if (writerOutcome === 'abort') controller.abort();
        return writerOutcome !== 'false';
      },
    },
    newCorrelationId: () => 'm1-correlation-server-only',
  });
  const issue = (overrides: Partial<M1ProjectCommand> = {}): M1ProjectCommand => {
    const operation = overrides.operation ?? 'create';
    const args = {
      operation, accessToken: 'signed-north',
      tenantId: 'demo-north', projectId: 'project-m1',
      // disable has no name by design. Preserve an explicitly supplied
      // forbidden name in negative tests instead of silently discarding it.
      ...(operation === 'disable' ? {} : { name: 'Test project' }),
      signal: controller.signal, ...overrides,
    };
    return args as M1ProjectCommand;
  };
  return {
    handler, actors, writes, controller, issue,
    revokeBeforeWrite() {
      beforeSecondLookup = () => {
        actors.set('actor-north', {
          ...north, memberships: [
            { tenantId: 'demo-north', role: 'tenant-admin', status: 'revoked' },
          ],
        });
      };
    },
    changeDirectory() { directoryChanged = true; },
    writerOutcome(value: typeof writerOutcome) { writerOutcome = value; },
  };
}

describe('M1a server-only tenant project write boundary (no deployed API)', () => {
  test('verified synthetic issuer/subject resolves server actor, not request role or JWT claims', async () => {
    const f = fixture();
    const spoofed = {
      ...f.issue(),
      actorId: 'admin-forged',
      role: 'tenant-owner',
      claims: { tenantId: 'demo-orbit', role: 'tenant-owner' },
    };
    const result = await f.handler(spoofed);
    expect(result).toEqual({
      ok: true, status: 201, correlationId: 'm1-correlation-server-only',
    });
    expect(f.writes).toHaveLength(1);
    const [write] = f.writes;
    expect(write.scope).toEqual({
      actorId: 'actor-north', tenantId: 'demo-north',
      role: 'tenant-admin', correlationId: 'm1-correlation-server-only',
    });
    expect(write.projectId).toBe('project-m1');
    expect(write.name).toBe('Test project');
    expect(write.signal).toBe(f.controller.signal);
    expect(JSON.stringify(write)).not.toContain('signed-north');
    expect(JSON.stringify(write)).not.toContain('admin-forged');
    expect(JSON.stringify(result)).not.toContain('project-m1');
  });

  test('create/rename/disable carry only bounded project fields and CAS version', async () => {
    for (const operation of ['create', 'rename', 'disable'] as const) {
      const f = fixture();
      const args = operation === 'create' ? f.issue() :
        operation === 'rename'
          ? f.issue({ operation, expectedVersion: 2, name: 'Renamed' })
          : f.issue({ operation, expectedVersion: 3 });
      const result = await f.handler(args);
      expect(result.ok).toBe(true);
      expect(result.status).toBe(operation === 'create' ? 201 : 200);
      expect(f.writes[0].operation).toBe(operation);
      expect(f.writes[0].expectedVersion).toBe(operation === 'create' ? undefined :
        operation === 'rename' ? 2 : 3);
      expect(f.writes[0].name).toBe(operation === 'disable' ? undefined :
        operation === 'rename' ? 'Renamed' : 'Test project');
    }
  });

  test('unverified, malformed, oversized bearer or forged directory actor never writes', async () => {
    const f = fixture();
    for (const accessToken of ['', 'bearer-not-a-jwt', 'a'.repeat(9000)]) {
      const response = await f.handler(f.issue({ accessToken }));
      expect(response.ok).toBe(false);
      expect(response.status).toBe(401);
    }
    const b = fixture();
    b.changeDirectory();
    // North bearer now resolves to Orbit viewer; cannot write North.
    const response = await b.handler(b.issue());
    expect(response.status).toBe(404);
    expect(f.writes).toHaveLength(0);
    expect(b.writes).toHaveLength(0);
  });

  test('tenant viewer, auditor, cross-tenant, revoked and ambiguous grants denied', async () => {
    const f = fixture();
    const viewerResult = await f.handler(f.issue({
      accessToken: 'signed-orbit', tenantId: 'demo-orbit',
    }));
    expect(viewerResult.status).toBe(404);
    const auditorResult = await f.handler(f.issue({
      accessToken: 'signed-auditor', tenantId: 'demo-north',
    }));
    expect(auditorResult.status).toBe(404);
    const crossTenant = await f.handler(f.issue({ tenantId: 'demo-orbit' }));
    expect(crossTenant.status).toBe(404);

    f.actors.set(north.id, {
      ...north, memberships: [
        { tenantId: 'demo-north', role: 'tenant-admin', status: 'revoked' },
      ],
    });
    expect((await f.handler(f.issue())).status).toBe(404);
    f.actors.set(north.id, {
      ...north, memberships: [north.memberships[0], north.memberships[0]],
    });
    expect((await f.handler(f.issue())).status).toBe(404);
    expect(f.writes).toHaveLength(0);
  });

  test('role revoked while token/directory verification awaits is denied before writer', async () => {
    const f = fixture();
    f.revokeBeforeWrite();
    const response = await f.handler(f.issue());
    expect(response.status).toBe(404);
    expect(f.writes).toHaveLength(0);
  });

  test('unsafe project names, IDs, versions and forbidden command body denied', async () => {
    const invalid: Partial<M1ProjectCommand>[] = [
      { projectId: '../other' }, { tenantId: 'demo/north' },
      { name: '' }, { name: ' spaced' }, { name: 'a'.repeat(121) },
      { name: 'newline\nunsafe' }, { name: 'secret\u0000data' },
      { operation: 'rename', expectedVersion: 0 },
      { operation: 'rename', expectedVersion: -1 },
      { operation: 'disable', expectedVersion: 0 },
      { operation: 'disable', name: 'not-allowed' } as unknown as Partial<M1ProjectCommand>,
      { operation: 'rename', expectedVersion: Number.MAX_SAFE_INTEGER },
    ];
    for (const override of invalid) {
      const f = fixture();
      const result = await f.handler(f.issue(override));
      expect(result.status).toBe(404);
      expect(f.writes).toHaveLength(0);
    }
  });

  test('abort and uncertain SQL failures never return success or expose diagnostics', async () => {
    const cancelled = fixture();
    cancelled.controller.abort();
    expect((await cancelled.handler(cancelled.issue())).status).toBe(503);
    expect(cancelled.writes).toHaveLength(0);

    for (const state of ['false', 'throw', 'abort'] as const) {
      const f = fixture();
      f.writerOutcome(state);
      const response = await f.handler(f.issue());
      expect(response.ok).toBe(false);
      expect(response.status).toBe(state === 'false' ? 404 : 503);
      expect(JSON.stringify(response)).not.toContain('PG PRIVATE SECRET');
      expect(JSON.stringify(response)).not.toContain('signed-north');
      expect(f.writes).toHaveLength(1);
    }
  });

  test('required verifier/directory/writer dependencies are mandatory', () => {
    expect(() => createM1ProjectCommandBoundary({} as never)).toThrow(
      'M1a requires a trusted verifier'
    );
  });
});
