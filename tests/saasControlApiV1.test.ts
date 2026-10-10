import { describe, expect, test } from 'bun:test';
import type {
  AccessGrant, BlueprintSnapshot, EgressProfile, ProviderAccount,
} from '../src/features/saasBlueprint/domain';
import {
  authorizeTenantRead, mayViewTenantResource,
} from '../src/features/saasBlueprint/controlApi/authorization';
import type {
  ControlActor, ControlCollection, ControlResource, TenantRole,
} from '../src/features/saasBlueprint/controlApi/contracts';
import {
  listAccessibleTenants, readSyntheticTenantCollection,
} from '../src/features/saasBlueprint/controlApi/readOnlyProjection';
import {
  DEMO_CLOCK, DEMO_SNAPSHOT,
} from '../src/features/saasBlueprint/demo/demoData';

const north: ControlActor = {
  id: 'actor-north',
  memberships: [{ tenantId: 'demo-north', role: 'tenant-admin', status: 'active' }],
};
const orbit: ControlActor = {
  id: 'actor-orbit',
  memberships: [{ tenantId: 'demo-orbit', role: 'tenant-viewer', status: 'active' }],
};
const auditor: ControlActor = {
  id: 'actor-auditor',
  memberships: [{ tenantId: 'demo-north', role: 'tenant-auditor', status: 'active' }],
};
const sharedGrants = DEMO_SNAPSHOT.accessGrants;

function result(
  collection: ControlCollection,
  actor: ControlActor = north,
  snapshot: BlueprintSnapshot = DEMO_SNAPSHOT,
  tenantId = 'demo-north',
  nowMs = DEMO_CLOCK
) {
  return readSyntheticTenantCollection(snapshot, actor, tenantId, collection, nowMs);
}

function data(
  collection: ControlCollection,
  actor: ControlActor = north,
  snapshot: BlueprintSnapshot = DEMO_SNAPSHOT,
  tenantId = 'demo-north',
  nowMs = DEMO_CLOCK
): readonly ControlResource[] {
  const response = result(collection, actor, snapshot, tenantId, nowMs);
  if (!response.ok) throw new Error('Unexpected denied fixture response: ' + response.error.code);
  expect(response.source).toBe('synthetic-simulation');
  expect(response.apiVersion).toBe(1);
  return response.data;
}

function grantedExcept(resourceKind: AccessGrant['resourceKind']): BlueprintSnapshot {
  return {
    ...DEMO_SNAPSHOT,
    accessGrants: sharedGrants.filter((grant) => grant.resourceKind !== resourceKind),
  };
}

describe('SaaS Control API v1 — contracts ONLY (no backend or network)', () => {
  test('tenant index includes only unique active memberships, never global tenant list', () => {
    expect(listAccessibleTenants(DEMO_SNAPSHOT, north).map((item) => item.id)).toEqual(['demo-north']);
    expect(listAccessibleTenants(DEMO_SNAPSHOT, orbit).map((item) => item.id)).toEqual(['demo-orbit']);
    expect(listAccessibleTenants(DEMO_SNAPSHOT, {
      id: 'multi-user', memberships: [...north.memberships, ...orbit.memberships],
    }).map((item) => item.id)).toEqual(['demo-north', 'demo-orbit']);
    const conflicting: ControlActor = {
      id: 'bad-actor', memberships: [...north.memberships, ...north.memberships],
    };
    expect(listAccessibleTenants(DEMO_SNAPSHOT, conflicting)).toEqual([]);
    expect(listAccessibleTenants(DEMO_SNAPSHOT, {
      id: 'revoked', memberships: [{ ...north.memberships[0], status: 'revoked' }],
    })).toEqual([]);
  });

  test('trusted tenant scope, role matrix and fail-closed absence or duplicate membership', () => {
    expect(authorizeTenantRead(north, 'demo-north', 'accounts').allowed).toBe(true);
    expect(authorizeTenantRead(auditor, 'demo-north', 'projects').allowed).toBe(true);
    for (const collection of ['client-keys', 'accounts', 'pools', 'egress', 'routing'] as const) {
      expect(result(collection, auditor)).toEqual({
        ok: false, status: 403,
        error: { code: 'FORBIDDEN', message: 'Permission denied' },
      });
    }
    const stranger: ControlActor = { id: 'stranger', memberships: [] };
    const duplicate: ControlActor = {
      id: 'duplicate', memberships: [...north.memberships, ...north.memberships],
    };
    const revoked: ControlActor = {
      id: 'revoked', memberships: [{ ...north.memberships[0], status: 'revoked' }],
    };
    for (const actor of [stranger, duplicate, revoked, { id: '', memberships: north.memberships }]) {
      expect(result('accounts', actor)).toEqual({
        ok: false, status: 404,
        error: { code: 'NOT_FOUND', message: 'Resource unavailable' },
      });
    }
    expect(result('accounts', north, DEMO_SNAPSHOT, 'demo-orbit')).toMatchObject({
      ok: false, status: 404, error: { code: 'NOT_FOUND' },
    });
    expect(authorizeTenantRead(north, 'demo-north', 'unknown' as ControlCollection).allowed).toBe(false);
    expect(authorizeTenantRead({
      id: 'bad-role', memberships: [{ tenantId: 'demo-north', role: 'invalid' as TenantRole, status: 'active' }],
    }, 'demo-north', 'tenant').allowed).toBe(false);
  });

  test('read-only tenant, project and application metadata is tenant-scoped', () => {
    expect(data('tenant')).toMatchObject([{
      kind: 'tenant', id: 'demo-north', name: 'North Studio', role: 'tenant-admin',
    }]);
    expect(data('projects')).toMatchObject([{
      kind: 'project', id: 'project-north', tenantId: 'demo-north',
    }]);
    expect(data('applications')).toMatchObject([{
      kind: 'application', id: 'app-north', projectId: 'project-north',
    }]);
    expect(JSON.stringify(data('projects'))).not.toContain('project-orbit');
    expect(JSON.stringify(data('applications'))).not.toContain('app-orbit');
    expect(data('projects', orbit, DEMO_SNAPSHOT, 'demo-orbit'))
      .toMatchObject([{ id: 'project-orbit' }]);
  });

  test('shows CPA binding references but never native Core key bindings or plaintext', () => {
    expect(data('client-keys')).toEqual([{
      kind: 'client-key', id: 'key-north', applicationId: 'app-north',
      status: 'active', keyType: 'cpa',
    }]);
    const withNative: BlueprintSnapshot = {
      ...DEMO_SNAPSHOT,
      keyBindings: [
        ...DEMO_SNAPSHOT.keyBindings,
        { id: 'native-private', tenantId: 'demo-north', applicationId: 'app-north',
          kind: 'core-native', status: 'active' },
      ],
      routingBindings: [
        ...DEMO_SNAPSHOT.routingBindings,
        { ...DEMO_SNAPSHOT.routingBindings[0], id: 'native-route', keyBindingId: 'native-private' },
      ],
    };
    expect(JSON.stringify(data('client-keys', north, withNative))).not.toContain('native-private');
    expect(JSON.stringify(data('routing', north, withNative))).not.toContain('native-route');
  });

  test('owned and explicitly shared accounts, pools and egress stay separate', () => {
    const accounts = data('accounts');
    expect(accounts.map((item) => item.id)).toEqual([
      'account-north', 'account-north-oauth', 'account-platform',
    ]);
    expect(accounts.find((item) => item.id === 'account-platform')).toMatchObject({
      owner: { kind: 'platform', tenantName: null, access: 'explicit-grant' },
      egressProfileId: 'proxy-platform',
    });
    expect(data('pools').find((item) => item.id === 'pool-platform')).toMatchObject({
      accountIds: ['account-platform'],
    });
    expect(data('egress').find((item) => item.id === 'proxy-platform')).toMatchObject({
      publicEndpoint: 'HTTPS · proxy.example.net:443',
    });
    for (const collection of ['accounts', 'pools', 'egress'] as const) {
      const serialized = JSON.stringify(data(collection));
      expect(serialized).not.toContain('account-orbit');
      expect(serialized).not.toContain('pool-orbit');
      expect(serialized).not.toContain('proxy-orbit');
      expect(serialized).not.toContain('vpn-orbit');
    }
    const orbitAccounts = data('accounts', orbit, DEMO_SNAPSHOT, 'demo-orbit');
    expect(orbitAccounts.map((item) => item.id).sort())
      .toEqual(['account-orbit', 'account-orbit-vpn']);
    expect(JSON.stringify(orbitAccounts)).not.toContain('account-north');
    expect(JSON.stringify(orbitAccounts)).not.toContain('account-platform');
  });

  test('pool grant NEVER grants member account identities implicitly', () => {
    const snapshot = grantedExcept('account');
    expect(data('pools', north, snapshot).find((item) => item.id === 'pool-platform'))
      .toMatchObject({ accountIds: [] });
    expect(JSON.stringify(data('accounts', north, snapshot))).not.toContain('account-platform');
  });

  test('account grant NEVER shares egress or pool automatically', () => {
    const snapshot = { ...grantedExcept('egress'),
      accessGrants: sharedGrants.filter((grant) => grant.resourceKind === 'account') };
    const account = data('accounts', north, snapshot).find((item) => item.id === 'account-platform');
    expect(account).toMatchObject({ egressProfileId: null });
    expect(JSON.stringify(data('egress', north, snapshot))).not.toContain('proxy-platform');
    expect(JSON.stringify(data('pools', north, snapshot))).not.toContain('pool-platform');
  });

  test('routing must redact a pool without a distinct grant', () => {
    const snapshot: BlueprintSnapshot = {
      ...grantedExcept('pool'),
      routingBindings: DEMO_SNAPSHOT.routingBindings.map((item) =>
        item.tenantId === 'demo-north' ? { ...item, poolId: 'pool-platform' } : item),
    };
    expect(data('routing', north, snapshot)).toMatchObject([{
      kind: 'routing', poolId: null, applicationId: 'app-north', keyBindingId: 'key-north',
    }]);
    expect(JSON.stringify(data('routing', north, snapshot))).not.toContain('pool-platform');
  });

  test('foreign ownership does not become visible through a same-name or misattributed grant', () => {
    const rogue: BlueprintSnapshot = {
      ...DEMO_SNAPSHOT,
      accessGrants: [{
        id: 'bad-grant', owner: { kind: 'tenant', tenantId: 'demo-north' },
        granteeTenantId: 'demo-north', resourceKind: 'account',
        resourceId: 'account-orbit', status: 'active',
      }],
    };
    expect(JSON.stringify(data('accounts', north, rogue))).not.toContain('account-orbit');
  });

  test('expired, invalid, disabled, wrong-tenant or wrong-owner grants fail closed', () => {
    for (const overrides of [
      { expiresAt: '2026-10-09T00:00:00Z' },
      { expiresAt: 'not-a-timestamp' },
      { status: 'disabled' as const },
      { granteeTenantId: 'demo-orbit' },
      { owner: { kind: 'tenant', tenantId: 'demo-orbit' } as const },
    ]) {
      const snapshot: BlueprintSnapshot = {
        ...DEMO_SNAPSHOT,
        accessGrants: sharedGrants.map((grant) => grant.resourceKind === 'account'
          ? { ...grant, ...overrides } : grant),
      };
      expect(JSON.stringify(data('accounts', north, snapshot))).not.toContain('account-platform');
    }
    expect(result('accounts', north, DEMO_SNAPSHOT, 'demo-north', Number.NaN))
      .toMatchObject({ ok: false, status: 503, error: { code: 'SOURCE_UNAVAILABLE' } });
  });

  test('tenant suspended and invalid source version do not expose any rows', () => {
    const suspended = {
      ...DEMO_SNAPSHOT,
      tenants: DEMO_SNAPSHOT.tenants.map((entry) =>
        entry.id === 'demo-north' ? { ...entry, status: 'suspended' as const } : entry),
    };
    expect(result('accounts', north, suspended)).toMatchObject({
      ok: false, status: 403, error: { code: 'TENANT_UNAVAILABLE' },
    });
    expect(listAccessibleTenants(suspended, north)).toEqual([]);
    const unsupported = { ...DEMO_SNAPSHOT, schemaVersion: 2 as unknown as 1 };
    expect(result('accounts', north, unsupported)).toMatchObject({
      ok: false, status: 503, error: { code: 'SOURCE_UNAVAILABLE' },
    });
    expect(result('accounts', north, DEMO_SNAPSHOT, 'demo-north', Infinity))
      .toMatchObject({ ok: false, status: 503 });
    expect(result('tenant', north, DEMO_SNAPSHOT, 'not-a-tenant'))
      .toMatchObject({ ok: false, status: 404 });
    expect(result('unknown' as ControlCollection))
      .toMatchObject({ ok: false, status: 404 });
  });

  test('orphaned cross-tenant project references and account egress IDs remain hidden', () => {
    const orphan: BlueprintSnapshot = {
      ...DEMO_SNAPSHOT,
      applications: [
        ...DEMO_SNAPSHOT.applications,
        { id: 'app-orphan', tenantId: 'demo-north', projectId: 'project-orbit',
          name: 'Orphan App', status: 'active' },
      ],
      providerAccounts: DEMO_SNAPSHOT.providerAccounts.map((item) =>
        item.id === 'account-north' ? { ...item, egressProfileId: 'proxy-orbit' } : item),
    };
    expect(JSON.stringify(data('applications', north, orphan))).not.toContain('app-orphan');
    expect(data('accounts', north, orphan).find((item) => item.id === 'account-north'))
      .toMatchObject({ egressProfileId: null });
  });

  test('every response is a whitelist: injected secrets, OAuth, proxy userinfo and prompts vanish', () => {
    const dangerousAccount: ProviderAccount & Record<string, unknown> = {
      ...DEMO_SNAPSHOT.providerAccounts[0],
      apiKey: 'NEVER_SHOW_API_KEY',
      oauthAccessToken: 'NEVER_SHOW_OAUTH',
      rawPrompt: 'NEVER_SHOW_PROMPT',
    };
    const dangerousEgress: EgressProfile & Record<string, unknown> = {
      ...DEMO_SNAPSHOT.egressProfiles[0],
      password: 'NEVER_SHOW_PROXY_PASSWORD',
      endpoint: { hostname: 'user:NEVER_SHOW_USERINFO@proxy.vendor.net', port: 1080 },
    };
    const snapshot: BlueprintSnapshot = {
      ...DEMO_SNAPSHOT,
      providerAccounts: [dangerousAccount, ...DEMO_SNAPSHOT.providerAccounts.slice(1)],
      egressProfiles: [dangerousEgress, ...DEMO_SNAPSHOT.egressProfiles.slice(1)],
    };
    const payload = JSON.stringify([
      data('accounts', north, snapshot),
      data('pools', north, snapshot),
      data('egress', north, snapshot),
      data('routing', north, snapshot),
    ]);
    for (const secret of ['NEVER_SHOW_API_KEY', 'NEVER_SHOW_OAUTH',
      'NEVER_SHOW_PROMPT', 'NEVER_SHOW_PROXY_PASSWORD', 'NEVER_SHOW_USERINFO']) {
      expect(payload).not.toContain(secret);
    }
    expect(payload).toContain('Invalid proxy endpoint');
  });

  test('no accidental request state, transport or backend is invoked by the projection', () => {
    const response = result('accounts');
    expect(response.ok).toBe(true);
    if (response.ok) {
      expect(Object.keys(response).sort()).toEqual([
        'apiVersion', 'collection', 'data', 'ok', 'source', 'status', 'tenantId',
      ]);
    }
    expect(mayViewTenantResource(DEMO_SNAPSHOT, 'demo-north', 'account',
      'account-platform', { kind: 'platform' }, DEMO_CLOCK)).toBe(true);
    expect(mayViewTenantResource(DEMO_SNAPSHOT, 'demo-orbit', 'account',
      'account-platform', { kind: 'platform' }, DEMO_CLOCK)).toBe(false);
    expect(mayViewTenantResource(DEMO_SNAPSHOT, 'demo-north', 'account',
      'account-platform', { kind: 'platform' }, Number.NaN)).toBe(false);
  });

  test('tenant switching re-evaluates access without retaining foreign identifiers', () => {
    const before = data('accounts');
    const another = data('accounts', orbit, DEMO_SNAPSHOT, 'demo-orbit');
    const after = data('accounts');
    expect(before).toEqual(after);
    expect(JSON.stringify(another)).not.toContain('account-platform');
    expect(JSON.stringify(before)).not.toContain('account-orbit');
  });
});
