import { describe, expect, test } from 'bun:test';
import type {
  AccessGrant,
  BlueprintSnapshot,
  RouteRequest,
  RoutingBinding,
} from '../src/features/saasBlueprint/domain';
import { resolveSaasRoute } from '../src/features/saasBlueprint/resolveRoute';
import { safeDecisionPreview } from '../src/features/saasBlueprint/safeDecisionPreview';

const NOW = Date.parse('2026-10-10T12:00:00Z');
const ownerA = { kind: 'tenant', tenantId: 'tenant-a' } as const;
const ownerB = { kind: 'tenant', tenantId: 'tenant-b' } as const;
const platform = { kind: 'platform' } as const;

const base: BlueprintSnapshot = {
  schemaVersion: 1,
  tenants: [
    { id: 'tenant-a', name: 'Tenant A', status: 'active', allowDirectEgress: false },
    { id: 'tenant-b', name: 'Tenant B', status: 'active', allowDirectEgress: false },
  ],
  projects: [
    { id: 'project-a', tenantId: 'tenant-a', name: 'A', status: 'active' },
    { id: 'project-b', tenantId: 'tenant-b', name: 'B', status: 'active' },
  ],
  applications: [
    { id: 'app-a', tenantId: 'tenant-a', projectId: 'project-a', name: 'Bot A', status: 'active' },
    { id: 'app-b', tenantId: 'tenant-b', projectId: 'project-b', name: 'Bot B', status: 'active' },
  ],
  keyBindings: [
    { id: 'key-a', tenantId: 'tenant-a', applicationId: 'app-a', kind: 'cpa', status: 'active' },
    { id: 'key-b', tenantId: 'tenant-b', applicationId: 'app-b', kind: 'cpa', status: 'active' },
    { id: 'native-a', tenantId: 'tenant-a', applicationId: 'app-a', kind: 'core-native', status: 'active' },
  ],
  providerAccounts: [
    {
      id: 'account-a', owner: ownerA, providerId: 'demo-provider',
      authMode: 'provider-api-key', authorizationStatus: 'approved', status: 'active',
      allowedModelIds: ['demo-model'], egressProfileId: 'proxy-a',
    },
    {
      id: 'account-b', owner: ownerB, providerId: 'demo-provider',
      authMode: 'provider-oauth', authorizationStatus: 'approved', status: 'active',
      allowedModelIds: ['demo-model'], egressProfileId: 'vpn-b',
    },
    {
      id: 'account-shared', owner: platform, providerId: 'demo-provider',
      authMode: 'provider-api-key', authorizationStatus: 'approved', status: 'active',
      allowedModelIds: ['demo-model'], egressProfileId: 'proxy-shared',
    },
  ],
  accountPools: [
    { id: 'pool-a', owner: ownerA, status: 'active', providerId: 'demo-provider', accountIds: ['account-a'] },
    { id: 'pool-b', owner: ownerB, status: 'active', providerId: 'demo-provider', accountIds: ['account-b'] },
    { id: 'pool-shared', owner: platform, status: 'active', providerId: 'demo-provider', accountIds: ['account-shared'] },
  ],
  egressProfiles: [
    {
      id: 'proxy-a', owner: ownerA, name: 'Private A', kind: 'socks5',
      status: 'active', health: 'healthy', endpoint: { hostname: 'proxy.vendor.net', port: 1080 },
    },
    {
      id: 'vpn-b', owner: ownerB, name: 'VPN B', kind: 'vpn-connector',
      status: 'active', health: 'healthy', connectorId: 'vpn-b',
    },
    {
      id: 'proxy-shared', owner: platform, name: 'Shared proxy', kind: 'https',
      status: 'active', health: 'healthy', endpoint: { hostname: 'proxy.vendor.net', port: 443 },
    },
  ],
  accessGrants: [],
  routingBindings: [
    {
      id: 'route-a', tenantId: 'tenant-a', applicationId: 'app-a', keyBindingId: 'key-a',
      poolId: 'pool-a', providerId: 'demo-provider', requestedModelId: 'demo-model',
      status: 'active', egressPolicy: 'required',
    },
    {
      id: 'route-b', tenantId: 'tenant-b', applicationId: 'app-b', keyBindingId: 'key-b',
      poolId: 'pool-b', providerId: 'demo-provider', requestedModelId: 'demo-model',
      status: 'active', egressPolicy: 'required',
    },
  ],
};

const requestA: RouteRequest = {
  tenantId: 'tenant-a',
  applicationId: 'app-a',
  keyBindingId: 'key-a',
  requestedModelId: 'demo-model',
  selectedAccountId: 'account-a',
};

const requestB: RouteRequest = {
  tenantId: 'tenant-b',
  applicationId: 'app-b',
  keyBindingId: 'key-b',
  requestedModelId: 'demo-model',
  selectedAccountId: 'account-b',
};

function decision(
  snapshot: BlueprintSnapshot = base,
  input: RouteRequest = requestA,
  verifiedVpnConnectorIds: readonly string[] = []
) {
  return resolveSaasRoute(snapshot, input, {
    nowMs: NOW,
    runtime: { verifiedVpnConnectorIds },
  });
}
function withSnapshot(overrides: Partial<BlueprintSnapshot>): BlueprintSnapshot {
  return { ...base, ...overrides };
}
function withRoute(changes: Partial<RoutingBinding>): BlueprintSnapshot {
  return withSnapshot({ routingBindings: [{ ...base.routingBindings[0], ...changes }] });
}
function grant(
  resourceKind: AccessGrant['resourceKind'],
  resourceId: string,
  overrides: Partial<AccessGrant> = {}
): AccessGrant {
  return {
    id: 'grant-' + resourceKind,
    resourceKind,
    resourceId,
    owner: platform,
    granteeTenantId: 'tenant-a',
    status: 'active',
    ...overrides,
  };
}

describe('SaaS Blueprint routing prototype (synthetic data only)', () => {
  test('allows an owned CPA account and required healthy proxy', () => {
    expect(decision()).toEqual({
      allowed: true,
      stage: 'egress',
      routeBindingId: 'route-a',
      accountPoolId: 'pool-a',
      providerAccountId: 'account-a',
      egressProfileId: 'proxy-a',
      providerId: 'demo-provider',
      modelId: 'demo-model',
    });
  });

  test('rejects an account owned by another tenant even when placed in a pool', () => {
    const snapshot = withSnapshot({
      accountPools: [{ ...base.accountPools[0], accountIds: ['account-a', 'account-b'] }],
    });
    expect(decision(snapshot, { ...requestA, selectedAccountId: 'account-b' })).toMatchObject({
      allowed: false, reason: 'account-forbidden',
    });
  });

  test('rejects a foreign account pool without an explicit pool grant', () => {
    const snapshot = withRoute({ poolId: 'pool-b' });
    expect(decision(snapshot, { ...requestA, selectedAccountId: 'account-b' })).toMatchObject({
      allowed: false, reason: 'pool-forbidden',
    });
  });

  test('rejects the other tenant egress even when the account is owned', () => {
    const snapshot = withSnapshot({
      providerAccounts: [{ ...base.providerAccounts[0], egressProfileId: 'vpn-b' }],
    });
    expect(decision(snapshot)).toMatchObject({
      allowed: false, reason: 'egress-forbidden',
    });
  });

  test('fails closed when the internal scheduler picks an account not in its pool', () => {
    expect(decision(base, { ...requestA, selectedAccountId: 'account-b' })).toMatchObject({
      allowed: false, reason: 'account-not-in-pool',
    });
  });

  test('platform resources need THREE explicit grants (pool, account, egress)', () => {
    const snapshot = withRoute({ poolId: 'pool-shared' });
    const selected = { ...requestA, selectedAccountId: 'account-shared' };
    const grants = [
      grant('pool', 'pool-shared'),
      grant('account', 'account-shared'),
      grant('egress', 'proxy-shared'),
    ];
    expect(decision(snapshot, selected)).toMatchObject({ allowed: false, reason: 'pool-forbidden' });
    expect(decision({ ...snapshot, accessGrants: grants.slice(0, 1) }, selected)).toMatchObject({
      allowed: false, reason: 'account-forbidden',
    });
    expect(decision({ ...snapshot, accessGrants: grants.slice(0, 2) }, selected)).toMatchObject({
      allowed: false, reason: 'egress-forbidden',
    });
    expect(decision({ ...snapshot, accessGrants: grants }, selected).allowed).toBe(true);
  });

  test('expired, disabled and misattributed grants never authorize cross-tenant use', () => {
    const snapshot = withRoute({ poolId: 'pool-shared' });
    const selected = { ...requestA, selectedAccountId: 'account-shared' };
    for (const broken of [
      { expiresAt: '2026-10-09T00:00:00Z' },
      { expiresAt: 'not-a-date' },
      { status: 'disabled' as const },
      { owner: ownerB },
      { granteeTenantId: 'tenant-b' },
    ]) {
      expect(decision({
        ...snapshot,
        accessGrants: [grant('pool', 'pool-shared', broken)],
      }, selected)).toMatchObject({ allowed: false, reason: 'pool-forbidden' });
    }
  });

  test('native Core api keys cannot accidentally bypass CPA SaaS policies', () => {
    expect(decision(
      withRoute({ keyBindingId: 'native-a' }),
      { ...requestA, keyBindingId: 'native-a' }
    )).toMatchObject({ allowed: false, reason: 'core-native-key-forbidden' });
  });

  test('requires active tenant, project, application and key binding', () => {
    expect(decision(withSnapshot({
      tenants: [{ ...base.tenants[0], status: 'suspended' }],
    }))).toMatchObject({ allowed: false, stage: 'tenant' });
    expect(decision(withSnapshot({
      projects: [{ ...base.projects[0], status: 'disabled' }],
    }))).toMatchObject({ allowed: false, reason: 'project-unavailable' });
    expect(decision(withSnapshot({
      applications: [{ ...base.applications[0], status: 'disabled' }],
    }))).toMatchObject({ allowed: false, reason: 'application-unavailable' });
    expect(decision(withSnapshot({
      keyBindings: [{ ...base.keyBindings[0], status: 'disabled' }],
    }))).toMatchObject({ allowed: false, reason: 'client-key-unavailable' });
  });

  test('blocks unapproved OAuth and disallowed models/providers', () => {
    expect(decision(withSnapshot({
      providerAccounts: [{ ...base.providerAccounts[0], authorizationStatus: 'unverified' }],
    }))).toMatchObject({ allowed: false, reason: 'account-auth-unapproved' });
    expect(decision(withSnapshot({
      providerAccounts: [{ ...base.providerAccounts[0], allowedModelIds: ['other-model'] }],
    }))).toMatchObject({ allowed: false, reason: 'model-forbidden' });
    expect(decision(withSnapshot({
      providerAccounts: [{ ...base.providerAccounts[0], providerId: 'different-provider' }],
    }))).toMatchObject({ allowed: false, reason: 'provider-mismatch' });
  });

  test('ambiguous policy bindings fail closed', () => {
    expect(decision(withSnapshot({
      routingBindings: [base.routingBindings[0], { ...base.routingBindings[0], id: 'duplicate-route' }],
    }))).toMatchObject({ allowed: false, reason: 'route-ambiguous' });
  });

  test('offline or unverified proxy NEVER silently falls back to direct', () => {
    for (const health of ['degraded', 'offline', 'unknown'] as const) {
      expect(decision(withSnapshot({
        egressProfiles: [{ ...base.egressProfiles[0], health }],
      }))).toMatchObject({ allowed: false, reason: 'egress-unavailable' });
    }
    expect(decision(withSnapshot({
      egressProfiles: [],
    }))).toMatchObject({ allowed: false, reason: 'egress-unavailable' });
  });

  test('rejects a direct route unless both tenant and route policy explicitly opt in', () => {
    const direct = { ...base.egressProfiles[0], kind: 'direct' as const, endpoint: undefined };
    const snapshot = withSnapshot({ egressProfiles: [direct] });
    expect(decision(snapshot)).toMatchObject({ allowed: false, reason: 'egress-direct-forbidden' });
    expect(decision({ ...snapshot, routingBindings: [{ ...base.routingBindings[0], egressPolicy: 'direct-explicit' }] }))
      .toMatchObject({ allowed: false, reason: 'egress-direct-forbidden' });
    expect(decision({
      ...snapshot,
      tenants: [{ ...base.tenants[0], allowDirectEgress: true }],
      routingBindings: [{ ...base.routingBindings[0], egressPolicy: 'direct-explicit' }],
    }).allowed).toBe(true);
  });

  test('VPN is NOT executable until an independent trusted connector is verified', () => {
    expect(decision(base, requestB)).toMatchObject({
      allowed: false, reason: 'vpn-connector-unverified',
    });
    expect(decision(base, requestB, ['vpn-b']).allowed).toBe(true);
  });

  test('invalid static proxy destination is rejected before route approval', () => {
    const snapshot = withSnapshot({
      egressProfiles: [{
        ...base.egressProfiles[0],
        endpoint: { hostname: '169.254.169.254', port: 80 },
      }],
    });
    expect(decision(snapshot)).toMatchObject({ allowed: false, reason: 'egress-invalid' });
  });

  test('UX timeline contains only allow-listed fields, no secrets or source objects', () => {
    const allowed = decision();
    if (!allowed.allowed) throw new Error('fixture routing failed');
    const annotated = {
      ...allowed,
      oauthAccessToken: 'LEAK_ME_NEVER',
      proxyPassword: 'ANOTHER_SECRET',
      rawPrompt: 'SENSITIVE_PROMPT',
    };
    const preview = safeDecisionPreview(annotated);
    const serialized = JSON.stringify(preview);
    expect(serialized).not.toContain('LEAK_ME_NEVER');
    expect(serialized).not.toContain('ANOTHER_SECRET');
    expect(serialized).not.toContain('SENSITIVE_PROMPT');
    expect(preview.mode).toBe('synthetic-simulation');
    expect(preview.steps.every((step) => step.state === 'passed')).toBe(true);

    const blocked = safeDecisionPreview(decision(base, {
      ...requestA, selectedAccountId: 'account-b',
    }));
    expect(blocked.selectedRoute).toBeNull();
    expect(blocked.steps.some((step) => step.state === 'blocked')).toBe(true);
    expect(blocked.steps.some((step) => step.state === 'not-reached')).toBe(true);
  });
});
