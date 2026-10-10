/**
 * Product design fixture, NEVER real Core state. This file is intentionally
 * self-contained, has no API imports and includes no credential material.
 */
import type {
  AccessGrant,
  BlueprintSnapshot,
  ProviderAccount,
  RouteRequest,
  Tenant,
} from '../domain';
import { resolveSaasRoute, type RouteDecision } from '../resolveRoute';
import { safeDecisionPreview, type SafeDecisionPreview } from '../safeDecisionPreview';

export const DEMO_CLOCK = Date.parse('2026-10-10T12:00:00.000Z');
const north = { kind: 'tenant', tenantId: 'demo-north' } as const;
const orbit = { kind: 'tenant', tenantId: 'demo-orbit' } as const;
const platform = { kind: 'platform' } as const;

export const DEMO_SNAPSHOT: BlueprintSnapshot = {
  schemaVersion: 1,
  tenants: [
    { id: 'demo-north', name: 'North Studio', status: 'active', allowDirectEgress: false },
    { id: 'demo-orbit', name: 'Orbit Lab', status: 'active', allowDirectEgress: false },
  ],
  projects: [
    { id: 'project-north', tenantId: 'demo-north', name: 'Customer support', status: 'active' },
    { id: 'project-orbit', tenantId: 'demo-orbit', name: 'Internal research', status: 'active' },
  ],
  applications: [
    { id: 'app-north', projectId: 'project-north', tenantId: 'demo-north', name: 'Helpdesk Bot', status: 'active' },
    { id: 'app-orbit', projectId: 'project-orbit', tenantId: 'demo-orbit', name: 'Research Assistant', status: 'active' },
  ],
  keyBindings: [
    { id: 'key-north', tenantId: 'demo-north', applicationId: 'app-north', kind: 'cpa', status: 'active' },
    { id: 'key-orbit', tenantId: 'demo-orbit', applicationId: 'app-orbit', kind: 'cpa', status: 'active' },
  ],
  providerAccounts: [
    {
      id: 'account-north', owner: north, providerId: 'demo-provider',
      authMode: 'provider-api-key', authorizationStatus: 'approved', status: 'active',
      allowedModelIds: ['demo-chat'], egressProfileId: 'proxy-north',
    },
    {
      id: 'account-north-oauth', owner: north, providerId: 'demo-provider',
      authMode: 'provider-oauth', authorizationStatus: 'unverified', status: 'active',
      allowedModelIds: ['demo-chat'], egressProfileId: 'proxy-north',
    },
    {
      id: 'account-orbit', owner: orbit, providerId: 'demo-provider',
      authMode: 'provider-api-key', authorizationStatus: 'approved', status: 'active',
      allowedModelIds: ['demo-chat'], egressProfileId: 'proxy-orbit',
    },
    {
      id: 'account-orbit-vpn', owner: orbit, providerId: 'demo-provider',
      authMode: 'provider-api-key', authorizationStatus: 'approved', status: 'active',
      allowedModelIds: ['demo-chat'], egressProfileId: 'vpn-orbit',
    },
    {
      id: 'account-platform', owner: platform, providerId: 'demo-provider',
      authMode: 'provider-api-key', authorizationStatus: 'approved', status: 'active',
      allowedModelIds: ['demo-chat'], egressProfileId: 'proxy-platform',
    },
  ],
  accountPools: [
    {
      id: 'pool-north', owner: north, providerId: 'demo-provider',
      status: 'active', accountIds: ['account-north', 'account-north-oauth'],
    },
    {
      id: 'pool-orbit', owner: orbit, providerId: 'demo-provider',
      status: 'active', accountIds: ['account-orbit', 'account-orbit-vpn'],
    },
    {
      id: 'pool-platform', owner: platform, providerId: 'demo-provider',
      status: 'active', accountIds: ['account-platform'],
    },
  ],
  egressProfiles: [
    {
      id: 'proxy-north', owner: north, name: 'EU SOCKS5 · Demo',
      kind: 'socks5', status: 'active', health: 'healthy',
      endpoint: { hostname: 'proxy.example.net', port: 1080 },
    },
    {
      id: 'proxy-north-down', owner: north, name: 'Offline proxy · Demo',
      kind: 'https', status: 'active', health: 'offline',
      endpoint: { hostname: 'proxy.example.net', port: 443 },
    },
    {
      id: 'direct-north', owner: north, name: 'Direct · Opt-in required',
      kind: 'direct', status: 'active', health: 'healthy',
    },
    {
      id: 'proxy-orbit', owner: orbit, name: 'US HTTPS · Demo',
      kind: 'https', status: 'active', health: 'healthy',
      endpoint: { hostname: 'proxy.example.net', port: 8443 },
    },
    {
      id: 'vpn-orbit', owner: orbit, name: 'VPN connector · Not deployed',
      kind: 'vpn-connector', status: 'active', health: 'unknown', connectorId: 'demo-vpn-orbit',
    },
    {
      id: 'proxy-platform', owner: platform, name: 'Shared HTTPS · Demo',
      kind: 'https', status: 'active', health: 'healthy',
      endpoint: { hostname: 'proxy.example.net', port: 443 },
    },
  ],
  accessGrants: [
    {
      id: 'grant-pool', owner: platform, resourceKind: 'pool',
      resourceId: 'pool-platform', granteeTenantId: 'demo-north', status: 'active',
    },
    {
      id: 'grant-account', owner: platform, resourceKind: 'account',
      resourceId: 'account-platform', granteeTenantId: 'demo-north', status: 'active',
    },
    {
      id: 'grant-egress', owner: platform, resourceKind: 'egress',
      resourceId: 'proxy-platform', granteeTenantId: 'demo-north', status: 'active',
    },
  ],
  routingBindings: [
    {
      id: 'route-north', tenantId: 'demo-north', applicationId: 'app-north',
      keyBindingId: 'key-north', providerId: 'demo-provider', poolId: 'pool-north',
      requestedModelId: 'demo-chat', status: 'active', egressPolicy: 'required',
    },
    {
      id: 'route-orbit', tenantId: 'demo-orbit', applicationId: 'app-orbit',
      keyBindingId: 'key-orbit', providerId: 'demo-provider', poolId: 'pool-orbit',
      requestedModelId: 'demo-chat', status: 'active', egressPolicy: 'required',
    },
  ],
};

export type DemoScenarioId =
  | 'north-owned'
  | 'north-shared'
  | 'north-foreign-account'
  | 'north-foreign-egress'
  | 'north-offline'
  | 'north-direct'
  | 'north-unapproved'
  | 'orbit-owned'
  | 'orbit-vpn';

export interface DemoScenario {
  readonly id: DemoScenarioId;
  readonly tenantId: string;
}

export const DEMO_SCENARIOS: readonly DemoScenario[] = [
  { id: 'north-owned', tenantId: 'demo-north' },
  { id: 'north-shared', tenantId: 'demo-north' },
  { id: 'north-foreign-account', tenantId: 'demo-north' },
  { id: 'north-foreign-egress', tenantId: 'demo-north' },
  { id: 'north-offline', tenantId: 'demo-north' },
  { id: 'north-direct', tenantId: 'demo-north' },
  { id: 'north-unapproved', tenantId: 'demo-north' },
  { id: 'orbit-owned', tenantId: 'demo-orbit' },
  { id: 'orbit-vpn', tenantId: 'demo-orbit' },
];

/** Only project-owned resources or ACTIVE individual access grants become visible. */
function canView(
  owner: ProviderAccount['owner'],
  tenantId: string,
  kind: AccessGrant['resourceKind'],
  id: string,
  snapshot: BlueprintSnapshot
): boolean {
  if (owner.kind === 'tenant' && owner.tenantId === tenantId) return true;
  return snapshot.accessGrants.some((grant) => (
    grant.status === 'active' &&
    grant.owner.kind === owner.kind &&
    (grant.owner.kind === 'platform' ||
      (owner.kind === 'tenant' && grant.owner.tenantId === owner.tenantId)) &&
    grant.granteeTenantId === tenantId &&
    grant.resourceKind === kind &&
    grant.resourceId === id &&
    (grant.expiresAt === undefined ||
      (Number.isFinite(Date.parse(grant.expiresAt)) && Date.parse(grant.expiresAt) > DEMO_CLOCK))
  ));
}

export interface TenantDemoView {
  readonly tenant: Tenant;
  readonly projects: BlueprintSnapshot['projects'];
  readonly applications: BlueprintSnapshot['applications'];
  readonly keys: BlueprintSnapshot['keyBindings'];
  readonly accounts: BlueprintSnapshot['providerAccounts'];
  readonly pools: BlueprintSnapshot['accountPools'];
  readonly egress: BlueprintSnapshot['egressProfiles'];
}

/** Derived per-tenant metadata ONLY. Never send full snapshot to a tenant API. */
export function selectTenantDemoView(
  snapshot: BlueprintSnapshot,
  tenantId: string
): TenantDemoView | null {
  const tenant = snapshot.tenants.find((entry) => entry.id === tenantId);
  if (!tenant) return null;
  return {
    tenant,
    projects: snapshot.projects.filter((entry) => entry.tenantId === tenantId),
    applications: snapshot.applications.filter((entry) => entry.tenantId === tenantId),
    keys: snapshot.keyBindings.filter((entry) => entry.tenantId === tenantId),
    pools: snapshot.accountPools.filter((entry) =>
      canView(entry.owner, tenantId, 'pool', entry.id, snapshot)),
    accounts: snapshot.providerAccounts.filter((entry) =>
      canView(entry.owner, tenantId, 'account', entry.id, snapshot)),
    egress: snapshot.egressProfiles.filter((entry) =>
      canView(entry.owner, tenantId, 'egress', entry.id, snapshot)),
  };
}

const NORTH_REQUEST: RouteRequest = {
  tenantId: 'demo-north', applicationId: 'app-north',
  keyBindingId: 'key-north', requestedModelId: 'demo-chat',
  selectedAccountId: 'account-north',
};
const ORBIT_REQUEST: RouteRequest = {
  tenantId: 'demo-orbit', applicationId: 'app-orbit',
  keyBindingId: 'key-orbit', requestedModelId: 'demo-chat',
  selectedAccountId: 'account-orbit',
};

/** Immutable fixture transformations, intentionally impossible to persist. */
function withAccountEgress(egressId: string): BlueprintSnapshot {
  return {
    ...DEMO_SNAPSHOT,
    providerAccounts: DEMO_SNAPSHOT.providerAccounts.map((account) =>
      account.id === 'account-north'
        ? { ...account, egressProfileId: egressId }
        : account),
  };
}
function withNorthPool(poolId: string): BlueprintSnapshot {
  return {
    ...DEMO_SNAPSHOT,
    routingBindings: DEMO_SNAPSHOT.routingBindings.map((route) =>
      route.id === 'route-north' ? { ...route, poolId } : route),
  };
}

export interface DemoRun {
  readonly scenario: DemoScenario;
  readonly decision: RouteDecision;
  readonly preview: SafeDecisionPreview;
}

export function runDemoScenario(id: DemoScenarioId): DemoRun {
  const scenario = DEMO_SCENARIOS.find((entry) => entry.id === id);
  if (!scenario) throw new Error('Unknown static demo scenario');
  let snapshot = DEMO_SNAPSHOT;
  let request = id.startsWith('orbit-') ? ORBIT_REQUEST : NORTH_REQUEST;

  switch (id) {
    case 'north-shared':
      snapshot = withNorthPool('pool-platform');
      request = { ...request, selectedAccountId: 'account-platform' };
      break;
    case 'north-foreign-account':
      request = { ...request, selectedAccountId: 'account-orbit' };
      break;
    case 'north-foreign-egress':
      snapshot = withAccountEgress('proxy-orbit');
      break;
    case 'north-offline':
      snapshot = withAccountEgress('proxy-north-down');
      break;
    case 'north-direct':
      snapshot = withAccountEgress('direct-north');
      break;
    case 'north-unapproved':
      request = { ...request, selectedAccountId: 'account-north-oauth' };
      break;
    case 'orbit-vpn':
      request = { ...request, selectedAccountId: 'account-orbit-vpn' };
      break;
    case 'north-owned':
    case 'orbit-owned':
      break;
  }
  const decision = resolveSaasRoute(snapshot, request, {
    nowMs: DEMO_CLOCK,
    runtime: { verifiedVpnConnectorIds: [] },
  });
  return { scenario, decision, preview: safeDecisionPreview(decision) };
}

export function getTenantScenarios(tenantId: string): readonly DemoScenario[] {
  return DEMO_SCENARIOS.filter((scenario) => scenario.tenantId === tenantId);
}
