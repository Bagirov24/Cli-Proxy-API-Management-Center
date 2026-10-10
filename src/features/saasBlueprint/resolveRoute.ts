import type {
  AccessGrant,
  BlueprintSnapshot,
  Owner,
  RouteRequest,
  RoutingBinding,
  RuntimeCapabilities,
} from './domain';
import { SAAS_BLUEPRINT_SCHEMA_VERSION } from './domain';
import { validateEgressProfileShape } from './egressValidation';

/**
 * Pure policy prototype: NO I/O, persistence, calls to Core, or credential access.
 * This decision is NOT enforcement until the Core scheduler/egress transport are
 * integrated and tested. Never trust tenant/account IDs from downstream headers.
 */
export type PolicyStage =
  | 'configuration'
  | 'tenant'
  | 'application'
  | 'client-key'
  | 'routing'
  | 'account-pool'
  | 'provider-account'
  | 'egress';

export type DenialReason =
  | 'unsupported-schema'
  | 'invalid-clock'
  | 'tenant-unavailable'
  | 'application-unavailable'
  | 'project-unavailable'
  | 'client-key-unavailable'
  | 'core-native-key-forbidden'
  | 'route-not-found'
  | 'route-ambiguous'
  | 'pool-unavailable'
  | 'pool-forbidden'
  | 'account-unavailable'
  | 'account-not-in-pool'
  | 'account-forbidden'
  | 'account-auth-unapproved'
  | 'provider-mismatch'
  | 'model-forbidden'
  | 'egress-unavailable'
  | 'egress-forbidden'
  | 'egress-invalid'
  | 'egress-direct-forbidden'
  | 'vpn-connector-unverified';

export type RouteDecision =
  | { readonly allowed: false; readonly stage: PolicyStage; readonly reason: DenialReason }
  | {
      readonly allowed: true;
      readonly stage: 'egress';
      readonly routeBindingId: string;
      readonly accountPoolId: string;
      readonly providerAccountId: string;
      readonly egressProfileId: string;
      readonly providerId: string;
      readonly modelId: string;
    };

export interface ResolveContext {
  /** Supplied by trusted control-plane clock, never inferred from a user request. */
  readonly nowMs: number;
  readonly runtime?: RuntimeCapabilities;
}

const denied = (stage: PolicyStage, reason: DenialReason): RouteDecision => ({
  allowed: false,
  stage,
  reason,
});

/** Duplicate resource IDs fail closed instead of silently selecting a first match. */
function exactlyOne<T>(entries: readonly T[], match: (entry: T) => boolean): T | undefined {
  const matches = entries.filter(match);
  return matches.length === 1 ? matches[0] : undefined;
}

function sameOwner(left: Owner, right: Owner): boolean {
  if (left.kind !== right.kind) return false;
  return left.kind === 'platform' ||
    (right.kind === 'tenant' && left.tenantId === right.tenantId);
}

function grantActive(grant: AccessGrant, nowMs: number): boolean {
  if (grant.status !== 'active') return false;
  if (grant.expiresAt === undefined) return true;
  const expiresAt = Date.parse(grant.expiresAt);
  return Number.isFinite(expiresAt) && expiresAt > nowMs;
}

function hasAccess(
  owner: Owner,
  tenantId: string,
  kind: AccessGrant['resourceKind'],
  resourceId: string,
  grants: readonly AccessGrant[],
  nowMs: number
): boolean {
  if (owner.kind === 'tenant' && owner.tenantId === tenantId) return true;
  // A platform account is NOT automatically shared with every tenant.
  return grants.some(
    (grant) =>
      grant.resourceKind === kind &&
      grant.resourceId === resourceId &&
      grant.granteeTenantId === tenantId &&
      sameOwner(grant.owner, owner) &&
      grantActive(grant, nowMs)
  );
}

function findBinding(
  snapshot: BlueprintSnapshot,
  input: RouteRequest
): RoutingBinding | 'ambiguous' | undefined {
  const bindings = snapshot.routingBindings.filter(
    (binding) =>
      binding.status === 'active' &&
      binding.tenantId === input.tenantId &&
      binding.applicationId === input.applicationId &&
      binding.keyBindingId === input.keyBindingId &&
      binding.requestedModelId === input.requestedModelId
  );
  if (bindings.length > 1) return 'ambiguous';
  return bindings[0];
}

export function resolveSaasRoute(
  snapshot: BlueprintSnapshot,
  input: RouteRequest,
  context: ResolveContext
): RouteDecision {
  if (snapshot.schemaVersion !== SAAS_BLUEPRINT_SCHEMA_VERSION) {
    return denied('configuration', 'unsupported-schema');
  }
  if (!Number.isFinite(context.nowMs)) return denied('configuration', 'invalid-clock');

  const tenant = exactlyOne(snapshot.tenants, (t) => t.id === input.tenantId);
  if (!tenant || tenant.status !== 'active') return denied('tenant', 'tenant-unavailable');

  const application = exactlyOne(
    snapshot.applications,
    (a) => a.id === input.applicationId && a.tenantId === tenant.id
  );
  if (!application || application.status !== 'active') {
    return denied('application', 'application-unavailable');
  }
  const project = exactlyOne(
    snapshot.projects,
    (p) => p.id === application.projectId && p.tenantId === tenant.id
  );
  if (!project || project.status !== 'active') {
    return denied('application', 'project-unavailable');
  }

  const clientKey = exactlyOne(
    snapshot.keyBindings,
    (k) =>
      k.id === input.keyBindingId &&
      k.tenantId === tenant.id &&
      k.applicationId === application.id
  );
  if (!clientKey || clientKey.status !== 'active') {
    return denied('client-key', 'client-key-unavailable');
  }
  if (clientKey.kind !== 'cpa') return denied('client-key', 'core-native-key-forbidden');

  const binding = findBinding(snapshot, input);
  if (binding === 'ambiguous') return denied('routing', 'route-ambiguous');
  if (!binding) return denied('routing', 'route-not-found');

  const pool = exactlyOne(snapshot.accountPools, (p) => p.id === binding.poolId);
  if (!pool || pool.status !== 'active') return denied('account-pool', 'pool-unavailable');
  if (!hasAccess(pool.owner, tenant.id, 'pool', pool.id, snapshot.accessGrants, context.nowMs)) {
    return denied('account-pool', 'pool-forbidden');
  }

  if (!pool.accountIds.includes(input.selectedAccountId)) {
    return denied('provider-account', 'account-not-in-pool');
  }
  const account = exactlyOne(
    snapshot.providerAccounts,
    (a) => a.id === input.selectedAccountId
  );
  if (!account || account.status !== 'active') {
    return denied('provider-account', 'account-unavailable');
  }
  if (!hasAccess(
    account.owner,
    tenant.id,
    'account',
    account.id,
    snapshot.accessGrants,
    context.nowMs
  )) {
    return denied('provider-account', 'account-forbidden');
  }
  if (account.authorizationStatus !== 'approved') {
    return denied('provider-account', 'account-auth-unapproved');
  }
  if (account.providerId !== pool.providerId || account.providerId !== binding.providerId) {
    return denied('provider-account', 'provider-mismatch');
  }
  if (!account.allowedModelIds.includes(input.requestedModelId)) {
    return denied('provider-account', 'model-forbidden');
  }

  const egress = exactlyOne(
    snapshot.egressProfiles,
    (profile) => profile.id === account.egressProfileId
  );
  if (!egress || egress.status !== 'active' || egress.health !== 'healthy') {
    return denied('egress', 'egress-unavailable');
  }
  if (!hasAccess(
    egress.owner,
    tenant.id,
    'egress',
    egress.id,
    snapshot.accessGrants,
    context.nowMs
  )) {
    return denied('egress', 'egress-forbidden');
  }
  if (validateEgressProfileShape(egress)) return denied('egress', 'egress-invalid');
  if (egress.kind === 'direct') {
    if (binding.egressPolicy !== 'direct-explicit' || !tenant.allowDirectEgress) {
      return denied('egress', 'egress-direct-forbidden');
    }
  } else if (egress.kind === 'vpn-connector') {
    // A known connector ID alone does not authorize use: an independently
    // deployed and verified connector must be present in runtime capabilities.
    if (!context.runtime?.verifiedVpnConnectorIds.includes(egress.connectorId || '')) {
      return denied('egress', 'vpn-connector-unverified');
    }
  }

  return {
    allowed: true,
    stage: 'egress',
    routeBindingId: binding.id,
    accountPoolId: pool.id,
    providerAccountId: account.id,
    egressProfileId: egress.id,
    providerId: binding.providerId,
    modelId: input.requestedModelId,
  };
}
